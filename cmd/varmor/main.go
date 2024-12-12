// Copyright 2021-2023 vArmor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/kyverno/kyverno/pkg/leaderelection"
	_ "go.uber.org/automaxprocs"
	"golang.org/x/sys/unix"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2/textlogger"
	"sigs.k8s.io/controller-runtime/pkg/log"

	varmoragent "github.com/bytedance/vArmor/internal/agent"
	"github.com/bytedance/vArmor/internal/config"
	"github.com/bytedance/vArmor/internal/policy"
	"github.com/bytedance/vArmor/internal/policycacher"
	"github.com/bytedance/vArmor/internal/status"
	varmortls "github.com/bytedance/vArmor/internal/tls"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
	"github.com/bytedance/vArmor/internal/webhookconfig"
	"github.com/bytedance/vArmor/internal/webhooks"
	varmorclient "github.com/bytedance/vArmor/pkg/client/clientset/versioned"
	varmorinformer "github.com/bytedance/vArmor/pkg/client/informers/externalversions"
	"github.com/bytedance/vArmor/pkg/metrics"
	"github.com/bytedance/vArmor/pkg/signal"
)

const (
	resyncPeriod       = time.Minute * 15
	varmorResyncPeriod = time.Hour * 1
)

var (
	versionFlag              bool
	gitVersion               string
	gitCommit                string
	buildDate                string
	goVersion                string
	kubeconfig               string
	agent                    bool
	enableBpfEnforcer        bool
	unloadAllAaProfiles      bool
	removeAllSeccompProfiles bool
	enableBehaviorModeling   bool
	restartExistWorkloads    bool
	clientRateLimitQPS       float64
	clientRateLimitBurst     int
	managerIP                string
	webhookTimeout           int
	webhookMatchLabel        string
	bpfExclusiveMode         bool
	statusUpdateCycle        time.Duration
	auditLogPaths            string
	enableMetrics            bool
	//syncMetricsSecond        int
	setupLog = log.Log.WithName("SETUP")
)

func main() {
	c := textlogger.NewConfig()
	c.AddFlags(flag.CommandLine)
	log.SetLogger(textlogger.NewLogger(c))

	flag.BoolVar(&versionFlag, "version", false, "Print the version information.")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.BoolVar(&agent, "agent", false, "Set this flag to run vArmor agent. Run vArmor manager default if true.")
	flag.BoolVar(&enableBpfEnforcer, "enableBpfEnforcer", false, "Set this flag to enable BPF enforcer.")
	flag.BoolVar(&unloadAllAaProfiles, "unloadAllAaProfiles", false, "Unload all AppArmor profiles when the agent exits.")
	flag.BoolVar(&removeAllSeccompProfiles, "removeAllSeccompProfiles", false, "Remove all Seccomp profiles when the agent exits.")
	flag.BoolVar(&enableBehaviorModeling, "enableBehaviorModeling", false, "Set this flag to enable BehaviorModeling feature (Note: this is an experimental feature, please do not enable it in production environment).")
	flag.BoolVar(&restartExistWorkloads, "restartExistWorkloads", false, "Set this flag to allow users control whether or not to restart existing workloads with the .spec.updateExistingWorkloads feild.")
	flag.Float64Var(&clientRateLimitQPS, "clientRateLimitQPS", 0, "Configure the maximum QPS to the master from vArmor. Uses the client default if zero.")
	flag.IntVar(&clientRateLimitBurst, "clientRateLimitBurst", 0, "Configure the maximum burst for throttle. Uses the client default if zero.")
	flag.StringVar(&managerIP, "managerIP", "0.0.0.0", "Configure the IP address of manager.")
	flag.IntVar(&webhookTimeout, "webhookTimeout", int(config.WebhookTimeout), "Timeout for webhook configurations.")
	flag.StringVar(&webhookMatchLabel, "webhookMatchLabel", "sandbox.varmor.org/enable=true", "Configure the matchLabel of webhook configuration, the valid format is key=value or nil")
	flag.BoolVar(&bpfExclusiveMode, "bpfExclusiveMode", false, "Set this flag to enable exclusive mode for the BPF enforcer. It will disable the AppArmor confinement when using the BPF enforcer.")
	flag.DurationVar(&statusUpdateCycle, "statusUpdateCycle", time.Hour*2, "Configure the status update cycle for VarmorPolicy and ArmorProfile")
	flag.StringVar(&auditLogPaths, "auditLogPaths", "/var/log/audit/audit.log|/var/log/kern.log", "Configure the file search list to select the audit log file and read the AppArmor and Seccomp audit events. Please use a vertical bar to separate the file paths, the first valid file will be used to track the audit events.")
	flag.BoolVar(&enableMetrics, "enableMetrics", false, "Set this flag to enable metrics.")
	//flag.IntVar(&syncMetricsSecond, "syncMetricsSecond", 10, "Configure the profile metric update seconds")
	flag.Parse()

	if versionFlag {
		fmt.Printf("GitVersion: %s\nGitCommit: %s\nBuildDate: %s\nGoVersion: %s\n", gitVersion, gitCommit, buildDate, goVersion)
		return
	}

	// Set the webhook matchLabels configuration.
	if webhookMatchLabel != "" {
		labelKvs := strings.Split(webhookMatchLabel, "=")
		if len(labelKvs) != 2 {
			setupLog.Error(fmt.Errorf("format error"), "failed to parse the --webhookMatchLabel argument, the valid format is key=value or nil")
			os.Exit(1)
		}
		config.WebhookSelectorLabel[labelKvs[0]] = labelKvs[1]
	}

	debug := kubeconfig != ""
	stopCh := signal.SetupSignalHandler()

	clientConfig, err := config.CreateClientConfig(kubeconfig, clientRateLimitQPS, clientRateLimitBurst, log.Log)
	if err != nil {
		setupLog.Error(err, "config.CreateClientConfig()")
		os.Exit(1)
	}

	kubeClient, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		setupLog.Error(err, "kubernetes.NewForConfig()")
		os.Exit(1)
	}

	// vArmor CRD CLIENT, access CRD resources: ArmorProfile & VarmorPolicy
	varmorClient, err := varmorclient.NewForConfig(clientConfig)
	if err != nil {
		setupLog.Error(err, "varmorclient.NewForConfig()")
		os.Exit(1)
	}

	// vArmor CRD INFORMER, used to watch CRD resources: ArmorProfile & VarmorPolicy
	varmorInformer := varmorinformer.NewSharedInformerFactoryWithOptions(varmorClient, varmorResyncPeriod)

	// Gather APIServer version
	config.ServerVersion, err = kubeClient.ServerVersion()
	if err != nil {
		setupLog.Error(err, "kubeClient.ServerVersion()")
		os.Exit(1)
	}

	config.AppArmorGA, err = varmorutils.IsAppArmorGA(config.ServerVersion)
	if err != nil {
		setupLog.Error(err, "varmorutils.IsAppArmorGA()")
		os.Exit(1)
	}

	if debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// init a metrics
	metricsModule := metrics.NewMetricsModule(log.Log.WithName("METRICS"), enableMetrics, 10)

	if agent {
		setupLog.Info("vArmor agent startup")

		// RemoveMemlock requires the write permission for /proc/sys/kernel/printk_ratelimit
		if !debug {
			err = unix.Unmount("/proc/sys", 0)
			if err != nil {
				setupLog.Error(err, "unix.Unmount(\"/proc/sys\", 0)")
				os.Exit(1)
			}
		}

		agentCtrl, err := varmoragent.NewAgent(
			varmorClient.CrdV1beta1(),
			varmorInformer.Crd().V1beta1().ArmorProfiles(),
			enableBehaviorModeling,
			enableBpfEnforcer,
			unloadAllAaProfiles,
			removeAllSeccompProfiles,
			debug,
			managerIP,
			config.StatusServicePort,
			config.ClassifierServicePort,
			auditLogPaths,
			stopCh,
			metricsModule,
			log.Log.WithName("AGENT"),
		)
		if err != nil {
			setupLog.Error(err, "agent.NewAgent()")
			os.Exit(1)
		}

		go agentCtrl.Run(1, stopCh)

		// Wait for the manager to be ready.
		setupLog.Info("Waiting for the manager to be ready")
		varmorutils.WaitForManagerReady(debug, managerIP, config.StatusServicePort)

		// Starting up agent.
		varmorInformer.Start(stopCh)
		varmorutils.SetAgentReady()
		setupLog.Info("vArmor agent is online")

		<-stopCh

		agentCtrl.CleanUp()
		setupLog.Info("vArmor agent shutdown successful")

	} else {
		setupLog.Info("vArmor manager startup")

		// leader election context
		leaderCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-stopCh
			cancel()
		}()

		cacher, _ := policycacher.NewPolicyCacher(
			varmorInformer.Crd().V1beta1().VarmorClusterPolicies(),
			varmorInformer.Crd().V1beta1().VarmorPolicies(),
			debug,
			log.Log.WithName("POLICY-CACHER"))
		go cacher.Run(stopCh)

		certRenewer := varmortls.NewCertRenewer(
			clientConfig,
			kubeClient.CoreV1().Secrets(config.Namespace),
			kubeClient.AppsV1().Deployments(config.Namespace),
			config.CertRenewalInterval,
			config.CertValidityDuration,
			managerIP,
			debug,
			log.Log.WithName("CERT-RENEWER"),
		)
		secretInformer := kubeinformers.NewSharedInformerFactoryWithOptions(kubeClient, resyncPeriod, kubeinformers.WithNamespace(config.Namespace))
		certManager := webhookconfig.NewCertManager(
			clientConfig,
			certRenewer,
			kubeClient.CoreV1().Secrets(config.Namespace),
			secretInformer.Core().V1().Secrets(),
			stopCh,
			log.Log.WithName("CERT-MANAGER"),
		)

		kubeInformer := kubeinformers.NewSharedInformerFactoryWithOptions(kubeClient, resyncPeriod)
		webhookRegister := webhookconfig.NewRegister(
			clientConfig,
			kubeClient.AdmissionregistrationV1().MutatingWebhookConfigurations(),
			kubeClient.CoreV1().Secrets(config.Namespace),
			kubeClient.AppsV1().Deployments(config.Namespace),
			kubeClient.CoordinationV1().Leases(config.Namespace),
			varmorClient.CrdV1beta1(),
			varmorInformer.Crd().V1beta1().VarmorPolicies(),
			kubeInformer.Admissionregistration().V1().MutatingWebhookConfigurations(),
			managerIP,
			int32(webhookTimeout),
			debug,
			stopCh,
			log.Log.WithName("WEBHOOK-CONFIG"),
		)

		// Elect a leader to register the admission webhook configurations.
		registerWebhookConfigurations := func() {
			// Only leader init the secrets of CA cert and TLS pair.
			certManager.InitTLSPemPair()
			// Only leader register MutatingWebhookConfiguration.
			err = webhookRegister.Register()
			if err != nil {
				setupLog.Error(err, "webhookRegister.Register()")
				os.Exit(1)
			}
		}
		webhookRegisterLeader, err := leaderelection.New("webhook-register", config.Namespace, kubeClient, registerWebhookConfigurations, nil, log.Log.WithName("webhook-register/LeaderElection"))
		if err != nil {
			setupLog.Error(err, "failed to elect a leader")
			os.Exit(1)
		}
		go webhookRegisterLeader.Run(leaderCtx)

		// The webhook server runs across all instances.
		tlsPair, err := certManager.GetTLSPemPair()
		if err != nil {
			setupLog.Error(err, "Failed to get TLS key/certificate pair")
			os.Exit(1)
		}
		webhookServer, err := webhooks.NewWebhookServer(
			webhookRegister,
			cacher,
			tlsPair,
			managerIP,
			config.WebhookServicePort,
			bpfExclusiveMode,
			metricsModule,
			log.Log.WithName("WEBHOOK-SERVER"))
		if err != nil {
			setupLog.Error(err, "Failed to create webhook webhookServer")
			os.Exit(1)
		}
		go webhookServer.Run()

		// The service is used for state synchronization. It only works with leader.
		statusSvc, err := status.NewStatusService(
			managerIP,
			config.StatusServicePort,
			tlsPair,
			debug,
			kubeClient.CoreV1(),
			kubeClient.AppsV1(),
			varmorClient.CrdV1beta1(),
			kubeClient.AuthenticationV1(),
			statusUpdateCycle,
			metricsModule,
			log.Log.WithName("STATUS-SERVICE"),
		)
		if err != nil {
			setupLog.Error(err, "service.NewStatusService()")
			os.Exit(1)
		}

		clusterPolicyCtrl, err := policy.NewClusterPolicyController(
			kubeClient.CoreV1().Pods(config.Namespace),
			kubeClient.AppsV1(),
			varmorClient.CrdV1beta1(),
			varmorInformer.Crd().V1beta1().VarmorClusterPolicies(),
			statusSvc.StatusManager,
			restartExistWorkloads,
			enableBehaviorModeling,
			bpfExclusiveMode,
			debug,
			log.Log.WithName("CLUSTER-POLICY"),
		)
		if err != nil {
			setupLog.Error(err, "policy.NewClusterPolicyController()")
			os.Exit(1)
		}

		policyCtrl, err := policy.NewPolicyController(
			kubeClient.CoreV1().Pods(config.Namespace),
			kubeClient.AppsV1(),
			varmorClient.CrdV1beta1(),
			varmorInformer.Crd().V1beta1().VarmorPolicies(),
			statusSvc.StatusManager,
			restartExistWorkloads,
			enableBehaviorModeling,
			bpfExclusiveMode,
			debug,
			log.Log.WithName("POLICY"),
		)
		if err != nil {
			setupLog.Error(err, "policy.NewPolicyController()")
			os.Exit(1)
		}

		retriable := func(err error) bool {
			return err != nil
		}

		// Wrap all controllers that need leaderelection, start them once by the leader.
		leaderRun := func() {
			// Only the leader manage the status service.
			go statusSvc.Run(stopCh)
			// Only the leader validates the CA Cert periodically and rolling update manager when secrets changed or rootCA expired.
			go certManager.Run(stopCh)
			// Only the leader run as the VarmorClusterPolicy & VarmorPolicy controller.
			go clusterPolicyCtrl.Run(1, stopCh)
			go policyCtrl.Run(1, stopCh)
			// Tag the leader Pod with "identity: leader" label so that agents can use varmor-status-svc for state synchronization.
			if !debug {
				tag := func() error {
					err := varmorutils.UnTagLeaderPod(kubeClient.CoreV1().Pods(config.Namespace))
					if err != nil {
						return err
					}
					return varmorutils.TagLeaderPod(kubeClient.CoreV1().Pods(config.Namespace))
				}
				err := retry.OnError(retry.DefaultRetry, retriable, tag)
				if err != nil {
					setupLog.Error(err, "Retag Leader failed")
					os.Exit(1)
				}
			}
		}

		leaderStop := func() {
			statusSvc.CleanUp()
			clusterPolicyCtrl.CleanUp()
			policyCtrl.CleanUp()
			signal.RequestShutdown()
		}
		leader, err := leaderelection.New("varmor-manager", config.Namespace, kubeClient, leaderRun, leaderStop, log.Log.WithName("varmor-manager/LeaderElection"))
		if err != nil {
			setupLog.Error(err, "failed to elect a leader")
			os.Exit(1)
		}
		go leader.Run(leaderCtx)

		varmorInformer.Start(stopCh)
		kubeInformer.Start(stopCh)
		secretInformer.Start(stopCh)

		setupLog.Info("vArmor manager is online")

		<-stopCh

		if webhookRegister.ShouldRemoveVarmorResources() {
			webhookRegister.Remove()
		}
		webhookServer.CleanUp()

		setupLog.Info("vArmor manager shutdown successful")
	}
}
