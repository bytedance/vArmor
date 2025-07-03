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
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	"github.com/go-logr/zerologr"
	"github.com/kyverno/kyverno/pkg/leaderelection"
	"github.com/rs/zerolog"
	"go.uber.org/automaxprocs/maxprocs"
	"golang.org/x/sys/unix"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"k8s.io/klog/v2/textlogger"
	"sigs.k8s.io/controller-runtime/pkg/log"

	varmoragent "github.com/bytedance/vArmor/internal/agent"
	"github.com/bytedance/vArmor/internal/config"
	"github.com/bytedance/vArmor/internal/ipwatcher"
	"github.com/bytedance/vArmor/internal/policy"
	"github.com/bytedance/vArmor/internal/policycacher"
	"github.com/bytedance/vArmor/internal/status"
	varmortls "github.com/bytedance/vArmor/internal/tls"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
	"github.com/bytedance/vArmor/internal/webhookconfig"
	"github.com/bytedance/vArmor/internal/webhooks"
	varmorclient "github.com/bytedance/vArmor/pkg/client/clientset/versioned"
	varmorinformer "github.com/bytedance/vArmor/pkg/client/informers/externalversions"
	"github.com/bytedance/vArmor/pkg/metrics"
	"github.com/bytedance/vArmor/pkg/signal"
)

const (
	secretResyncPeriod = time.Minute * 15
	varmorResyncPeriod = time.Hour * 1
	ipResyncPeriod     = time.Minute * 2
)

var (
	agent                         bool
	enableMetrics                 bool
	enableBpfEnforcer             bool
	enableBehaviorModeling        bool
	enablePodServiceEgressControl bool
	unloadAllAaProfiles           bool
	removeAllSeccompProfiles      bool
	bpfExclusiveMode              bool
	restartExistWorkloads         bool
	clientRateLimitQPS            float64
	clientRateLimitBurst          int
	webhookTimeout                int
	webhookMatchLabel             string
	statusUpdateCycle             time.Duration
	auditLogPaths                 string
	logFormat                     string
	verbosity                     int
	managerIP                     string
	kubeconfig                    string
	versionFlag                   bool
	debugFlag                     bool
	gitVersion                    string
	gitCommit                     string
	buildDate                     string
	goVersion                     string
	logger                        = log.Log
)

func setLogger() {
	// Disable the log of automaxprocs
	maxprocs.Set()

	// Setup logger
	var logrLogger logr.Logger
	switch logFormat {
	case "json":
		zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMicro
		zerologger := zerolog.New(os.Stdout).With().Timestamp().Caller().Logger()
		zerologr.SetMaxV(verbosity)
		logrLogger = zerologr.New(&zerologger)
	default:
		c := textlogger.NewConfig(textlogger.Verbosity(verbosity))
		logrLogger = textlogger.NewLogger(c)
	}
	log.SetLogger(logrLogger)
	klog.SetLogger(logrLogger)

	if id, ok := config.AuditEventMetadata["accountId"]; ok {
		logger = logger.WithValues("accountId", id)
	}
	if region, ok := config.AuditEventMetadata["region"]; ok {
		logger = logger.WithValues("region", region)
	}
	if id, ok := config.AuditEventMetadata["clusterId"]; ok {
		logger = logger.WithValues("clusterId", id)
	}
	if name, ok := config.AuditEventMetadata["clusterName"]; ok {
		logger = logger.WithValues("clusterName", name)
	}
	logger = logger.WithValues("podName", config.Name)
	logger = logger.WithValues("podNamespace", config.Namespace)
}

func main() {
	flag.BoolVar(&agent, "agent", false, "Set this flag to run vArmor agent.")
	flag.BoolVar(&enableMetrics, "enableMetrics", false, "Set this flag to enable metrics.")
	flag.BoolVar(&enableBpfEnforcer, "enableBpfEnforcer", false, "Set this flag to enable BPF enforcer.")
	flag.BoolVar(&enableBehaviorModeling, "enableBehaviorModeling", false, "Set this flag to enable BehaviorModeling feature (Note: this is an experimental feature, please do not enable it in production environment).")
	flag.BoolVar(&enablePodServiceEgressControl, "enablePodServiceEgressControl", false, "Set this flag to enable the egress control feature for Pod and Service access")
	flag.BoolVar(&unloadAllAaProfiles, "unloadAllAaProfiles", false, "Unload all AppArmor profiles when the agent exits.")
	flag.BoolVar(&removeAllSeccompProfiles, "removeAllSeccompProfiles", false, "Remove all Seccomp profiles when the agent exits.")
	flag.BoolVar(&bpfExclusiveMode, "bpfExclusiveMode", false, "Set this flag to enable exclusive mode for the BPF enforcer. It will disable the AppArmor confinement when using the BPF enforcer.")
	flag.BoolVar(&restartExistWorkloads, "restartExistWorkloads", false, "Set this flag to allow users control whether or not to restart existing workloads with the .spec.updateExistingWorkloads feild.")
	flag.Float64Var(&clientRateLimitQPS, "clientRateLimitQPS", 100, "Configure the maximum QPS to the master from vArmor. Uses the client default if zero.")
	flag.IntVar(&clientRateLimitBurst, "clientRateLimitBurst", 200, "Configure the maximum burst for throttle. Uses the client default if zero.")
	flag.IntVar(&webhookTimeout, "webhookTimeout", int(config.WebhookTimeout), "Timeout for webhook configurations.")
	flag.StringVar(&webhookMatchLabel, "webhookMatchLabel", "sandbox.varmor.org/enable=true", "Configure the matchLabel of webhook configuration, the valid format is key=value or nil")
	flag.DurationVar(&statusUpdateCycle, "statusUpdateCycle", time.Hour*2, "Configure the status update cycle for VarmorPolicy and ArmorProfile")
	flag.StringVar(&auditLogPaths, "auditLogPaths", "/var/log/audit/audit.log|/var/log/kern.log", "Configure the file search list to select the audit log file and read the AppArmor and Seccomp audit events. Please use a vertical bar to separate the file paths, the first valid file will be used to track the audit events.")
	flag.StringVar(&logFormat, "logFormat", "text", "Log format (text or json). Default is text.")
	flag.IntVar(&verbosity, "v", 0, "Log verbosity level (higher value means more verbose).")
	flag.IntVar(&verbosity, "verbosity", 0, "Log verbosity level (higher value means more verbose).")
	flag.StringVar(&managerIP, "managerIP", "0.0.0.0", "Configure the IP address of manager.")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.BoolVar(&versionFlag, "version", false, "Print the version information.")
	flag.BoolVar(&debugFlag, "debug", false, "Enable debug mode.")
	flag.Parse()

	if versionFlag {
		fmt.Printf("GitVersion: %s\nGitCommit: %s\nBuildDate: %s\nGoVersion: %s\n", gitVersion, gitCommit, buildDate, goVersion)
		return
	}

	// Setup logger
	setLogger()

	// Set the webhook matchLabels configuration.
	if webhookMatchLabel != "" {
		labelKvs := strings.Split(webhookMatchLabel, "=")
		if len(labelKvs) != 2 {
			logger.WithName("SETUP").Error(fmt.Errorf("format error"), "failed to parse the --webhookMatchLabel argument, the valid format is key=value or nil")
			os.Exit(1)
		}
		config.WebhookSelectorLabel[labelKvs[0]] = labelKvs[1]
	}

	inContainer := kubeconfig == ""
	stopCh := signal.SetupSignalHandler()

	clientConfig, err := config.CreateClientConfig(kubeconfig, clientRateLimitQPS, clientRateLimitBurst, logger)
	if err != nil {
		logger.WithName("SETUP").Error(err, "config.CreateClientConfig()")
		os.Exit(1)
	}

	kubeClient, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		logger.WithName("SETUP").Error(err, "kubernetes.NewForConfig()")
		os.Exit(1)
	}

	// vArmor CRD CLIENT, access CRD resources: ArmorProfile & VarmorPolicy
	varmorClient, err := varmorclient.NewForConfig(clientConfig)
	if err != nil {
		logger.WithName("SETUP").Error(err, "varmorclient.NewForConfig()")
		os.Exit(1)
	}

	// vArmor CRD INFORMER, used to watch CRD resources: ArmorProfile & VarmorPolicy
	varmorFactory := varmorinformer.NewSharedInformerFactoryWithOptions(varmorClient, varmorResyncPeriod)

	// Gather APIServer version
	config.ServerVersion, err = kubeClient.ServerVersion()
	if err != nil {
		logger.WithName("SETUP").Error(err, "kubeClient.ServerVersion()")
		os.Exit(1)
	}

	config.AppArmorGA, err = varmorutils.IsAppArmorGA(config.ServerVersion)
	if err != nil {
		logger.WithName("SETUP").Error(err, "varmorutils.IsAppArmorGA()")
		os.Exit(1)
	}

	if debugFlag {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// init a metrics
	metricsModule := metrics.NewMetricsModule(logger.WithName("METRICS"), enableMetrics, 10)

	if agent {
		logger.WithName("SETUP").Info("vArmor agent startup")

		// RemoveMemlock requires the write permission for /proc/sys/kernel/printk_ratelimit
		if inContainer {
			err = unix.Unmount("/proc/sys", 0)
			if err != nil {
				logger.WithName("SETUP").Error(err, "unix.Unmount(\"/proc/sys\", 0)")
				os.Exit(1)
			}
		}

		agentCtrl, err := varmoragent.NewAgent(
			varmorClient.CrdV1beta1(),
			varmorFactory.Crd().V1beta1().ArmorProfiles(),
			enableBehaviorModeling,
			enableBpfEnforcer,
			unloadAllAaProfiles,
			removeAllSeccompProfiles,
			debugFlag,
			inContainer,
			managerIP,
			config.StatusServicePort,
			config.ClassifierServicePort,
			auditLogPaths,
			stopCh,
			metricsModule,
			logger.WithName("AGENT"),
		)
		if err != nil {
			logger.WithName("SETUP").Error(err, "agent.NewAgent()")
			os.Exit(1)
		}
		varmorFactory.Start(stopCh)
		go agentCtrl.Run(1, stopCh)

		// Wait for the manager to be ready.
		logger.WithName("SETUP").Info("Waiting for the manager to be ready")
		varmorutils.WaitForManagerReady(inContainer, managerIP, config.StatusServicePort)

		// Set the agent to ready.
		varmorutils.SetAgentReady()

		logger.WithName("SETUP").Info("vArmor agent is online")

		<-stopCh

		agentCtrl.CleanUp()
		logger.WithName("SETUP").Info("vArmor agent shutdown successful")

	} else {
		logger.WithName("SETUP").Info("vArmor manager startup")

		// leader election context
		leaderCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			<-stopCh
			cancel()
		}()

		// Create a policy cacher for the webhook server
		cacher, _ := policycacher.NewPolicyCacher(
			varmorFactory.Crd().V1beta1().VarmorClusterPolicies(),
			varmorFactory.Crd().V1beta1().VarmorPolicies(),
			logger.WithName("POLICY-CACHER"))
		go cacher.Run(stopCh)

		certRenewer := varmortls.NewCertRenewer(
			clientConfig,
			kubeClient.CoreV1().Secrets(config.Namespace),
			kubeClient.AppsV1().Deployments(config.Namespace),
			config.CertRenewalInterval,
			config.CertValidityDuration,
			managerIP,
			inContainer,
			logger.WithName("CERT-RENEWER"),
		)

		secretFactory := kubeinformers.NewSharedInformerFactoryWithOptions(kubeClient, secretResyncPeriod, kubeinformers.WithNamespace(config.Namespace))
		certManager := webhookconfig.NewCertManager(
			clientConfig,
			certRenewer,
			kubeClient.CoreV1().Secrets(config.Namespace),
			secretFactory.Core().V1().Secrets(),
			stopCh,
			logger.WithName("CERT-MANAGER"),
		)
		secretFactory.Start(stopCh)

		mwcFactory := kubeinformers.NewSharedInformerFactoryWithOptions(kubeClient, secretResyncPeriod)
		webhookRegister := webhookconfig.NewRegister(
			clientConfig,
			kubeClient.AdmissionregistrationV1().MutatingWebhookConfigurations(),
			kubeClient.CoreV1().Secrets(config.Namespace),
			kubeClient.AppsV1().Deployments(config.Namespace),
			kubeClient.CoordinationV1().Leases(config.Namespace),
			varmorClient.CrdV1beta1(),
			mwcFactory.Admissionregistration().V1().MutatingWebhookConfigurations(),
			managerIP,
			int32(webhookTimeout),
			inContainer,
			stopCh,
			logger.WithName("WEBHOOK-CONFIG"),
		)
		mwcFactory.Start(stopCh)

		// Elect a leader to register the admission webhook configurations.
		registerWebhookConfigurations := func() {
			// Only leader initializes the secrets of CA cert and TLS pair.
			certManager.InitTLSPemPair()
			// Only leader registers the MutatingWebhookConfiguration object.
			err = webhookRegister.Register()
			if err != nil {
				logger.WithName("SETUP").Error(err, "webhookRegister.Register()")
				os.Exit(1)
			}
		}
		webhookRegisterLeader, err := leaderelection.New(
			"webhook-register",
			config.Namespace,
			kubeClient,
			registerWebhookConfigurations,
			nil,
			logger.WithName("webhook-register/LeaderElection"))
		if err != nil {
			logger.WithName("SETUP").Error(err, "failed to elect a leader")
			os.Exit(1)
		}
		go webhookRegisterLeader.Run(leaderCtx)

		// Create a TLS key/certificate pair for the webhook server and status server
		tlsPair, err := certManager.GetTLSPemPair()
		if err != nil {
			logger.WithName("SETUP").Error(err, "Failed to get TLS key/certificate pair")
			os.Exit(1)
		}

		// Create the webhook server.
		// It runs across all instances.
		webhookServer, err := webhooks.NewWebhookServer(
			webhookRegister,
			cacher,
			tlsPair,
			managerIP,
			config.WebhookServicePort,
			bpfExclusiveMode,
			metricsModule,
			logger.WithName("WEBHOOK-SERVER"))
		if err != nil {
			logger.WithName("SETUP").Error(err, "Failed to create webhook webhookServer")
			os.Exit(1)
		}
		go webhookServer.Run()

		// Create a service for state synchronization.
		// It's only run by the leader.
		statusSvc, err := status.NewStatusService(
			managerIP,
			config.StatusServicePort,
			tlsPair,
			debugFlag,
			inContainer,
			kubeClient.CoreV1(),
			kubeClient.AppsV1(),
			varmorClient.CrdV1beta1(),
			kubeClient.AuthenticationV1(),
			kubeClient.AuthorizationV1(),
			statusUpdateCycle,
			metricsModule,
			logger.WithName("STATUS-SERVICE"),
		)
		if err != nil {
			logger.WithName("SETUP").Error(err, "service.NewStatusService()")
			os.Exit(1)
		}

		// Create an IPWatcher to watch the Pod and Service IP changes.
		// It uses the IP that matches the egress rules of policies to update the armorprofile.
		// It's only run by the leader.
		//
		// Please note that only the BPF enforcer supports restricting container access to specific
		// Pods and Services currently. After the AppArmor enforcer is adapted to AppArmor 4.0, it
		// will also support this feature.
		egressCache := make(map[string]varmortypes.EgressInfo)
		egressCacheMutex := &sync.RWMutex{}
		var ipWatcher *ipwatcher.IPWatcher
		if enablePodServiceEgressControl && enableBpfEnforcer {
			factory := kubeinformers.NewSharedInformerFactoryWithOptions(kubeClient, ipResyncPeriod, kubeinformers.WithTransform(ipwatcher.Transform))
			ipWatcher, err = ipwatcher.NewIPWatcher(
				varmorClient.CrdV1beta1(),
				factory.Core().V1().Pods(),
				factory.Core().V1().Services(),
				factory.Discovery().V1().EndpointSlices(),
				egressCache,
				egressCacheMutex,
				logger.WithName("IP-WATCHER"))
			if err != nil {
				logger.WithName("SETUP").Error(err, "ipwatcher.NewIPWatcher()")
				os.Exit(1)
			}
			factory.Start(stopCh)
		}

		// Create the VarmorClusterPolicy controller.
		// It's only run by the leader.
		clusterPolicyCtrl, err := policy.NewClusterPolicyController(
			kubeClient,
			varmorClient.CrdV1beta1(),
			varmorFactory.Crd().V1beta1().VarmorClusterPolicies(),
			statusSvc.StatusManager,
			egressCache,
			egressCacheMutex,
			restartExistWorkloads,
			enableBehaviorModeling,
			enablePodServiceEgressControl,
			bpfExclusiveMode,
			logger.WithName("CLUSTER-POLICY"),
		)
		if err != nil {
			logger.WithName("SETUP").Error(err, "policy.NewClusterPolicyController()")
			os.Exit(1)
		}

		// Create the VarmorPolicy controller.
		// It's only run by the leader.
		policyCtrl, err := policy.NewPolicyController(
			kubeClient,
			varmorClient.CrdV1beta1(),
			varmorFactory.Crd().V1beta1().VarmorPolicies(),
			statusSvc.StatusManager,
			egressCache,
			egressCacheMutex,
			restartExistWorkloads,
			enableBehaviorModeling,
			enablePodServiceEgressControl,
			bpfExclusiveMode,
			logger.WithName("POLICY"),
		)
		if err != nil {
			logger.WithName("SETUP").Error(err, "policy.NewPolicyController()")
			os.Exit(1)
		}

		// Start all varmor CRD informers
		varmorFactory.Start(stopCh)

		// Wrap all controllers that need leaderelection, start them once by the leader.
		leaderRun := func() {
			if enablePodServiceEgressControl && enableBpfEnforcer {
				// Only the leader watches the Pod and Service IP changes.
				go ipWatcher.Run(1, stopCh)
			}
			// Only the leader manages the status service.
			go statusSvc.Run(stopCh)
			// Only the leader validates the CA Cert periodically and updates manager when the rootCA is changed or expired.
			go certManager.Run(stopCh)
			// Only the leader runs as the VarmorClusterPolicy & VarmorPolicy controller.
			go clusterPolicyCtrl.Run(1, stopCh)
			go policyCtrl.Run(1, stopCh)

			// Tag the leader Pod with "identity: leader" label so that agents can use varmor-status-svc for state synchronization.
			if inContainer {
				retriable := func(err error) bool {
					return err != nil
				}
				tag := func() error {
					err := varmorutils.UnTagLeaderPod(kubeClient.CoreV1().Pods(config.Namespace))
					if err != nil {
						return err
					}
					return varmorutils.TagLeaderPod(kubeClient.CoreV1().Pods(config.Namespace))
				}
				err := retry.OnError(retry.DefaultRetry, retriable, tag)
				if err != nil {
					logger.WithName("SETUP").Error(err, "Retag Leader failed")
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

		leader, err := leaderelection.New("varmor-manager", config.Namespace, kubeClient, leaderRun, leaderStop, logger.WithName("varmor-manager/LeaderElection"))
		if err != nil {
			logger.WithName("SETUP").Error(err, "failed to elect a leader")
			os.Exit(1)
		}
		go leader.Run(leaderCtx)

		logger.WithName("SETUP").Info("vArmor manager is online")

		<-stopCh

		// Cleanup the webhook resource when the manager exits.
		if webhookRegister.ShouldRemoveVarmorResources() {
			webhookRegister.Remove()
		}
		webhookServer.CleanUp()

		logger.WithName("SETUP").Info("vArmor manager shutdown successful")
	}
}
