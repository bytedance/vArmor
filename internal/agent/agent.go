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

// Package agent implements the function of vArmor agent
package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	// listerv1 "k8s.io/client-go/listers/core/v1"
	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorbehavior "github.com/bytedance/vArmor/internal/behavior"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
	varmorauditor "github.com/bytedance/vArmor/pkg/auditor"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
	varmorinformer "github.com/bytedance/vArmor/pkg/client/informers/externalversions/varmor/v1beta1"
	varmorlister "github.com/bytedance/vArmor/pkg/client/listers/varmor/v1beta1"
	varmorapparmor "github.com/bytedance/vArmor/pkg/lsm/apparmor"
	varmorbpfenforcer "github.com/bytedance/vArmor/pkg/lsm/bpfenforcer"
	varmormetrics "github.com/bytedance/vArmor/pkg/metrics"
	varmorptracer "github.com/bytedance/vArmor/pkg/processtracer"
	varmorruntime "github.com/bytedance/vArmor/pkg/runtime"
	varmorseccomp "github.com/bytedance/vArmor/pkg/seccomp"
)

const (
	// maxRetries used for setting the retry times of sync failed
	maxRetries = 10
)

type Agent struct {
	varmorInterface          varmorinterface.CrdV1beta1Interface
	apInformer               varmorinformer.ArmorProfileInformer
	apLister                 varmorlister.ArmorProfileLister
	apInformerSynced         cache.InformerSynced
	queue                    workqueue.RateLimitingInterface
	appArmorSupported        bool
	bpfLsmSupported          bool
	seccompSupported         bool
	appArmorProfileDir       string
	seccompProfileDir        string
	bpfEnforcer              *varmorbpfenforcer.BpfEnforcer
	auditor                  *varmorauditor.Auditor
	monitor                  *varmorruntime.RuntimeMonitor
	waitExistingApSync       sync.WaitGroup
	existingApCount          int
	processedApCount         int
	enableBehaviorModeling   bool
	enableBpfEnforcer        bool
	unloadAllAaProfiles      bool
	removeAllSeccompProfiles bool
	ptracer                  *varmorptracer.ProcessTracer
	modellers                map[string]*varmorbehavior.BehaviorModeller
	nodeName                 string
	ready                    int32
	debug                    bool
	inContainer              bool
	svcAddresses             map[string]string
	stopCh                   <-chan struct{}
	log                      logr.Logger
}

func NewAgent(
	varmorInterface varmorinterface.CrdV1beta1Interface,
	apInformer varmorinformer.ArmorProfileInformer,
	enableBehaviorModeling bool,
	enableBpfEnforcer bool,
	unloadAllAaProfiles bool,
	removeAllSeccompProfiles bool,
	svcAddresses map[string]string,
	debug bool,
	inContainer bool,
	auditLogPaths string,
	stopCh <-chan struct{},
	metricsModule *varmormetrics.MetricsModule,
	log logr.Logger,
) (*Agent, error) {

	var err error

	agent := Agent{
		varmorInterface:          varmorInterface,
		apInformer:               apInformer,
		apLister:                 apInformer.Lister(),
		apInformerSynced:         apInformer.Informer().HasSynced,
		queue:                    workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "agent"),
		appArmorProfileDir:       varmorconfig.AppArmorProfileDir,
		seccompProfileDir:        varmorconfig.SeccompProfileDir,
		existingApCount:          0,
		processedApCount:         0,
		enableBehaviorModeling:   enableBehaviorModeling,
		enableBpfEnforcer:        enableBpfEnforcer,
		unloadAllAaProfiles:      unloadAllAaProfiles,
		removeAllSeccompProfiles: removeAllSeccompProfiles,
		modellers:                make(map[string]*varmorbehavior.BehaviorModeller),
		svcAddresses:             svcAddresses,
		debug:                    debug,
		inContainer:              inContainer,
		stopCh:                   stopCh,
		log:                      log,
	}

	if inContainer {
		// Initializes and rotates the token that is used for authenticating with the manager periodically.
		varmorutils.InitAndStartTokenRotation(5*time.Minute, log)
	}

	// Set up a readiness probe
	r := gin.New()
	r.Use(gin.Recovery(), varmorutils.GinLogger())
	r.SetTrustedProxies(nil)
	r.GET(varmorconfig.AgentReadinessPath, func(c *gin.Context) {
		if atomic.LoadInt32(&agent.ready) == 1 {
			c.String(http.StatusOK, "ok")
		} else {
			c.Status(http.StatusServiceUnavailable)
		}
	})

	go func() {
		if err := r.Run(fmt.Sprintf(":%d", varmorconfig.AgentReadinessPort)); err != nil {
			log.Error(err, "fatal error: agent service failed to start")
		}
	}()

	// Pre-checks
	agent.appArmorSupported, err = isLSMSupported("AppArmor")
	if err != nil {
		log.Info("the AppArmor LSM is not supported", "error", err)
	}
	if enableBpfEnforcer {
		agent.bpfLsmSupported, err = isLSMSupported("BPF")
		if err != nil {
			log.Info("the BPF LSM is not supported", "error", err)
		}
	} else {
		agent.bpfLsmSupported = false
		log.Info("the BPF enforcer is not enabled (use --enableBpfEnforcer to enable it)")
	}
	agent.seccompSupported, err = isSeccompSupported(varmorconfig.ServerVersion)
	if err != nil {
		log.Info("the Seccomp enforcer only supports Kubernetes v1.19 and above", "error", err)
	}

	if !agent.appArmorSupported && !agent.bpfLsmSupported && !agent.seccompSupported {
		log.Error(fmt.Errorf("no enforcer is supported in the environment"), "unsupported OS and Kubernetes")
		return nil, err
	}

	// Retrieve the node name where the agent is located.
	agent.nodeName, err = retrieveNodeName(inContainer)
	if err != nil {
		return nil, err
	}
	log.Info("NewAgent", "nodeName", agent.nodeName)

	// Initialize the runtime monitor
	log.Info("initialize the RuntimeMonitor")
	agent.monitor, err = varmorruntime.NewRuntimeMonitor(log.WithName("RUNTIME-MONITOR"))
	if err != nil {
		return nil, err
	}

	// AppArmor LSM initialization
	if agent.appArmorSupported {
		log.Info("initialize the AppArmor LSM")

		if inContainer {
			log.Info("setup the AppArmor feature ABI, abstractions, tunables and default profiles to /etc/apparmor.d")
			ret, err := exec.Command("cp", "-r", varmorconfig.PackagedAppArmorProfiles, "/etc/").CombinedOutput()
			if err != nil {
				log.Info(string(ret))
				return nil, err
			}
		}

		log.Info("setup the mock cri-containerd.apparmor.d profile for containerd")
		profilePath := filepath.Join(agent.appArmorProfileDir, "cri-containerd.apparmor.d")
		err = saveMockAppArmorProfile(profilePath, containerdDefaultProfile)
		if err != nil {
			log.Error(err, "saveMockAppArmorProfile()")
			return nil, err
		} else {
			varmorapparmor.RemoveUnknown()
		}
	}

	// BPF LSM initialization
	if agent.bpfLsmSupported {
		log.Info("initialize the BPF LSM")
		agent.bpfEnforcer, err = varmorbpfenforcer.NewBpfEnforcer(log.WithName("BPF-ENFORCER"))
		if err != nil {
			return nil, err
		}

		// Subscribe BPF enforcer to the monitor
		agent.monitor.AddTaskNotifyChs("BPF-ENFORCER", &agent.bpfEnforcer.TaskStartCh, &agent.bpfEnforcer.TaskDeleteCh, &agent.bpfEnforcer.TaskDeleteSyncCh)

		// Retrieve the count of existing ArmorProfile objects.
		apList, err := agent.varmorInterface.ArmorProfiles(metav1.NamespaceAll).List(context.Background(), metav1.ListOptions{ResourceVersion: "0"})
		if err != nil {
			return nil, err
		}
		agent.existingApCount = len(apList.Items)

		// Initialize the WaitGroup.
		if agent.existingApCount > 0 {
			agent.waitExistingApSync.Add(1)
		}
	}

	// Create an auditor to audit violation and behavior events for AppArmor, Seccomp and BPF enforcers
	agent.auditor, err = varmorauditor.NewAuditor(agent.nodeName,
		agent.appArmorSupported, agent.bpfLsmSupported, agent.enableBehaviorModeling,
		auditLogPaths, varmorconfig.AuditEventMetadata, log.WithName("AUDITOR"))
	if err != nil {
		return nil, err
	}

	// Subscribe auditor to the monitor
	agent.monitor.AddTaskNotifyChs("AUDITOR", &agent.auditor.TaskStartCh, &agent.auditor.TaskDeleteCh, &agent.auditor.TaskDeleteSyncCh)

	// [Experimental feature]
	//     Initialize the process tracer for BehaviorModeling mode.
	//     It only works with AppArmor and Seccomp enforcers for now.
	// TODO: Support BPF enforcer
	if agent.enableBehaviorModeling {
		log.Info("initialize the process tracer for BehaviorModeling mode")
		agent.ptracer, err = varmorptracer.NewProcessTracer(log.WithName("TRACER"))
		if err != nil {
			return nil, err
		}
	}

	return &agent, nil
}

func (agent *Agent) WaitForManagerReady() {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	url := fmt.Sprintf("https://%s%s", agent.svcAddresses[varmorconfig.StatusServiceName], "/healthz")
	for {
		resp, err := client.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return
		}
		time.Sleep(2 * time.Second)
	}
}

func (agent *Agent) SetAgentReady() {
	atomic.StoreInt32(&agent.ready, 1)
}

func (agent *Agent) SetAgentUnready() {
	atomic.StoreInt32(&agent.ready, 0)
}

func (agent *Agent) enqueuePolicy(ap *varmor.ArmorProfile, logger logr.Logger) {
	key, err := cache.MetaNamespaceKeyFunc(ap)
	if err != nil {
		logger.Error(err, "cache.MetaNamespaceKeyFunc()")
		return
	}
	agent.queue.Add(key)
}

func (agent *Agent) addArmorProfile(obj interface{}) {
	logger := agent.log.WithName("AddFunc()")

	ap := obj.(*varmor.ArmorProfile)

	if ap.Name != ap.Spec.Profile.Name {
		// This shouldn't have happened.
		logger.Error(fmt.Errorf("the name of ArmorProfile should equal with its spec.profile.name"), "illegal object")
	} else {
		logger.V(2).Info("enqueue ArmorPolicy")
		agent.enqueuePolicy(ap, logger)
	}
}

func (agent *Agent) deleteArmorProfile(obj interface{}) {
	logger := agent.log.WithName("DeleteFunc()")

	ap := obj.(*varmor.ArmorProfile)

	if ap.Name != ap.Spec.Profile.Name {
		// This shouldn't have happened.
		logger.Error(fmt.Errorf("the name of ArmorProfile should equal with its spec.profile.name"), "illegal object")
	} else {
		logger.V(2).Info("enqueue ArmorPolicy")
		agent.enqueuePolicy(ap, logger)
	}
}

func (agent *Agent) updateArmorProfile(oldObj interface{}, newObj interface{}) {
	logger := agent.log.WithName("UpdateFunc()")

	oldAp := oldObj.(*varmor.ArmorProfile)
	newAp := newObj.(*varmor.ArmorProfile)

	var oldReconcile, newReconcile int
	if oldAp.Annotations != nil {
		value := oldAp.Annotations[varmortypes.ReconcileAnnotation]
		oldReconcile, _ = strconv.Atoi(value)
	}
	if newAp.Annotations != nil {
		value := newAp.Annotations[varmortypes.ReconcileAnnotation]
		newReconcile, _ = strconv.Atoi(value)
	}

	if reflect.DeepEqual(newAp.Spec, oldAp.Spec) && newReconcile == oldReconcile {
		logger.V(2).Info("Nothing need to be updated")
	} else if newAp.Name != newAp.Spec.Profile.Name {
		// This shouldn't have happened.
		logger.Error(fmt.Errorf("new and old objects should have same spec.profile.name"), "illegal object")
	} else {
		logger.V(2).Info("enqueue ArmorPolicy")
		agent.enqueuePolicy(newAp, logger)
	}
}

func (agent *Agent) sendStatus(ap *varmor.ArmorProfile, status varmortypes.Status, message string) error {
	s := varmortypes.ProfileStatus{
		Namespace:   ap.Namespace,
		ProfileName: ap.Name,
		NodeName:    agent.nodeName,
		Status:      status,
		Message:     message,
	}
	reqBody, _ := json.Marshal(&s)
	address := agent.svcAddresses[varmorconfig.StatusServiceName]
	return varmorutils.HTTPSPostWithRetryAndToken(address, varmorconfig.StatusSyncPath, reqBody, agent.inContainer)
}

func (agent *Agent) selectEnforcer(ap *varmor.ArmorProfile) (varmortypes.Enforcer, error) {
	e := varmortypes.GetEnforcerType(ap.Spec.Profile.Enforcer)

	if (e&varmortypes.AppArmor != 0) && !agent.appArmorSupported {
		return e, fmt.Errorf("the AppArmor LSM feature is not supported by the host, or the AppArmor enforcer has been disabled in vArmor")
	}

	if (e&varmortypes.BPF != 0) && !agent.bpfLsmSupported {
		return e, fmt.Errorf("the BPF LSM feature is not supported by the host, or the BPF enforcer has not been enabled in vArmor")
	}

	if (e&varmortypes.Seccomp != 0) && !agent.seccompSupported {
		return e, fmt.Errorf("the Seccomp enforcer needs Kubernetes v1.19 and above")
	}

	if (e&varmortypes.BPF != 0) && ap.Spec.BehaviorModeling.Enable {
		return e, fmt.Errorf("the BPF enforcer does not support the BehaviorModeling mode")
	}

	if e&varmortypes.Unknown != 0 {
		return e, fmt.Errorf("unknown enforcer")
	}

	return e, nil
}

// handleCreateOrUpdateArmorProfile load or reload AppArmor Profile for containers.
func (agent *Agent) handleCreateOrUpdateArmorProfile(ap *varmor.ArmorProfile, key string) error {
	logger := agent.log.WithName("handleCreateOrUpdateArmorProfile()")

	logger.Info("ArmorProfile created or updated", "namespace", ap.Namespace, "name", ap.Name,
		"labels", ap.Labels, "profile name", ap.Spec.Profile.Name, "profile mode", ap.Spec.Profile.Mode)

	defer func() {
		if !agent.bpfLsmSupported || agent.existingApCount <= agent.processedApCount {
			return
		}
		agent.processedApCount += 1
		if agent.existingApCount == agent.processedApCount {
			agent.waitExistingApSync.Done()
		}
	}()

	enforcer, err := agent.selectEnforcer(ap)
	if err != nil {
		// If the enforcer is not supported, we should send a failed status to the manager.
		logger.Info("send a failed status to the manager", "error", err.Error())
		return agent.sendStatus(ap, varmortypes.Failed, err.Error())
	}

	// [Experimental feature] For BehaviorModeling mode,
	// only works with AppArmor/Seccomp/AppArmorSeccomp enforcer for now.
	if agent.enableBehaviorModeling {
		createTime := ap.CreationTimestamp.Time
		Duration := time.Duration(ap.Spec.BehaviorModeling.Duration) * time.Minute

		modeller, exist := agent.modellers[key]
		if exist && modeller.IsModeling() {
			modeller.UpdateDuration(Duration)
		} else {
			if time.Now().Before(createTime.Add(Duration)) {
				// Create a new modeller and start modeling for the ArmorProfile object.
				modeller = varmorbehavior.NewBehaviorModeller(
					agent.auditor,
					agent.ptracer,
					agent.monitor,
					agent.nodeName,
					ap.Namespace,
					ap.Name,
					ap.Spec.Profile.Enforcer,
					createTime,
					Duration,
					agent.stopCh,
					agent.svcAddresses,
					agent.debug,
					agent.inContainer,
					agent.log.WithName("BEHAVIOR-MODELLER"))
				agent.modellers[key] = modeller
				modeller.Run()
			}
		}
	}

	var errorMessages []string

	// AppArmor
	if (enforcer & varmortypes.AppArmor) != 0 {
		// Save and load AppArmor profile.
		logger.Info(fmt.Sprintf("saving the AppArmor profile '%s (%s)' to Node/%s", ap.Spec.Profile.Name, ap.Spec.Profile.Mode, agent.nodeName))
		profilePath := filepath.Join(agent.appArmorProfileDir, ap.Spec.Profile.Name)
		err := varmorapparmor.SaveAppArmorProfile(profilePath, ap.Spec.Profile.Content)
		if err != nil {
			logger.Error(err, "SaveAppArmorProfile()")
			errorMessages = append(errorMessages, "SaveAppArmorProfile(): "+err.Error())
		} else {
			if yes, _ := varmorapparmor.IsAppArmorProfileLoaded(ap.Spec.Profile.Name); !yes {
				// Load a new AppArmor profile to kernel for ArmorProfile creation event.
				logger.Info(fmt.Sprintf("loading '%s (%s)' to Node/%s's kernel", ap.Spec.Profile.Name, ap.Spec.Profile.Mode, agent.nodeName))
				output, err := varmorapparmor.LoadAppArmorProfile(profilePath, ap.Spec.Profile.Mode)
				if err != nil {
					logger.Error(err, "LoadAppArmorProfile()", "output", output)
					errorMessages = append(errorMessages, "LoadAppArmorProfile(): "+err.Error()+"  output: "+output)
				}
			} else {
				// Update a existing AppArmor profile for ArmorProfile update event.
				logger.Info(fmt.Sprintf("reloading '%s (%s)' to Node/%s's kernel", ap.Spec.Profile.Name, ap.Spec.Profile.Mode, agent.nodeName))
				output, err := varmorapparmor.UpdateAppArmorProfile(profilePath, ap.Spec.Profile.Mode)
				if err != nil {
					logger.Error(err, "UpdateAppArmorProfile()", "output", output)
					errorMessages = append(errorMessages, "UpdateAppArmorProfile(): "+err.Error()+"  output: "+output)
				}
			}
		}
	}

	// BPF
	if (enforcer & varmortypes.BPF) != 0 {
		// Save and apply BPF profile.
		logger.Info(fmt.Sprintf("saving and applying the BPF profile '%s (%s)' to Node/%s", ap.Spec.Profile.Name, ap.Spec.Profile.Mode, agent.nodeName))
		err := agent.bpfEnforcer.SaveAndApplyBpfProfile(ap.Spec.Profile.Name, ap.Spec.Profile.Mode, *ap.Spec.Profile.BpfContent)
		if err != nil {
			logger.Error(err, "SaveAndApplyBpfProfile()")
			errorMessages = append(errorMessages, "SaveAndApplyBpfProfile(): "+err.Error())
		}
	} else if agent.bpfLsmSupported && agent.bpfEnforcer.IsBpfProfileExist(ap.Spec.Profile.Name) {
		// Remove BPF profile if the policy no longer uses the BPF enforcer.
		logger.Info(fmt.Sprintf("unloading the BPF profile '%s' from Node/%s's kernel", ap.Spec.Profile.Name, agent.nodeName))
		err := agent.bpfEnforcer.DeleteBpfProfile(ap.Spec.Profile.Name)
		if err != nil {
			logger.Error(err, "DeleteBpfProfile()")
			errorMessages = append(errorMessages, "DeleteBpfProfile(): "+err.Error())
		}
	}

	// Seccomp
	if (enforcer & varmortypes.Seccomp) != 0 {
		// Save Seccomp profile.
		logger.Info(fmt.Sprintf("saving the Seccomp profile '%s (%s)' to Node/%s", ap.Spec.Profile.Name, ap.Spec.Profile.Mode, agent.nodeName))
		profilePath := filepath.Join(agent.seccompProfileDir, ap.Spec.Profile.Name)
		err := varmorseccomp.SaveSeccompProfile(profilePath, ap.Spec.Profile.SeccompContent)
		if err != nil {
			logger.Error(err, "SaveSeccompProfile()")
			errorMessages = append(errorMessages, "SaveSeccompProfile(): "+err.Error())
		}
	}

	logger.Info("send a status to the manager")
	if len(errorMessages) > 0 {
		combinedErr := strings.Join(errorMessages, "; ")
		return agent.sendStatus(ap, varmortypes.Failed, combinedErr)
	} else {
		return agent.sendStatus(ap, varmortypes.Succeeded, string(varmor.ArmorProfileReady))
	}
}

func (agent *Agent) handleDeleteArmorProfile(namespace, name, key string) error {
	logger := agent.log.WithName("handleDeleteArmorProfile()")

	logger.Info("ArmorProfile deleted", "namespace", namespace, "name", name)

	if !agent.appArmorSupported && !agent.bpfLsmSupported {
		return nil
	}

	if modeller, ok := agent.modellers[key]; ok {
		modeller.ModellerStopCh <- true
		delete(agent.modellers, key)
	}

	// BPF
	if agent.bpfLsmSupported && agent.bpfEnforcer.IsBpfProfileExist(name) {
		logger.Info(fmt.Sprintf("unloading the BPF profile ('%s') from Node/%s's kernel", name, agent.nodeName))
		err := agent.bpfEnforcer.DeleteBpfProfile(name)
		if err != nil {
			logger.Error(err, "DeleteBpfProfile()")
		}
	}

	// AppArmor
	if agent.appArmorSupported {
		if loaded, _ := varmorapparmor.IsAppArmorProfileLoaded(name); loaded {
			logger.Info(fmt.Sprintf("unloading the AppArmor profile ('%s') from Node/%s's kernel", name, agent.nodeName))
			profilePath := filepath.Join(agent.appArmorProfileDir, name)
			output, err := varmorapparmor.UnloadAppArmorProfile(profilePath)
			if err != nil {
				logger.Error(err, "UnloadAppArmorProfile()", "output", output)
			}

			logger.Info(fmt.Sprintf("removing the AppArmor profile ('%s') from Node/%s", name, agent.nodeName))
			err = varmorapparmor.RemoveAppArmorProfile(profilePath)
			if err != nil {
				logger.Error(err, "RemoveAppArmorProfile()")
			}
		}
	}

	// Seccomp
	profilePath := filepath.Join(agent.seccompProfileDir, name)
	if varmorseccomp.SeccompProfileExist(profilePath) {
		logger.Info(fmt.Sprintf("removing the Seccomp profile ('%s') from Node/%s", name, agent.nodeName))
		err := varmorseccomp.RemoveSeccompProfile(profilePath)
		if err != nil {
			logger.Error(err, "RemoveSeccompProfile()")
		}
	}

	return nil
}

func (agent *Agent) syncProfile(key string) error {
	logger := agent.log.WithName("syncProfile()")

	startTime := time.Now()
	logger.V(2).Info("started syncing profile", "key", key, "startTime", startTime)
	defer func() {
		logger.V(2).Info("finished syncing profile", "key", key, "processingTime", time.Since(startTime).String())
	}()

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		logger.Error(err, "cache.SplitMetaNamespaceKey()")
		return err
	}

	ap, err := agent.varmorInterface.ArmorProfiles(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) {
			// ArmorProfile delete event
			logger.V(2).Info("processing ArmorProfile delete event")
			return agent.handleDeleteArmorProfile(namespace, name, key)
		} else {
			logger.Error(err, "agent.varmorInterface.ArmorProfiles().Get()")
			return err
		}
	} else {
		// ArmorProfile create or update event
		logger.V(2).Info("processing ArmorProfile create or update event")
		return agent.handleCreateOrUpdateArmorProfile(ap, key)
	}
}

func (agent *Agent) handleErr(err error, key interface{}) {
	logger := agent.log
	if err == nil {
		agent.queue.Forget(key)
		return
	}

	if agent.queue.NumRequeues(key) < maxRetries {
		logger.V(2).Error(err, "failed to sync profile", "key", key)
		agent.queue.AddRateLimited(key)
		return
	}

	utilruntime.HandleError(err)
	logger.Error(err, "max retries exceeded, dropping profile out of queue", "key", key)
	agent.queue.Forget(key)
}

func (agent *Agent) processNextWorkItem() bool {
	key, quit := agent.queue.Get()
	if quit {
		return false
	}
	defer agent.queue.Done(key)
	err := agent.syncProfile(key.(string))
	agent.handleErr(err, key)

	return true
}

func (agent *Agent) worker() {
	for agent.processNextWorkItem() {
	}
}

func (agent *Agent) Run(workers int, stopCh <-chan struct{}) {
	logger := agent.log
	logger.Info("starting")

	defer utilruntime.HandleCrash()

	if !cache.WaitForCacheSync(stopCh, agent.apInformerSynced) {
		logger.Error(fmt.Errorf("failed to sync informer cache"), "cache.WaitForCacheSync()")
		return
	}

	agent.apInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    agent.addArmorProfile,
		DeleteFunc: agent.deleteArmorProfile,
		UpdateFunc: agent.updateArmorProfile,
	})

	for i := 0; i < workers; i++ {
		go wait.Until(agent.worker, time.Second, stopCh)
	}

	// Run bpf enforcer if BPF LSM is supported.
	if agent.bpfLsmSupported {
		go agent.bpfEnforcer.Run(stopCh)
	}

	// Run auditor to record violation behaviors
	go agent.auditor.Run(stopCh)

	// Run runtime monitor to watch container events and send them to subscribers
	go agent.monitor.Run(stopCh)

	// Wait for all existing ArmorProfile objects have been processed.
	if agent.existingApCount > 0 {
		agent.waitExistingApSync.Wait()
		// Gather all existing target containers and send them to subscribers
		err := agent.monitor.CollectExistingTargetContainers()
		if err != nil {
			logger.Error(err, "CollectExistingTargetContainers() failed")
		}
	}

	<-stopCh
}

func (agent *Agent) CleanUp() {
	agent.log.Info("cleaning up")
	agent.SetAgentUnready()
	agent.queue.ShutDown()
	agent.monitor.Close()
	agent.auditor.Close()

	if agent.enableBehaviorModeling {
		agent.ptracer.Close()
	}

	if agent.appArmorSupported && agent.unloadAllAaProfiles {
		agent.log.WithName("APPARMOR-ENFORCER").Info("unload all AppArmor profiles")
		varmorapparmor.UnloadAllAppArmorProfiles(agent.appArmorProfileDir)
	}

	if agent.removeAllSeccompProfiles {
		agent.log.WithName("APPARMOR-ENFORCER").Info("remove all Seccomp profiles")
		varmorseccomp.RemoveAllSeccompProfiles(agent.seccompProfileDir)
	}

	if agent.bpfLsmSupported {
		agent.bpfEnforcer.Close()
	}
}
