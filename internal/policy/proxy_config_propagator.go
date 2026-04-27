// Copyright 2026 vArmor Authors
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

package policy

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	coreinformer "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	corelister "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmornetworkproxy "github.com/bytedance/vArmor/internal/networkproxy"
	"github.com/bytedance/vArmor/internal/policycacher"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
)

type ProxyConfigPropagator struct {
	kubeClient       *kubernetes.Clientset
	varmorInterface  varmorinterface.CrdV1beta1Interface
	nsInformer       coreinformer.NamespaceInformer
	nsLister         corelister.NamespaceLister
	nsInformerSynced cache.InformerSynced
	policyCacher     *policycacher.PolicyCacher
	stopCh           <-chan struct{}
	log              logr.Logger
}

// NewProxyConfigPropagator creates a new ProxyConfigPropagator which propagates proxy config to all new namespaces.
// It listens to namespace creation events and creates the proxy config for the VarmorClusterPolicy with the NetworkProxy enforcer.
func NewProxyConfigPropagator(
	kubeClient *kubernetes.Clientset,
	varmorInterface varmorinterface.CrdV1beta1Interface,
	nsInformer coreinformer.NamespaceInformer,
	policyCacher *policycacher.PolicyCacher,
	stopCh <-chan struct{},
	log logr.Logger) *ProxyConfigPropagator {

	return &ProxyConfigPropagator{
		kubeClient:       kubeClient,
		varmorInterface:  varmorInterface,
		nsInformer:       nsInformer,
		nsLister:         nsInformer.Lister(),
		nsInformerSynced: nsInformer.Informer().HasSynced,
		policyCacher:     policyCacher,
		stopCh:           stopCh,
		log:              log}
}

func (p *ProxyConfigPropagator) Run(stopCh <-chan struct{}) {
	logger := p.log
	logger.Info("starting")

	defer utilruntime.HandleCrash()

	if !cache.WaitForCacheSync(stopCh, p.nsInformerSynced) {
		logger.Error(fmt.Errorf("failed to sync informer cache"), "cache.WaitForCacheSync()")
		return
	}

	p.nsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: p.addNamespace,
	})
}

func (p *ProxyConfigPropagator) addNamespace(obj interface{}) {
	logger := p.log
	ns := obj.(*v1.Namespace).Name

	for key, enforcers := range p.policyCacher.ClusterPolicyEnforcer {
		e := varmortypes.GetEnforcerType(enforcers)
		if (e & varmortypes.NetworkProxy) == 0 {
			continue
		}

		if p.policyCacher.ClusterPolicyMode[key] == varmor.BehaviorModelingMode {
			continue
		}

		_, name, err := cache.SplitMetaNamespaceKey(key)
		if err != nil {
			logger.Error(err, "cache.SplitMetaNamespaceKey()")
			continue
		}

		vcp, err := p.varmorInterface.VarmorClusterPolicies().Get(context.Background(), name, metav1.GetOptions{})
		if err != nil {
			continue
		}

		err = varmornetworkproxy.CreateNetworkProxyConfigMap(p.kubeClient, vcp, ns, true, logger)
		if err != nil {
			logger.Error(err, "CreateNetworkProxyConfigMap()")
			continue
		}

		logger.Info("the config map has been created for the new namespace", "namespace", ns, "name", vcp.Status.ProfileName)
	}
}
