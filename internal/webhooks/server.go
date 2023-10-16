// Copyright 2022-2023 vArmor Authors
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

package webhooks

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"github.com/julienschmidt/httprouter"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/tools/cache"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	"github.com/bytedance/vArmor/internal/policycacher"
	varmorprofile "github.com/bytedance/vArmor/internal/profile"
	varmortls "github.com/bytedance/vArmor/internal/tls"
	"github.com/bytedance/vArmor/internal/webhookconfig"
)

// WebhookServer contains configured TLS server with MutationWebhook.
type WebhookServer struct {
	server           *http.Server
	webhookRegister  *webhookconfig.Register
	policyCacher     *policycacher.PolicyCacher
	deserializer     runtime.Decoder
	bpfExclusiveMode bool
	log              logr.Logger
}

func NewWebhookServer(
	webhookRegister *webhookconfig.Register,
	policyCacher *policycacher.PolicyCacher,
	tlsPair *varmortls.PemPair,
	addr string,
	port int,
	bpfExclusiveMode bool,
	log logr.Logger,
) (*WebhookServer, error) {

	ws := &WebhookServer{
		webhookRegister:  webhookRegister,
		policyCacher:     policyCacher,
		bpfExclusiveMode: bpfExclusiveMode,
		log:              log,
	}

	scheme := runtime.NewScheme()
	codecs := serializer.NewCodecFactory(scheme)
	ws.deserializer = codecs.UniversalDeserializer()

	mux := httprouter.New()
	mux.HandlerFunc("POST", varmorconfig.MutatingWebhookServicePath, ws.handlerFunc(ws.resourceMutation))

	// Patch Liveness responds to a Kubernetes Liveness probe.
	// Fail this request if Kubernetes should restart this instance.
	mux.HandlerFunc("GET", varmorconfig.LivenessServicePath, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if err := ws.webhookRegister.Check(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	})

	// Patch Readiness responds to a Kubernetes Readiness probe.
	// Fail this request if this instance can't accept traffic, but Kubernetes shouldn't restart it.
	mux.HandlerFunc("GET", varmorconfig.ReadinessServicePath, func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		w.WriteHeader(http.StatusOK)
	})

	var tlsConfig tls.Config
	pair, err := tls.X509KeyPair(tlsPair.Certificate, tlsPair.PrivateKey)
	if err != nil {
		return nil, err
	}
	tlsConfig.Certificates = []tls.Certificate{pair}

	ws.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", addr, port),
		TLSConfig:    &tlsConfig,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	return ws, nil
}

func (ws *WebhookServer) handlerFunc(handler func(request *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		admissionReview := bodyToAdmissionReview(r, rw, ws.log)
		if admissionReview == nil {
			ws.log.Error(fmt.Errorf("failed to parse admission review request"), "request", r)
			return
		}

		logger := ws.log.WithName("handlerFunc").WithValues("uid", admissionReview.Request.UID)

		request := admissionReview.Request
		admissionReview.Response = &admissionv1.AdmissionResponse{
			Allowed: true,
			UID:     admissionReview.Request.UID,
		}

		logger.V(3).Info("AdmissionRequest received",
			"uid", request.UID, "kind", request.Kind.String(),
			"namespace", request.Namespace, "name", request.Name,
			"operation", request.Operation)

		admissionReview.Response = handler(request)
		writeResponse(rw, admissionReview)

		logger.V(3).Info("AdmissionRequest processed", "time", time.Since(startTime).String())
	}
}

func (ws *WebhookServer) matchAndPatch(request *admissionv1.AdmissionRequest, key string, target varmor.Target, logger logr.Logger) *admissionv1.AdmissionResponse {
	policyNamespace, policyName, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return nil
	}
	logger.V(3).Info("policy matching", "policy namespace", policyNamespace, "policy name", policyName)

	clusterScope := policyNamespace == ""
	if !clusterScope && policyNamespace != request.Namespace {
		return nil
	}

	if request.Kind.Kind != target.Kind {
		return nil
	}

	enforcer := ""
	if clusterScope {
		enforcer = ws.policyCacher.ClusterPolicyEnforcer[key]
	} else {
		enforcer = ws.policyCacher.PolicyEnforcer[key]
	}

	apName := varmorprofile.GenerateArmorProfileName(policyNamespace, policyName, clusterScope)

	switch request.Kind.Kind {
	case "Deployment":
		deploy := appsv1.Deployment{}
		if _, _, err := ws.deserializer.Decode(request.Object.Raw, nil, &deploy); err != nil {
			logger.Error(err, "ws.deserializer.Decode()")
			break
		}

		if target.Name != "" && target.Name == deploy.Name {
			logger.Info("mutating resource", "resource kind", request.Kind.Kind, "resource namespace", request.Namespace, "resource name", request.Name, "profile", apName)
			patch, err := buildPatch(&deploy, enforcer, target, apName, ws.bpfExclusiveMode)
			if err != nil {
				logger.Error(err, "ws.buildPatch()")
				break
			}
			return successResponse(request.UID, []byte(patch))
		} else if target.Selector != nil {
			selector, err := metav1.LabelSelectorAsSelector(target.Selector)
			if err != nil {
				break
			}
			if selector.Matches(labels.Set(deploy.Labels)) {
				logger.Info("mutating resource", "resource kind", request.Kind.Kind, "resource namespace", request.Namespace, "resource name", request.Name, "profile", apName)
				patch, err := buildPatch(&deploy, enforcer, target, apName, ws.bpfExclusiveMode)
				if err != nil {
					logger.Error(err, "ws.buildPatch()")
					break
				}
				return successResponse(request.UID, []byte(patch))
			}
		}
	case "StatefulSet":
		statusful := appsv1.StatefulSet{}
		if _, _, err := ws.deserializer.Decode(request.Object.Raw, nil, &statusful); err != nil {
			logger.Error(err, "ws.deserializer.Decode()")
			break
		}

		if target.Name != "" && target.Name == statusful.Name {
			logger.Info("mutating resource", "resource kind", request.Kind.Kind, "resource namespace", request.Namespace, "resource name", request.Name, "profile", apName)
			patch, err := buildPatch(&statusful, enforcer, target, apName, ws.bpfExclusiveMode)
			if err != nil {
				logger.Error(err, "ws.buildPatch()")
				break
			}
			return successResponse(request.UID, []byte(patch))
		} else if target.Selector != nil {
			selector, err := metav1.LabelSelectorAsSelector(target.Selector)
			if err != nil {
				break
			}
			if selector.Matches(labels.Set(statusful.Labels)) {
				logger.Info("mutating resource", "resource kind", request.Kind.Kind, "resource namespace", request.Namespace, "resource name", request.Name, "profile", apName)
				patch, err := buildPatch(&statusful, enforcer, target, apName, ws.bpfExclusiveMode)
				if err != nil {
					logger.Error(err, "ws.buildPatch()")
					break
				}
				return successResponse(request.UID, []byte(patch))
			}
		}
	case "DaemonSet":
		daemon := appsv1.DaemonSet{}
		if _, _, err := ws.deserializer.Decode(request.Object.Raw, nil, &daemon); err != nil {
			logger.Error(err, "ws.deserializer.Decode()")
			break
		}

		if _, _, err := ws.deserializer.Decode(request.Object.Raw, nil, &daemon); err != nil {
			logger.Error(err, "ws.deserializer.Decode()")
			break
		}

		if target.Name != "" && target.Name == daemon.Name {
			logger.Info("mutating resource", "resource kind", request.Kind.Kind, "resource namespace", request.Namespace, "resource name", request.Name, "profile", apName)
			patch, err := buildPatch(&daemon, enforcer, target, apName, ws.bpfExclusiveMode)
			if err != nil {
				logger.Error(err, "ws.buildPatch()")
				break
			}
			return successResponse(request.UID, []byte(patch))
		} else if target.Selector != nil {
			selector, err := metav1.LabelSelectorAsSelector(target.Selector)
			if err != nil {
				break
			}
			if selector.Matches(labels.Set(daemon.Labels)) {
				logger.Info("mutating resource", "resource kind", request.Kind.Kind, "resource namespace", request.Namespace, "resource name", request.Name, "profile", apName)
				patch, err := buildPatch(&daemon, enforcer, target, apName, ws.bpfExclusiveMode)
				if err != nil {
					logger.Error(err, "ws.buildPatch()")
					break
				}
				return successResponse(request.UID, []byte(patch))
			}
		}
	case "Pod":
		pod := corev1.Pod{}
		if _, _, err := ws.deserializer.Decode(request.Object.Raw, nil, &pod); err != nil {
			logger.Error(err, "ws.deserializer.Decode()")
			break
		}

		if target.Name != "" && target.Name == pod.Name {
			logger.Info("mutating resource", "resource kind", request.Kind.Kind, "resource namespace", request.Namespace, "resource name", request.Name, "profile", apName)
			patch, err := buildPatch(&pod, enforcer, target, apName, ws.bpfExclusiveMode)
			if err != nil {
				logger.Error(err, "ws.buildPatch()")
				break
			}
			return successResponse(request.UID, []byte(patch))
		} else if target.Selector != nil {
			selector, err := metav1.LabelSelectorAsSelector(target.Selector)
			if err != nil {
				break
			}
			if selector.Matches(labels.Set(pod.Labels)) {
				if request.Name == "" {
					logger.Info("mutating resource", "resource kind", request.Kind.Kind, "resource namespace", request.Namespace, "resource name", pod.GenerateName, "profile", apName)
				} else {
					logger.Info("mutating resource", "resource kind", request.Kind.Kind, "resource namespace", request.Namespace, "resource name", request.Name, "profile", apName)
				}
				patch, err := buildPatch(&pod, enforcer, target, apName, ws.bpfExclusiveMode)
				if err != nil {
					logger.Error(err, "ws.buildPatch()")
					break
				}
				return successResponse(request.UID, []byte(patch))
			}
		}
	}

	return nil
}

// resourceMutation mutates workloads that meet the .spec.target condition of either VarmorClusterPolicy or VarmorPolicy.
// VarmorClusterPolicy objects have higher priority than VarmorPolicy objects. When both a VarmorClusterPolicy object and
// a VarmorPolicy object match a workload, VarmorClusterPolicy will be used to secure the workload. When multiple
// VarmorClusterPolicy/VarmorPolicy objects match a Workload, one will be randomly selected to secure the workload.
func (ws *WebhookServer) resourceMutation(request *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	logger := ws.log.WithName("resourceMutation()")

	for key, target := range ws.policyCacher.ClusterPolicyTargets {
		response := ws.matchAndPatch(request, key, target, logger)
		if response != nil {
			return response
		}
	}

	for key, target := range ws.policyCacher.PolicyTargets {
		response := ws.matchAndPatch(request, key, target, logger)
		if response != nil {
			return response
		}
	}

	logger.V(3).Info("no mutation required")
	return successResponse(request.UID, nil)
}

// Run start the tls server immediately.
func (ws *WebhookServer) Run() {
	logger := ws.log

	logger.Info("starting", "addr", ws.server.Addr)
	if err := ws.server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		logger.Error(err, "failed to listen to requests")
	}
}

// CleanUp stop the tls server and returns control after the server is shut down.
func (ws *WebhookServer) CleanUp() {
	logger := ws.log
	logger.Info("cleaning up")

	// Shutdown http.Server with context timeout.
	err := ws.server.Shutdown(context.Background())
	if err != nil {
		// Error from closing listeners, or context timeout.
		logger.Error(err, "shutting down webhook server")
		err = ws.server.Close()
		if err != nil {
			logger.Error(err, "webhook server shut down failed")
		}
	}
}
