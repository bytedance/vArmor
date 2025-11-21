// Copyright 2022-2025 vArmor Authors
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

// Package webhooks implements the webhook server for the admission webhook.
package webhooks

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/go-logr/logr"
	"github.com/julienschmidt/httprouter"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	"github.com/bytedance/vArmor/internal/policycacher"
	varmortls "github.com/bytedance/vArmor/internal/tls"
	"github.com/bytedance/vArmor/internal/webhookconfig"
	"github.com/bytedance/vArmor/pkg/metrics"
)

// WebhookServer contains configured TLS server with MutationWebhook.
type WebhookServer struct {
	server                 *http.Server
	webhookRegister        *webhookconfig.Register
	policyCacher           *policycacher.PolicyCacher
	deserializer           runtime.Decoder
	enableBehaviorModeling bool
	bpfExclusiveMode       bool
	metricsModule          *metrics.MetricsModule
	admissionRequests      metric.Float64Counter
	mutatedRequests        metric.Float64Counter
	nonMutatedRequests     metric.Float64Counter
	webhookLatency         metric.Float64Histogram
	log                    logr.Logger
}

func NewWebhookServer(
	webhookRegister *webhookconfig.Register,
	policyCacher *policycacher.PolicyCacher,
	tlsPair *varmortls.PemPair,
	addr string,
	port int,
	enableBehaviorModeling bool,
	bpfExclusiveMode bool,
	metricsModule *metrics.MetricsModule,
	log logr.Logger,
) (*WebhookServer, error) {

	ws := &WebhookServer{
		webhookRegister:        webhookRegister,
		policyCacher:           policyCacher,
		enableBehaviorModeling: enableBehaviorModeling,
		bpfExclusiveMode:       bpfExclusiveMode,
		metricsModule:          metricsModule,
		log:                    log,
	}

	if metricsModule.Enabled {
		ws.admissionRequests = metricsModule.RegisterFloat64Counter("varmor_admission_requests_total", "Total number of admission requests")
		ws.mutatedRequests = metricsModule.RegisterFloat64Counter("varmor_mutated_requests", "Number of requests that were mutated")
		ws.nonMutatedRequests = metricsModule.RegisterFloat64Counter("varmor_non_mutated_requests", "Number of requests that were not mutated")
		ws.webhookLatency = metricsModule.RegisterHistogram("varmor_webhook_latency", "Latency of webhook processing", 0.1, 0.5, 1, 2, 5)
	}

	scheme := runtime.NewScheme()
	// Register vArmor CRD types to the scheme
	utilruntime.Must(varmor.AddToScheme(scheme))
	codecs := serializer.NewCodecFactory(scheme)
	ws.deserializer = codecs.UniversalDeserializer()

	mux := httprouter.New()
	mux.HandlerFunc("POST", varmorconfig.MutatingWebhookServicePath, ws.handlerFunc(ws.resourceMutation))
	mux.HandlerFunc("POST", varmorconfig.ValidatingWebhookServicePath, ws.handlerFunc(ws.policyValidation))

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
		ctx := context.Background()
		startTime := time.Now()

		if ws.admissionRequests != nil {
			ws.admissionRequests.Add(ctx, 1)
		}
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

		logger.V(2).Info("AdmissionRequest received",
			"uid", request.UID, "kind", request.Kind.String(),
			"namespace", request.Namespace, "name", request.Name,
			"operation", request.Operation)

		admissionReview.Response = handler(request)
		mutated := false
		if len(admissionReview.Response.Patch) > 0 {
			mutated = true
			if ws.mutatedRequests != nil {
				ws.mutatedRequests.Add(ctx, 1)
			}
		} else {
			if ws.nonMutatedRequests != nil {
				ws.nonMutatedRequests.Add(ctx, 1)
			}
		}
		writeResponse(rw, admissionReview)

		if ws.webhookLatency != nil {
			keyValues := []attribute.KeyValue{
				attribute.String("request_uid", string(request.UID)),
				attribute.String("request_kind", request.Kind.String()),
				attribute.String("request_namespace", request.Namespace),
				attribute.String("request_name", request.Name),
				attribute.String("request_operation", string(request.Operation)),
				attribute.String("request_mutated", fmt.Sprintf("%t", mutated)),
			}
			attrSet := attribute.NewSet(keyValues...)
			ws.webhookLatency.Record(ctx, time.Since(startTime).Seconds(), metric.WithAttributeSet(attrSet))
		}
		logger.V(2).Info("AdmissionRequest processed", "time", time.Since(startTime).String())
	}
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

	logger.V(2).Info("no mutation required")
	return successResponse(request.UID, nil)
}

func (ws *WebhookServer) policyValidation(request *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	logger := ws.log.WithName("policyValidation()")
	logger.Info("validating policy", "kind", request.Kind.Kind, "namespace", request.Namespace, "name", request.Name, "operation", request.Operation)

	var new, old interface{}
	new, _, err := ws.deserializer.Decode(request.Object.Raw, nil, nil)
	if err != nil {
		logger.Error(err, "ws.deserializer.Decode()")
		return successResponse(request.UID, nil)
	}

	if request.Operation == admissionv1.Update {
		old, _, err = ws.deserializer.Decode(request.OldObject.Raw, nil, nil)
		if err != nil {
			logger.Error(err, "ws.deserializer.Decode()")
			return successResponse(request.UID, nil)
		}
	}

	return ws.validatePolicy(request, new, old, logger)
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
