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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	"github.com/bytedance/vArmor/internal/networkproxy"
	varmorprofile "github.com/bytedance/vArmor/internal/profile"
	varmorfake "github.com/bytedance/vArmor/pkg/client/clientset/versioned/fake"
)

// The production resolver takes a concrete Clientset. This loopback API
// exercises its real Secret reads and writes without a Kubernetes cluster.
func newMITMSecretTestClient(t *testing.T, namespace string) (*kubernetes.Clientset, *atomic.Int32) {
	t.Helper()
	var mu sync.Mutex
	var writes atomic.Int32
	secrets := make(map[string]*corev1.Secret)
	prefix := "/api/v1/namespaces/" + namespace + "/secrets"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces" {
			assert.NoError(t, json.NewEncoder(w).Encode(&corev1.NamespaceList{Items: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: namespace}}}}))
			return
		}
		if r.URL.Path != prefix && !strings.HasPrefix(r.URL.Path, prefix+"/") {
			t.Errorf("unexpected API request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected API path", http.StatusNotFound)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, prefix+"/")
		switch r.Method {
		case http.MethodGet:
			secret, ok := secrets[name]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				assert.NoError(t, json.NewEncoder(w).Encode(&metav1.Status{Status: "Failure", Reason: metav1.StatusReasonNotFound, Code: http.StatusNotFound}))
				return
			}
			assert.NoError(t, json.NewEncoder(w).Encode(secret))
		case http.MethodPost, http.MethodPut:
			var secret corev1.Secret
			if err := json.NewDecoder(r.Body).Decode(&secret); err != nil {
				t.Errorf("decode Secret: %v", err)
				http.Error(w, "invalid Secret", http.StatusBadRequest)
				return
			}
			if secret.Data == nil {
				secret.Data = make(map[string][]byte)
			}
			for key, value := range secret.StringData {
				secret.Data[key] = []byte(value)
			}
			secret.StringData = nil
			secret.ResourceVersion = fmt.Sprint(writes.Add(1))
			secrets[secret.Name] = secret.DeepCopy()
			assert.NoError(t, json.NewEncoder(w).Encode(&secret))
		default:
			t.Errorf("unexpected API method: %s", r.Method)
			http.Error(w, "unexpected API method", http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(server.Close)
	client, err := kubernetes.NewForConfig(&rest.Config{Host: server.URL, QPS: 100, Burst: 100})
	require.NoError(t, err)
	return client, &writes
}

func TestPolicyReconcile_EmptyMITMSecretValue(t *testing.T) {
	for _, clusterScope := range []bool{false, true} {
		for _, update := range []bool{false, true} {
			t.Run(fmt.Sprintf("cluster=%t/update=%t", clusterScope, update), func(t *testing.T) {
				ctx := context.Background()
				const namespace = "workload"
				client, writes := newMITMSecretTestClient(t, namespace)
				credential, err := client.CoreV1().Secrets(namespace).Create(ctx, &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "credentials", Namespace: namespace},
					Data:       map[string][]byte{"token": []byte("Bearer original-test-token")},
				}, metav1.CreateOptions{})
				require.NoError(t, err)
				spec := varmor.VarmorPolicySpec{
					Target: varmor.Target{Kind: "Deployment", Name: "demo"},
					Policy: varmor.Policy{
						Enforcer: "NetworkProxy", Mode: varmor.EnhanceProtectMode,
						EnhanceProtect: &varmor.EnhanceProtect{NetworkProxyRawRules: &varmor.NetworkProxyRules{Egress: &varmor.NetworkProxyEgress{DefaultAction: "allow"}}},
						NetworkProxyConfig: &varmor.NetworkProxyConfig{MITM: &varmor.MITMConfig{
							Domains: []string{"api.example.test"},
							HeaderMutations: []varmor.HeaderMutation{{Domain: "api.example.test", Headers: []varmor.HeaderAction{
								{Name: "Authorization", SecretRef: &varmor.SecretKeyRef{Name: "credentials", Key: "token"}},
							}}},
						}},
					},
				}
				meta := metav1.ObjectMeta{Name: "empty-secret", Namespace: namespace, Generation: 1}
				vp := &varmor.VarmorPolicy{ObjectMeta: meta, Spec: spec}
				vcp := &varmor.VarmorClusterPolicy{ObjectMeta: meta, Spec: *spec.DeepCopy()}
				vcp.Namespace = ""
				var obj runtime.Object = vp
				profileNamespace := namespace
				if clusterScope {
					obj = vcp
					profileNamespace = varmorconfig.Namespace
				}
				profileName := varmorprofile.GenerateArmorProfileName(profileNamespace, meta.Name, clusterScope)
				var previous *corev1.Secret
				if update {
					require.NoError(t, networkproxy.CreateNetworkProxySecret(client, obj, namespace, clusterScope, logr.Discard()))
					previous, err = client.CoreV1().Secrets(namespace).Get(ctx, profileName, metav1.GetOptions{})
					require.NoError(t, err)
					require.Contains(t, string(previous.Data[networkproxy.SecretKeyLDS]), "Bearer original-test-token")
					// The rejected candidate also changes RBAC; all old profile
					// data, including TLS material, must remain intact.
					vp.Spec.Policy.EnhanceProtect.NetworkProxyRawRules.Egress.DefaultAction = "deny"
					vcp.Spec.Policy.EnhanceProtect.NetworkProxyRawRules.Egress.DefaultAction = "deny"
					vp.Status = varmor.VarmorPolicyStatus{Ready: true, Phase: varmor.VarmorPolicyProtecting}
					vcp.Status = vp.Status
				}
				credential.Data["token"] = []byte{}
				_, err = client.CoreV1().Secrets(namespace).Update(ctx, credential, metav1.UpdateOptions{})
				require.NoError(t, err)
				beforeWrites := writes.Load()
				policies := varmorfake.NewSimpleClientset(obj)
				oldAP := &varmor.ArmorProfile{Spec: varmor.ArmorProfileSpec{Target: spec.Target, Profile: varmor.Profile{Enforcer: "NetworkProxy"}}}
				var status varmor.VarmorPolicyStatus
				if clusterScope {
					controller := ClusterPolicyController{kubeClient: client, varmorInterface: policies.CrdV1beta1(), log: logr.Discard()}
					if update {
						err = controller.handleUpdateVarmorClusterPolicy(vcp, oldAP)
					} else {
						err = controller.handleAddVarmorClusterPolicy(vcp, profileName)
					}
					require.NoError(t, err, "the existing handler returns the result of writing Error status")
					saved, getErr := policies.CrdV1beta1().VarmorClusterPolicies().Get(ctx, vcp.Name, metav1.GetOptions{})
					require.NoError(t, getErr)
					status = saved.Status
				} else {
					controller := PolicyController{kubeClient: client, varmorInterface: policies.CrdV1beta1(), log: logr.Discard()}
					if update {
						err = controller.handleUpdateVarmorPolicy(vp, oldAP)
					} else {
						err = controller.handleAddVarmorPolicy(vp, profileName)
					}
					require.NoError(t, err, "the existing handler returns the result of writing Error status")
					saved, getErr := policies.CrdV1beta1().VarmorPolicies(namespace).Get(ctx, vp.Name, metav1.GetOptions{})
					require.NoError(t, getErr)
					status = saved.Status
				}
				assert.Equal(t, varmor.VarmorPolicyError, status.Phase)
				assert.False(t, status.Ready)
				conditionType := varmor.VarmorPolicyCreated
				if update {
					conditionType = varmor.VarmorPolicyUpdated
				}
				require.Len(t, status.Conditions, 1)
				assert.Equal(t, conditionType, status.Conditions[0].Type)
				assert.Equal(t, corev1.ConditionFalse, status.Conditions[0].Status)
				assert.Equal(t, "Error", status.Conditions[0].Reason)
				assert.Contains(t, status.Conditions[0].Message, `secret workload/credentials key "token" must not be empty`)
				assert.NotContains(t, status.Conditions[0].Message, "original-test-token")
				assert.Equal(t, beforeWrites, writes.Load(), "no generated Secret may be written on resolution failure")
				saved, err := client.CoreV1().Secrets(namespace).Get(ctx, profileName, metav1.GetOptions{})
				if update {
					require.NoError(t, err)
					assert.Equal(t, previous, saved, "retain the complete last valid Secret")
				} else {
					assert.True(t, apierrors.IsNotFound(err), "invalid create must not publish a profile")
				}
				// A later reconcile can publish a valid nonempty value again.
				credential.Data["token"] = []byte("Bearer recovered-test-token")
				_, err = client.CoreV1().Secrets(namespace).Update(ctx, credential, metav1.UpdateOptions{})
				require.NoError(t, err)
				require.NoError(t, networkproxy.UpdateNetworkProxySecret(client, obj, namespace, clusterScope, logr.Discard()))
				recovered, err := client.CoreV1().Secrets(namespace).Get(ctx, profileName, metav1.GetOptions{})
				require.NoError(t, err)
				assert.Contains(t, string(recovered.Data[networkproxy.SecretKeyLDS]), "Bearer recovered-test-token")
				if update {
					assert.Equal(t, previous.Data[networkproxy.SecretKeyMITMCACert], recovered.Data[networkproxy.SecretKeyMITMCACert])
					assert.Equal(t, previous.Data[networkproxy.SecretKeyMITMCAKey], recovered.Data[networkproxy.SecretKeyMITMCAKey])
				}
			})
		}
	}
}
