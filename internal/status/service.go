// Copyright 2022 vArmor Authors
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

// Package status implements the service of manager
package status

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	authnclientv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	authzclientv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/util/retry"

	varmorconfig "github.com/bytedance/vArmor/internal/config"
	statusmanager "github.com/bytedance/vArmor/internal/status/apis/v1"
	modelmanager "github.com/bytedance/vArmor/internal/status/apis/v1beta1"
	varmortls "github.com/bytedance/vArmor/internal/tls"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
	"github.com/bytedance/vArmor/pkg/metrics"
)

const managerAudience = "varmor-manager"

type StatusService struct {
	StatusManager *statusmanager.StatusManager
	srv           *http.Server
	router        *gin.Engine
	addr          string
	port          int
	inContainer   bool
	log           logr.Logger
	tokenCache    *TokenCache
}

// CheckAgentToken verify the token of the client.
// Check if the requester is the varmor-agent.
func CheckAgentToken(authnInterface authnclientv1.AuthenticationV1Interface, inContainer bool, tokenCache *TokenCache) gin.HandlerFunc {
	if !inContainer {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		token := c.GetHeader("Token")
		if token == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if authenticated, found := tokenCache.Get(token); found {
			if authenticated {
				c.Next()
				return
			}
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		var result *authnv1.TokenReview
		defaultRetry := wait.Backoff{
			Steps:    3,
			Duration: 500 * time.Millisecond,
			Factor:   2.0,
			Jitter:   0.1,
		}
		err := retry.OnError(defaultRetry,
			func(err error) bool {
				return err != nil
			},
			func() (err error) {
				tr := &authnv1.TokenReview{
					Spec: authnv1.TokenReviewSpec{
						Token: token,
						Audiences: []string{
							managerAudience,
						},
					},
				}
				result, err = authnInterface.TokenReviews().Create(context.Background(), tr, metav1.CreateOptions{})
				return err
			})
		if err != nil {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		if !result.Status.Authenticated {
			tokenCache.Set(token, false)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		tokenCache.Set(token, true)

		c.Next()
	}
}

func getBearerToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header missing")
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return strings.TrimPrefix(authHeader, prefix), nil
}

// CheckClientBearerToken verify the Kubernetes bearer token of the client.
// Check if it has read access to the armorprofilemodels objects.
func CheckClientBearerToken(authnInterface authnclientv1.AuthenticationV1Interface, authzInterface authzclientv1.AuthorizationV1Interface, verb string, inContainer bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Authentication
		token, err := getBearerToken(c)
		if err != nil {
			c.String(http.StatusUnauthorized, "Unauthorized")
			c.AbortWithError(http.StatusUnauthorized, err)
			return
		}

		tr := &authnv1.TokenReview{
			Spec: authnv1.TokenReviewSpec{
				Token: token,
			},
		}
		trResult, err := authnInterface.TokenReviews().Create(context.Background(), tr, metav1.CreateOptions{})
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		if !trResult.Status.Authenticated {
			c.String(http.StatusUnauthorized, "Unauthorized")
			c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("authentication failed"))
			return
		}

		// Authorization
		sar := &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				ResourceAttributes: &authzv1.ResourceAttributes{
					Namespace: c.Param("namespace"),
					Verb:      verb,
					Group:     "crd.varmor.org",
					Resource:  "armorprofilemodels",
					Name:      c.Param("name"),
				},
				User:   trResult.Status.User.Username,
				Groups: trResult.Status.User.Groups,
			},
		}
		sarResult, err := authzInterface.SubjectAccessReviews().Create(context.Background(), sar, metav1.CreateOptions{})
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}

		if !sarResult.Status.Allowed {
			msg := fmt.Sprintf("Unauthorized. The user '%s' cannot %s resource 'armorprofilemodels' in API group 'crd.varmor.org' in the namespace '%s'.",
				trResult.Status.User.Username,
				verb,
				c.Param("namespace"))
			c.String(http.StatusUnauthorized, msg)
			c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("%s", msg))
			return
		}

		c.Next()
	}
}

func health(c *gin.Context) {
	c.String(http.StatusOK, "ok")
}

// NewStatusService creates and initializes a new StatusService instance.
// It sets up routes and an HTTP server with TLS configuration, returning the service pointer and an error if any issues occur.
func NewStatusService(
	addr string,
	port int,
	tlsPair *varmortls.PemPair,
	debug bool,
	inContainer bool,
	coreInterface corev1.CoreV1Interface,
	appsInterface appsv1.AppsV1Interface,
	varmorInterface varmorinterface.CrdV1beta1Interface,
	authnInterface authnclientv1.AuthenticationV1Interface,
	authzInterface authzclientv1.AuthorizationV1Interface,
	statusUpdateCycle time.Duration,
	metricsModule *metrics.MetricsModule,
	log logr.Logger) (*StatusService, error) {

	if port > 65535 {
		return nil, fmt.Errorf("port is illegal")
	}

	statusManager := statusmanager.NewStatusManager(coreInterface, appsInterface, varmorInterface, statusUpdateCycle, debug, inContainer, metricsModule, log)

	s := StatusService{
		StatusManager: statusManager,
		router:        gin.New(),
		addr:          addr,
		port:          port,
		inContainer:   inContainer,
		log:           log,
		tokenCache:    NewTokenCache(defaultTokenCacheTTL, log),
	}
	s.router.Use(gin.Recovery(), varmorutils.GinLogger())
	s.router.SetTrustedProxies(nil)

	s.router.GET("/healthz", health)
	s.router.POST(varmorconfig.StatusSyncPath, CheckAgentToken(authnInterface, inContainer, s.tokenCache), statusManager.Status)
	s.router.POST(varmorconfig.DataSyncPath, CheckAgentToken(authnInterface, inContainer, s.tokenCache), statusManager.Data)

	apiGroup := s.router.Group("/apis/crd.varmor.org/v1beta1")
	{
		apiGroup.GET(varmorconfig.ArmorProfileModelPath,
			CheckClientBearerToken(authnInterface, authzInterface, "get", inContainer),
			modelmanager.ExportArmorProfileModelHandler(varmorInterface, log))
		apiGroup.POST(varmorconfig.ArmorProfileModelPath,
			CheckClientBearerToken(authnInterface, authzInterface, "create", inContainer),
			modelmanager.ImportArmorProfileModelHandler(varmorInterface, log))
	}

	cert, err := tls.X509KeyPair(tlsPair.Certificate, tlsPair.PrivateKey)
	if err != nil {
		log.Error(err, "load key pair failed")
		os.Exit(1)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	s.srv = &http.Server{
		Addr:      fmt.Sprintf("%s:%d", s.addr, s.port),
		Handler:   s.router,
		TLSConfig: tlsConfig,
	}
	return &s, nil
}

func (s *StatusService) Run(stopCh <-chan struct{}) {
	s.log.Info("starting", "addr", s.srv.Addr)

	s.tokenCache.StartCleanup(stopCh)

	go s.StatusManager.Run(stopCh)

	if err := s.srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		s.log.Error(err, "s.srv.ListenAndServe() failed")
	}
}

func (s *StatusService) CleanUp() {
	s.log.Info("cleaning up")
	s.srv.Shutdown(context.Background())
	s.StatusManager.CleanUp()
}
