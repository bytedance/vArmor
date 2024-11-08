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

package status

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	authclientv1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"

	varmorconfig "github.com/bytedance/vArmor/internal/config"
	statusmanager "github.com/bytedance/vArmor/internal/status/api/v1"
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
	debug         bool
	log           logr.Logger
}

func CheckAgentToken(authInterface authclientv1.AuthenticationV1Interface, debug bool) gin.HandlerFunc {
	if debug {
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
		tr := &authv1.TokenReview{
			Spec: authv1.TokenReviewSpec{
				Token: token,
				Audiences: []string{
					managerAudience,
				},
			},
		}
		result, err := authInterface.TokenReviews().Create(context.Background(), tr, metav1.CreateOptions{})
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if !result.Status.Authenticated {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}
func health(c *gin.Context) {
	c.JSON(http.StatusOK, "ok")
}

func NewStatusService(
	addr string,
	port int,
	tlsPair *varmortls.PemPair,
	debug bool,
	coreInterface corev1.CoreV1Interface,
	appsInterface appsv1.AppsV1Interface,
	varmorInterface varmorinterface.CrdV1beta1Interface,
	authInterface authclientv1.AuthenticationV1Interface,
	statusUpdateCycle time.Duration,
	metricsModule *metrics.MetricsModule,
	log logr.Logger) (*StatusService, error) {

	if port > 65535 {
		return nil, fmt.Errorf("port is illegal")
	}

	statusManager := statusmanager.NewStatusManager(coreInterface, appsInterface, varmorInterface, statusUpdateCycle, debug, metricsModule, log)

	s := StatusService{
		StatusManager: statusManager,
		router:        gin.New(),
		addr:          addr,
		port:          port,
		debug:         debug,
		log:           log,
	}
	s.router.Use(gin.Recovery(), varmorutils.GinLogger())
	s.router.SetTrustedProxies(nil)
	s.router.POST(varmorconfig.StatusSyncPath, CheckAgentToken(authInterface, debug), statusManager.Status)
	s.router.POST(varmorconfig.DataSyncPath, CheckAgentToken(authInterface, debug), statusManager.Data)
	s.router.GET("/healthz", health)

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
