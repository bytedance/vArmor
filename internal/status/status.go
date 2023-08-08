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
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"

	appsv1 "k8s.io/client-go/kubernetes/typed/apps/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"

	varmorconfig "github.com/bytedance/vArmor/internal/config"
	statusmanager "github.com/bytedance/vArmor/internal/status/api/v1"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
)

type StatusService struct {
	StatusManager *statusmanager.StatusManager
	srv           *http.Server
	router        *gin.Engine
	addr          string
	port          int
	debug         bool
	log           logr.Logger
}

func health(c *gin.Context) {
	c.JSON(http.StatusOK, "ok")
}

func NewStatusService(
	addr string,
	port int,
	debug bool,
	coreInterface corev1.CoreV1Interface,
	appsInterface appsv1.AppsV1Interface,
	varmorInterface varmorinterface.CrdV1beta1Interface,
	statusUpdateCycle time.Duration,
	log logr.Logger) (*StatusService, error) {

	if port > 65535 {
		return nil, fmt.Errorf("port is illegal")
	}

	if debug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	statusManager := statusmanager.NewStatusManager(coreInterface, appsInterface, varmorInterface, statusUpdateCycle, debug, log)

	s := StatusService{
		StatusManager: statusManager,
		router:        gin.Default(),
		addr:          addr,
		port:          port,
		debug:         debug,
		log:           log,
	}
	s.router.SetTrustedProxies(nil)

	s.router.POST(varmorconfig.StatusSyncPath, statusManager.Status)
	s.router.POST(varmorconfig.DataSyncPath, statusManager.Data)
	s.router.GET("/healthz", health)

	s.srv = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", s.addr, s.port),
		Handler: s.router,
	}
	return &s, nil
}

func (s *StatusService) Run(stopCh <-chan struct{}) {
	s.log.Info("starting", "addr", s.srv.Addr)

	go s.StatusManager.Run(stopCh)

	if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.log.Error(err, "s.srv.ListenAndServe() failed")
	}
}

func (s *StatusService) CleanUp() {
	s.log.Info("cleaning up")
	s.srv.Shutdown(context.Background())
	s.StatusManager.CleanUp()
}
