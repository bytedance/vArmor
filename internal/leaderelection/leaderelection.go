// Copyright 2022-2023 vArmor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package leaderelection provides a Kubernetes leader election implementation
// for coordinating distributed components in the vArmor system.
//
// This package is modified from "github.com/kyverno/kyverno/pkg/leaderelection".
// The main enhancement is the support for dynamically selecting leaseDuration,
// renewDeadline, and retryPeriod based on the cluster size, which improves
// leader election performance and reliability in large-scale deployments.
package leaderelection

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/go-logr/logr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"

	varmorutils "github.com/bytedance/vArmor/internal/utils"
)

type Interface interface {
	// Run is a blocking call that runs a leader election
	Run(ctx context.Context)

	// ID returns this instances unique identifier
	ID() string

	// Name returns the name of the leader election
	Name() string

	// Namespace is the Kubernetes namespace used to coordinate the leader election
	Namespace() string

	// IsLeader indicates if this instance is the leader
	IsLeader() bool

	// GetLeader returns the leader ID
	GetLeader() string
}

type config struct {
	name              string
	namespace         string
	startWork         func(context.Context)
	stopWork          func()
	kubeClient        kubernetes.Interface
	lock              resourcelock.Interface
	leaderElectionCfg leaderelection.LeaderElectionConfig
	leaderElector     *leaderelection.LeaderElector
	isLeader          int64
	log               logr.Logger
}

func New(kubeClient *kubernetes.Clientset, name, namespace string, id string, startWork func(context.Context), stopWork func(), log logr.Logger) (Interface, error) {
	lock, err := resourcelock.New(
		resourcelock.LeasesResourceLock,
		namespace,
		name,
		kubeClient.CoreV1(),
		kubeClient.CoordinationV1(),
		resourcelock.ResourceLockConfig{
			Identity: id,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("error initializing resource lock: %s/%s: %w", namespace, name, err)
	}
	e := &config{
		name:       name,
		namespace:  namespace,
		kubeClient: kubeClient,
		lock:       lock,
		startWork:  startWork,
		stopWork:   stopWork,
		log:        log.WithValues("id", lock.Identity()),
	}

	leaseDuration, renewDeadline, retryPeriod, err := varmorutils.GenerateLeaseUpdatePeriod(kubeClient)
	if err != nil {
		log.Error(err, "varmorutils.GenerateLeaseUpdatePeriod()")
		return nil, err
	}

	e.leaderElectionCfg = leaderelection.LeaderElectionConfig{
		Lock:            e.lock,
		ReleaseOnCancel: false,
		LeaseDuration:   leaseDuration,
		RenewDeadline:   renewDeadline,
		RetryPeriod:     retryPeriod,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				atomic.StoreInt64(&e.isLeader, 1)
				e.log.Info("started leading")
				if e.startWork != nil {
					e.startWork(ctx)
				}
			},
			OnStoppedLeading: func() {
				atomic.StoreInt64(&e.isLeader, 0)
				e.log.Info("leadership lost, stopped leading")
				if e.stopWork != nil {
					e.stopWork()
				}
			},
			OnNewLeader: func(identity string) {
				if identity == e.lock.Identity() {
					e.log.Info("still leading")
				} else {
					e.log.Info("another instance has been elected as leader", "leader", identity)
				}
			},
		},
	}
	e.leaderElector, err = leaderelection.NewLeaderElector(e.leaderElectionCfg)
	if err != nil {
		e.log.Error(err, "failed to create leaderElector")
		return nil, err
	}
	if e.leaderElectionCfg.WatchDog != nil {
		e.leaderElectionCfg.WatchDog.SetLeaderElection(e.leaderElector)
	}
	return e, nil
}

func (e *config) Name() string {
	return e.name
}

func (e *config) Namespace() string {
	return e.namespace
}

func (e *config) ID() string {
	return e.lock.Identity()
}

func (e *config) IsLeader() bool {
	return atomic.LoadInt64(&e.isLeader) == 1
}

func (e *config) GetLeader() string {
	return e.leaderElector.GetLeader()
}

func (e *config) Run(ctx context.Context) {
	e.leaderElector.Run(ctx)
}
