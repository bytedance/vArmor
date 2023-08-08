// Copyright 2023 vArmor Authors
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

package runtime

import (
	"context"
	"net"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// maxMsgSize use 16MB as the default message size limit.
// grpc library default is 4MB
const maxMsgSize = 1024 * 1024 * 16

// appContext return a context with cancel
func appContext(ctx context.Context, namespace string, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx = namespaces.WithNamespace(ctx, namespace)
	if timeout > 0 {
		return context.WithTimeout(ctx, timeout)
	}
	return context.WithCancel(ctx)
}

// getContextWithTimeout returns a context with timeout.
func getContextWithTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, timeout)
}

// newContainerdClient returns a new containerd client
func newContainerdClient(endpoint string, timeout time.Duration, opts ...containerd.ClientOpt) (*containerd.Client, error) {
	timeoutOpt := containerd.WithTimeout(timeout)
	opts = append(opts, timeoutOpt)
	client, err := containerd.New(endpoint, opts...)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func dial(ctx context.Context, addr string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", addr)
}

func getConnection(endpoint string, timeout time.Duration) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return grpc.DialContext(ctx, endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dial),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxMsgSize)),
	)
}

func newRuntimeServiceClient(endpoint string, timeout time.Duration) (runtimeapi.RuntimeServiceClient, *grpc.ClientConn, error) {
	conn, err := getConnection(endpoint, timeout)
	if err != nil {
		return nil, nil, errors.Wrap(err, "connect")
	}

	runtimeClient := runtimeapi.NewRuntimeServiceClient(conn)
	return runtimeClient, conn, nil
}
