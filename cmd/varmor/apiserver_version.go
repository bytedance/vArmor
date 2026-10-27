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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/rest"

	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
)

func updateAPIServerVersion(ctx context.Context, client rest.Interface, log logr.Logger) error {
	// DiscoveryClient.ServerVersion uses context.TODO(), which cannot be cancelled
	// during shutdown. Bound each request as well, so a stalled server can be retried.
	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	body, err := client.Get().AbsPath("/version").Do(requestCtx).Raw()
	if err != nil {
		return fmt.Errorf("get APIServer version: %w", err)
	}
	var serverVersion version.Info
	if err := json.Unmarshal(body, &serverVersion); err != nil {
		return fmt.Errorf("decode APIServer version: %w", err)
	}
	if serverVersion.GitVersion == "" {
		return fmt.Errorf("APIServer version is missing gitVersion")
	}
	// Validate Major and Minor before publishing the version used by capability
	// detection, even if GitVersion matches the previously cached value.
	appArmorGA, err := varmorutils.IsAppArmorGA(&serverVersion)
	if err != nil {
		return fmt.Errorf("validate APIServer version: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if varmorconfig.ServerVersion == nil || serverVersion.String() != varmorconfig.ServerVersion.String() {
		varmorconfig.ServerVersion = &serverVersion
		varmorconfig.AppArmorGA = appArmorGA
		log.Info("APIServer version updated", "version", serverVersion.String(), "AppArmorGA", appArmorGA)
	}
	return nil
}

func waitForAPIServerVersion(ctx context.Context, client rest.Interface, log logr.Logger) error {
	backoff := wait.Backoff{
		Duration: time.Second,
		Factor:   2,
		Jitter:   0.2,
		Steps:    6,
		Cap:      30 * time.Second,
	}
	return backoff.DelayFunc().Until(ctx, true, true, func(ctx context.Context) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if err := updateAPIServerVersion(ctx, client, log); err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			log.Error(err, "Waiting for a valid APIServer version before initializing agent")
			return false, nil
		}
		return true, nil
	})
}
