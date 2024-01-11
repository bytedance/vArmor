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

package utils

import (
	"github.com/go-logr/logr"
	"os"
	"sync"
	"time"
)

const BindTokenPath = "/var/run/secrets/tokens"

var (
	token string
	mu    sync.RWMutex
)

func InitAndStartTokenRotation(interval time.Duration, logger logr.Logger) {
	updateToken(BindTokenPath, logger)
	go startTokenRotation(BindTokenPath, interval, logger)
}

func startTokenRotation(filePath string, interval time.Duration, logger logr.Logger) {
	for range time.Tick(interval) {
		updateToken(filePath, logger)
	}
}

func updateToken(filePath string, logger logr.Logger) {
	newToken, err := os.ReadFile(filePath)
	if err != nil {
		logger.Error(err, "update agent bind token error")
	}

	mu.Lock()
	token = string(newToken)
	mu.Unlock()
}

func GetToken() string {
	mu.RLock()
	defer mu.RUnlock()
	return token
}
