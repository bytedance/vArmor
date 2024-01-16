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
	"os"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

const BindTokenPath = "/var/run/secrets/tokens"

var (
	token      string
	mu         sync.RWMutex
	updateChan chan bool
)

func InitAndStartTokenRotation(interval time.Duration, logger logr.Logger) {
	updateToken(BindTokenPath, logger)
	updateChan = make(chan bool)
	go startTokenRotation(BindTokenPath, interval, logger, updateChan)
}

func startTokenRotation(filePath string, interval time.Duration, logger logr.Logger, update chan bool) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			updateToken(filePath, logger)
		case <-update:
			updateToken(filePath, logger)
		}
	}
}

func updateToken(filePath string, logger logr.Logger) {
	newToken, _ := os.ReadFile(filePath)

	mu.Lock()
	token = string(newToken)
	mu.Unlock()
}

func GetToken() string {
	mu.RLock()
	defer mu.RUnlock()
	return token
}
