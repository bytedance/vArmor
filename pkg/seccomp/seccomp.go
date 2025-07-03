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

// Package seccomp processes the seccomp profile
package seccomp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func isJSON(s string) bool {
	var js interface{}
	return json.Unmarshal([]byte(s), &js) == nil
}

func SaveSeccompProfile(fileName string, content string) error {
	if !isJSON(content) {
		return fmt.Errorf("the seccomp profile is invalid in JSON format")
	}

	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write([]byte(content))
	return err
}

func SeccompProfileExist(profilePath string) bool {
	_, err := os.Stat(profilePath)
	return !os.IsNotExist(err)
}

func RemoveSeccompProfile(profilePath string) error {
	return os.Remove(profilePath)
}

func RemoveAllSeccompProfiles(profileDir string) {
	prefix := filepath.Join(profileDir, "varmor-")

	filepath.WalkDir(profileDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			if strings.HasPrefix(path, prefix) {
				RemoveSeccompProfile(path)
			}
		}
		return nil
	})
}
