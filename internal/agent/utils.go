// Copyright 2021-2023 vArmor Authors
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

package agent

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	goversion "github.com/hashicorp/go-version"
	"k8s.io/apimachinery/pkg/version"
)

const (
	containerdDefaultProfile = `
## == Managed by vArmor == ##
## Attention:
##   This is a mock profile, only use to avoid cri-containerd.apparmor.d being removed by aa-remove-unknown unexpectedly.
##   This profile is not used to be loaded into the kernel.

abi <abi/3.0>,
#include <tunables/global>

profile cri-containerd.apparmor.d flags=(attach_disconnected,mediate_deleted) {
}
`

	minKernelVersionForAppArmorLSM = "4.15"
	minKernelVersionForBPFLSM      = "5.10"
	regexVersion                   = "^\\d+\\.?\\d*\\.?\\d*" // ^\d+\.?\d*\.?\d*
)

func isAppArmorEnabled() bool {
	content, err := os.ReadFile("/sys/module/apparmor/parameters/enabled")
	if err != nil {
		return false
	}
	if strings.Contains(string(content), "Y") {
		return true
	}
	return false
}

func isBpfLsmEnabled() bool {
	content, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	if strings.Contains(string(content), "bpf") {
		return true
	}
	return false
}

func versionGreaterThanOrEqual(current, minimum string) (bool, error) {
	regex, err := regexp.Compile(regexVersion)
	if err != nil {
		return false, err
	}
	current = regex.FindString(current)
	currentVersion, err := goversion.NewVersion(current)
	if err != nil {
		return false, err
	}
	minVersion, err := goversion.NewVersion(minimum)
	if err != nil {
		return false, err
	}

	if currentVersion.GreaterThanOrEqual(minVersion) {
		return true, nil
	}
	return false, fmt.Errorf("the current version (%s) < the minimum version (%s)", current, minimum)
}

func isLSMSupported(lsm string) (bool, error) {
	ret, err := exec.Command("uname", "-r").CombinedOutput()
	if err != nil {
		return false, err
	}

	switch lsm {
	case "AppArmor":
		if !isAppArmorEnabled() {
			return false, fmt.Errorf("the AppArmor LSM is not enabled")
		}
		return versionGreaterThanOrEqual(string(ret), minKernelVersionForAppArmorLSM)
	case "BPF":
		if !isBpfLsmEnabled() {
			return false, fmt.Errorf("the BPF LSM is not enabled")
		}
		return versionGreaterThanOrEqual(string(ret), minKernelVersionForBPFLSM)
	default:
		return false, fmt.Errorf("unsupported LSM")
	}
}

func isSeccompSupported(versionInfo *version.Info) (bool, error) {
	major, err := strconv.Atoi(versionInfo.Major)
	if err != nil {
		return false, err
	}

	minor, err := strconv.Atoi(strings.TrimRight(versionInfo.Minor, "+"))
	if err != nil {
		return false, err
	}

	if major <= 1 && minor < 19 {
		return false, fmt.Errorf("the current version of Kubernetes is v%d.%d", major, minor)
	}
	return true, nil
}

// retrieveNodeName retrieve nodeName from the varmor:agent pod's specification.
func retrieveNodeName(inContainer bool) (string, error) {
	if !inContainer {
		return os.Hostname()
	}

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		return "", fmt.Errorf("the NODE_NAME environment variable doesn't exist")
	}
	return nodeName, nil
}

// This profile is not used to be loaded into the kernel.
// It use to avoid cri-containerd.apparmor.d being removed by aa-remove-unknown unexpectedly.
func saveMockAppArmorProfile(fileName string, content string) error {
	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(content)
	return err
}
