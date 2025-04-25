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

package apparmor

import (
	"bufio"
	"fmt"
	"html/template"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	lsmutils "github.com/bytedance/vArmor/pkg/lsm/utils"
)

type templateData struct {
	DiskDevices []string
}

func generateAppArmorProfile(templateContent string, templateData *templateData, f io.Writer) error {
	t, err := template.New("apparmor_profile").Parse(templateContent)
	if err != nil {
		return err
	}
	return t.Execute(f, templateData)
}

func retrieveTemplateData() (*templateData, error) {
	data := templateData{}

	// Retrieve the list of Node disk devices.
	devices, err := lsmutils.RetrieveDiskDeviceList()
	if err != nil {
		return nil, err
	}
	data.DiskDevices = append(data.DiskDevices, devices...)

	return &data, nil
}

func SaveAppArmorProfile(fileName string, content string) error {
	if !strings.Contains(content, "profile") {
		return fmt.Errorf("the apparmor profile is invalid")
	}

	f, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer f.Close()

	templateData, err := retrieveTemplateData()
	if err != nil {
		return err
	}

	return generateAppArmorProfile(content, templateData, f)
}

func aaParser(args ...string) (string, error) {
	out, err := exec.Command("apparmor_parser", args...).CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}

func LoadAppArmorProfile(path string, mode string) (string, error) {
	switch mode {
	case "enforce":
		return aaParser("-Ka", path)
	case "complain":
		return aaParser("-KaC", path)
	default:
		return "", fmt.Errorf("vArmor doesn't support '%s' mode", mode)
	}
}

func UpdateAppArmorProfile(path string, mode string) (string, error) {
	switch mode {
	case "enforce":
		return aaParser("-Kr", path)
	case "complain":
		return aaParser("-KrC", path)
	default:
		return "", fmt.Errorf("vArmor doesn't support '%s' mode", mode)
	}
}

func UnloadAppArmorProfile(profilePath string) (string, error) {
	_, err := os.Stat(profilePath)
	if err == nil {
		return aaParser("-R", profilePath)
	}
	return "", err
}

func RemoveAppArmorProfile(profilePath string) error {
	return os.Remove(profilePath)
}

func IsAppArmorProfileLoaded(name string) (bool, error) {
	f, err := os.Open("/sys/kernel/security/apparmor/profiles")
	if err != nil {
		return false, err
	}
	defer f.Close()
	r := bufio.NewReader(f)
	for {
		p, err := r.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return false, err
		}
		if strings.HasPrefix(p, name+" ") {
			return true, nil
		}
	}
	return false, nil
}

// RemoveUnknown remove the unknown AppArmor profiles from kernel.
//
// Node: It will only recognize profiles in /etc/apparmor.d, not even its subdirectories
func RemoveUnknown() (string, error) {
	out, err := exec.Command("aa-remove-unknown").CombinedOutput()
	if err != nil {
		return string(out), err
	}
	return string(out), nil
}

func UnloadAllAppArmorProfiles(profileDir string) {
	prefix := filepath.Join(profileDir, "varmor-")

	filepath.WalkDir(profileDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			if strings.HasPrefix(path, prefix) {
				UnloadAppArmorProfile(path)
			}
		}
		return nil
	})
}
