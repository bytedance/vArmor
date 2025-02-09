// Copyright 2025 vArmor Authors
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

package apm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/go-logr/logr"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorconfig "github.com/bytedance/vArmor/internal/config"
	varmortypes "github.com/bytedance/vArmor/internal/types"
	varmorutils "github.com/bytedance/vArmor/internal/utils"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
)

func RetrieveArmorProfileModel(
	varmorInterface varmorinterface.CrdV1beta1Interface,
	namespace, name string,
	createNew bool,
	logger logr.Logger) (*varmor.ArmorProfileModel, error) {

	apm, err := varmorInterface.ArmorProfileModels(namespace).Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		if k8errors.IsNotFound(err) && createNew {
			// Create a new ArmorProfileModel object
			a := varmor.ArmorProfileModel{}
			a.Name = name
			a.Namespace = namespace
			a.StorageType = varmortypes.StorageTypeCRDInternal
			return varmorInterface.ArmorProfileModels(namespace).Create(context.Background(), &a, metav1.CreateOptions{})
		}
		return nil, err
	}

	// Load behavior data and profile of the ArmorProfileModel object from the local file
	if apm.StorageType != varmortypes.StorageTypeCRDInternal {
		if strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
			logger.Error(fmt.Errorf("invalid file name"), "Invalid file name: "+name)
			return apm, nil
		}

		fileName := path.Join(varmorconfig.BehaviorDataDirectory, name)
		data, err := os.ReadFile(fileName)
		if err != nil {
			logger.Error(err, "Read "+fileName+" failed")
			return apm, nil
		}

		a := varmor.ArmorProfileModel{}
		err = json.Unmarshal(data, &a)
		if err != nil {
			logger.Error(err, "Unmarshal "+fileName+" failed")
			return apm, nil
		}
		apm.Data = a.Data
	}

	return apm, nil
}

func UpdateArmorProfileModel(varmorInterface varmorinterface.CrdV1beta1Interface, apm *varmor.ArmorProfileModel) (*varmor.ArmorProfileModel, error) {
	var regain bool
	var err error

	update := func() (e error) {
		if regain {
			a, e := varmorInterface.ArmorProfileModels(apm.Namespace).Get(context.Background(), apm.Name, metav1.GetOptions{})
			if e != nil {
				if k8errors.IsNotFound(e) {
					err = e
					return nil
				}
				return e
			}
			apm.ResourceVersion = a.ResourceVersion
		}

		a, e := varmorInterface.ArmorProfileModels(apm.Namespace).Update(context.Background(), apm, metav1.UpdateOptions{})
		if e == nil {
			apm = a
		} else {
			if k8errors.IsRequestEntityTooLargeError(e) {
				err = e
				return nil
			}
		}
		return e
	}
	e := retry.RetryOnConflict(retry.DefaultRetry, update)
	if e == nil {
		return apm, err
	} else {
		return apm, e
	}
}

func PersistArmorProfileModel(varmorInterface varmorinterface.CrdV1beta1Interface, apm *varmor.ArmorProfileModel, logger logr.Logger) (*varmor.ArmorProfileModel, error) {
	if apm.StorageType == varmortypes.StorageTypeCRDInternal {
		apm, err := UpdateArmorProfileModel(varmorInterface, apm)
		if err == nil {
			return apm, nil
		}

		if !varmorutils.IsRequestSizeError(err) {
			return nil, err
		}
	}

	// Persist the object into the backend storage
	fileName := path.Join(varmorconfig.BehaviorDataDirectory, apm.Name)
	logger.Info("Persist the data into a local file because the data is too large to store into an ArmorProfileModel object",
		"namespace", apm.Namespace, "name", apm.Name, "path", fileName)
	jsonData, err := json.MarshalIndent(apm, "", "  ")
	if err == nil {
		err = os.WriteFile(fileName, jsonData, 0600)
		if err != nil {
			logger.Error(err, "unable persist the behavior data into the local file")
		}
	} else {
		logger.Error(err, "unable marshal the ArmorProfileModel object")
	}

	// Cache behavior data
	data := apm.Data

	// Update the ArmorProfileModel object without behavior data and profiles
	apm.Data = varmor.ArmorProfileModelData{}
	apm.StorageType = varmortypes.StorageTypeLocalDisk
	a, err := UpdateArmorProfileModel(varmorInterface, apm)

	// Recover behavior data and profiles
	a.Data = data
	return a, err
}
