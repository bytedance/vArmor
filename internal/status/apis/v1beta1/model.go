// Copyright 2024 vArmor Authors
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

// Package modelmanagerv1beta1 implements the v1beta1 version of the interface to access the ArmorProfileModel objects
package modelmanagerv1beta1

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"

	varmor "github.com/bytedance/vArmor/apis/varmor/v1beta1"
	varmorapm "github.com/bytedance/vArmor/internal/apm"
	statuscommon "github.com/bytedance/vArmor/internal/status/common"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
)

// ExportArmorProfileModelHandler is the API interface which exports the armorprofilemodel object with all behavior data.
func ExportArmorProfileModelHandler(varmorInterface varmorinterface.CrdV1beta1Interface, logger logr.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := logger.WithName("ExportArmorProfileModelHandler()")

		logger.Info("Export ArmorProfileModel object", "namespace", c.Param("namespace"), "name", c.Param("name"))
		apm, err := varmorapm.RetrieveArmorProfileModel(varmorInterface, c.Param("namespace"), c.Param("name"), false, logger)
		if err != nil {
			logger.Error(err, "varmorapm.RetrieveArmorProfileModel() failed")
			c.String(http.StatusInternalServerError, err.Error())
			return
		}

		c.JSON(http.StatusOK, apm)
	}
}

// ImportArmorProfileModelHandler is the API interface which imports the armorprofilemodel object.
func ImportArmorProfileModelHandler(varmorInterface varmorinterface.CrdV1beta1Interface, logger logr.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := logger.WithName("ImportArmorProfileModelHandler()")

		logger.Info("Import ArmorProfileModel object", "namespace", c.Param("namespace"), "name", c.Param("name"))

		var newApm varmor.ArmorProfileModel
		if err := c.ShouldBindJSON(&newApm); err != nil {
			logger.Error(err, "c.ShouldBindJSON() failed")
			c.String(http.StatusBadRequest, err.Error())
			return
		}

		// Retrieve or create the ArmorProfileModel object
		oldApm, err := varmorapm.RetrieveArmorProfileModel(varmorInterface, c.Param("namespace"), c.Param("name"), true, logger)
		if err != nil {
			logger.Error(err, "varmorapm.RetrieveArmorProfileModel() failed")
			c.String(http.StatusInternalServerError, err.Error())
			return
		}

		// Merge the behavior data
		statuscommon.MergeAppArmorResult(oldApm, newApm.Data.DynamicResult.AppArmor)
		statuscommon.MergeSeccompResult(oldApm, newApm.Data.DynamicResult.Seccomp)

		// Overwrite the profiles
		oldApm.Data.Profile.Name = c.Param("name")

		if newApm.Data.Profile.AppArmor != "" {
			oldApm.Data.Profile.AppArmor = newApm.Data.Profile.AppArmor
		}

		if newApm.Data.Profile.Seccomp != "" {
			oldApm.Data.Profile.Seccomp = newApm.Data.Profile.Seccomp
		}

		if newApm.Data.Profile.Bpf != nil {
			oldApm.Data.Profile.Bpf = newApm.Data.Profile.Bpf
		}

		// Persist the ArmorProfileModel object
		_, err = varmorapm.PersistArmorProfileModel(varmorInterface, oldApm, logger)
		if err != nil {
			logger.Error(err, "varmorapm.PersistArmorProfileModel() failed")
			c.String(http.StatusInternalServerError, err.Error())
			return
		}

		c.Status(http.StatusOK)
	}
}
