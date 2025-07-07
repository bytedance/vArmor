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

	varmorapm "github.com/bytedance/vArmor/internal/apm"
	varmorinterface "github.com/bytedance/vArmor/pkg/client/clientset/versioned/typed/varmor/v1beta1"
)

// ExportArmorProfileModelHandler is the API interface which exports the armorprofilemodel object with all behavior data.
func ExportArmorProfileModelHandler(varmorInterface varmorinterface.CrdV1beta1Interface, logger logr.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger := logger.WithName("ExportArmorProfileModel()")

		logger.Info("Export ArmorProfileModel object", "namespace", c.Param("namespace"), "name", c.Param("name"))
		apm, err := varmorapm.RetrieveArmorProfileModel(varmorInterface, c.Param("namespace"), c.Param("name"), false, logger)
		if err != nil {
			c.String(http.StatusInternalServerError, err.Error())
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		c.JSON(http.StatusOK, apm)
	}
}
