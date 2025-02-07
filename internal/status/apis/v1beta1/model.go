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
