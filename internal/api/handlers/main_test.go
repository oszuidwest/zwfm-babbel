package handlers

import (
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
)

// TestMain registers the request validators before any test binds a request,
// as router setup does in production.
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	utils.InitializeValidators()
	os.Exit(m.Run())
}
