package utils

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSingleQueryValue(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		query, value string
		valid        bool
	}{
		{"", "", true}, {"force=", "", true}, {"force=false", "false", true},
		{"force=true", "true", true}, {"other=x&force=1", "1", true},
		{"force=false&force=true", "", false}, {"force=&force=", "", false}, {"force=%ZZ", "", false},
	} {
		t.Run(tt.query, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x?"+tt.query, nil)
			value, ok := SingleQueryValue(c, "force")
			if ok != tt.valid || value != tt.value || !ok && rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("value = %q, ok = %v, status = %d", value, ok, rec.Code)
			}
			if !tt.valid && strings.Contains(tt.query, "&force=") && (!strings.Contains(rec.Body.String(), `"code":"duplicate"`) || !strings.Contains(rec.Body.String(), `"field":"force"`)) {
				t.Fatalf("duplicate response = %s", rec.Body)
			}
		})
	}
}
