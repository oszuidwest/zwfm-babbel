package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
)

func TestRequirePermissionLogsEnforcementCause(t *testing.T) {
	policy, err := model.NewModelFromString(`[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = broken()
`)
	if err != nil {
		t.Fatal(err)
	}
	enforcer, err := casbin.NewEnforcer(policy)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("permission evaluator unavailable")
	enforcer.AddFunction("broken", func(...any) (any, error) { return nil, cause })
	logs := testutil.CaptureLogs(t, slog.LevelDebug)
	s := &Service{enforcer: enforcer}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/stories", nil)
	SetUserContext(c, UserContext{UserID: 7, Role: "viewer"})
	s.RequirePermission(ResourceStories, ActionRead)(c)
	var record map[string]any
	if c.Writer.Status() != http.StatusInternalServerError || !c.IsAborted() || json.Unmarshal(logs.Bytes(), &record) != nil ||
		record["level"] != "ERROR" || record["role"] != "viewer" || record["resource"] != "stories" || record["action"] != "read" || record["error"] != cause.Error() {
		t.Fatalf("status = %d, logs = %s", c.Writer.Status(), logs)
	}
}
