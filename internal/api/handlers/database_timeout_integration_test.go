//go:build integration

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-sql-driver/mysql"
	"github.com/oszuidwest/zwfm-babbel/internal/apperrors"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/database"
	"github.com/oszuidwest/zwfm-babbel/internal/testutil"
	"gorm.io/gorm"
)

func openReadTimeoutDB(t *testing.T) *gorm.DB {
	t.Helper()
	parsed, err := mysql.ParseDSN(testutil.IntegrationDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(parsed.Addr)
	if err != nil {
		t.Fatal(err)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.NewGormDB(&config.Config{Database: config.DatabaseConfig{
		Host: host, Port: portNumber, User: parsed.User, Password: parsed.Passwd, Database: parsed.DBName,
		MaxOpenConns: 1, MaxIdleConns: 1, ConnMaxLifetime: time.Minute,
		ConnectTimeout: 5 * time.Second, ReadTimeout: 250 * time.Millisecond, WriteTimeout: time.Second,
	}})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

func TestDatabaseReadTimeoutIsLoggedAndAlerted(t *testing.T) {
	db := openReadTimeoutDB(t)
	logs := testutil.CaptureLogs(t, slog.LevelInfo)
	alerts := &automationAlertRecorder{}
	router := gin.New()
	router.Use(NotificationMiddleware(alerts))
	router.GET("/slow-query", func(c *gin.Context) {
		queryErr := db.WithContext(c.Request.Context()).Exec("DO SLEEP(2)").Error
		if queryErr == nil {
			t.Error("slow query succeeded despite read timeout")
			return
		}
		if !errors.Is(queryErr, mysql.ErrInvalidConn) {
			t.Errorf("query error = %v; want driver's transport failure, not a server SQL error", queryErr)
		}
		if c.Request.Context().Err() != nil {
			t.Errorf("request context ended before driver timeout: %v", c.Request.Context().Err())
		}
		handleServiceError(c, apperrors.Database("TimeoutProbe", "query", queryErr), "TimeoutProbe")
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodGet, "/slow-query", nil))
	var record map[string]any
	if rec.Code != http.StatusInternalServerError || json.Unmarshal(logs.Bytes(), &record) != nil || record["level"] != "ERROR" ||
		record["error_type"] != "database_error" || record["cause"] == nil {
		t.Fatalf("status = %d, logs = %s", rec.Code, logs)
	}
	if len(alerts.events) != 1 || alerts.events[0].Key != "database:request:GET /slow-query" || !alerts.events[0].RequiresThreshold ||
		!strings.Contains(alerts.events[0].Details, record["cause"].(string)) {
		t.Fatalf("alerts = %+v; want driver failure details", alerts.events)
	}
}
