//go:build integration

package handlers

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func storyIntegrationSetup(t *testing.T) (*gorm.DB, *gin.Engine) {
	t.Helper()
	dsn := os.Getenv("BABBEL_TEST_DB_DSN")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("BABBEL_TEST_DB_DSN is required in CI")
		}
		t.Skip("BABBEL_TEST_DB_DSN not set")
	}
	db, err := gorm.Open(gormmysql.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sqlDB.Close(); err != nil {
			t.Error(err)
		}
	})
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	t.Cleanup(func() {
		if err := tx.Rollback().Error; err != nil {
			t.Error(err)
		}
	})
	h := &Handlers{
		storySvc: services.NewStoryService(services.StoryServiceDeps{
			StoryRepo:             repository.NewStoryRepository(tx),
			PronunciationInjector: services.NewPronunciationInjector(repository.NewPronunciationRuleRepository(tx)),
		}),
		ttsEnabled: true,
	}
	gin.SetMode(gin.TestMode)
	utils.InitializeValidators()
	router := gin.New()
	router.GET("/stories", h.ListStories)
	router.POST("/stories", h.CreateStory)
	router.GET("/stories/:id", h.GetStory)
	router.PUT("/stories/:id", h.UpdateStory)
	router.PATCH("/stories/:id", h.UpdateStoryStatus)
	router.DELETE("/stories/:id", h.DeleteStory)
	router.POST("/stories/:id/audio", h.UploadStoryAudio)
	router.POST("/stories/:id/tts", h.GenerateStoryTTS)
	return tx, router
}

func storyRequest(t *testing.T, router *gin.Engine, method, path, body string, status int) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != status {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, rec.Code, status, rec.Body.String())
	}
	return rec
}

func createIntegrationStory(t *testing.T, router *gin.Engine) int64 {
	t.Helper()
	rec := storyRequest(t, router, "POST", "/stories", `{"title":"Calendar story","text":"News","start_date":"2026-09-26","end_date":"2026-10-25"}`, 201)
	var result struct{ ID int64 }
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result.ID
}

func TestStoryWritesIntegration_DeletedAndMissing(t *testing.T) {
	db, router := storyIntegrationSetup(t)
	id := createIntegrationStory(t, router)
	path := fmt.Sprintf("/stories/%d", id)
	storyRequest(t, router, "DELETE", path, "", 204)
	var deleted models.Story
	if err := db.Unscoped().First(&deleted, id).Error; err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		method string
		suffix string
		body   string
	}{
		{name: "update", method: "PUT", body: `{"title":"Changed"}`},
		{name: "update start only", method: "PUT", body: `{"start_date":"2026-09-27"}`},
		{name: "update end only", method: "PUT", body: `{"end_date":"2026-10-26"}`},
		{name: "status", method: "PATCH", body: `{"status":"active"}`},
		{name: "audio", method: "POST", suffix: "/audio"},
		{name: "tts", method: "POST", suffix: "/tts"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, state := range []struct {
				name   string
				path   string
				status int
				code   string
			}{
				{name: "deleted", path: path, status: 410, code: "story.deleted"},
				{name: "missing", path: "/stories/9223372036854775807", status: 404, code: "story.not_found"},
			} {
				t.Run(state.name, func(t *testing.T) {
					rec := storyRequest(t, router, tt.method, state.path+tt.suffix, tt.body, state.status)
					var problem utils.ProblemDetail
					if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
						t.Fatal(err)
					}
					if rec.Header().Get("Content-Type") != "application/problem+json" || problem.Code != state.code || problem.Status != state.status {
						t.Fatalf("unexpected problem: %s", rec.Body.String())
					}
					if state.status == 410 {
						if problem.DeletedAt == nil || !problem.DeletedAt.Equal(deleted.DeletedAt.Time) {
							t.Fatalf("deleted_at = %v, want %v", problem.DeletedAt, deleted.DeletedAt.Time)
						}
					} else if problem.DeletedAt != nil {
						t.Fatal("missing story has deleted_at")
					}
				})
			}
		})
	}
	storyRequest(t, router, "GET", path, "", 404)
	storyRequest(t, router, "PATCH", path, `{"deleted_at":""}`, 200)
	storyRequest(t, router, "PUT", path, `{"title":"Restored"}`, 200)
	storyRequest(t, router, "PATCH", path, `{"status":"active"}`, 200)
}

func TestStoryDeleteIntegration_Idempotent(t *testing.T) {
	db, router := storyIntegrationSetup(t)
	for _, method := range []string{"DELETE", "PATCH"} {
		t.Run(method, func(t *testing.T) {
			id := createIntegrationStory(t, router)
			path := fmt.Sprintf("/stories/%d", id)
			body := ""
			if method == "PATCH" {
				body = `{"deleted_at":"2026-09-26T12:00:00Z"}`
			}
			storyRequest(t, router, method, path, body, 204)
			// Use an older timestamp so overwriting it would be observable within the same second.
			original := time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local)
			if err := db.Unscoped().Model(&models.Story{}).Where("id = ?", id).Update("deleted_at", original).Error; err != nil {
				t.Fatal(err)
			}
			rec := storyRequest(t, router, method, path, body, 204)
			if rec.Body.Len() != 0 {
				t.Fatalf("204 body = %q", rec.Body.String())
			}
			var story models.Story
			if err := db.Unscoped().First(&story, id).Error; err != nil {
				t.Fatal(err)
			}
			if !story.DeletedAt.Time.Equal(original) {
				t.Fatalf("repeated delete changed timestamp: %v", story.DeletedAt)
			}
			rec = storyRequest(t, router, method, "/stories/9223372036854775807", body, 404)
			if decodeProblem(t, rec).Code != "story.not_found" {
				t.Fatal("missing delete must return story.not_found")
			}
		})
	}
}

func TestStoryDatesIntegration_ResponsesAndFilters(t *testing.T) {
	_, router := storyIntegrationSetup(t)
	id := createIntegrationStory(t, router)
	path := fmt.Sprintf("/stories/%d", id)
	assertDates := func(data []byte, start, end string) {
		t.Helper()
		var story map[string]any
		if err := json.Unmarshal(data, &story); err != nil {
			t.Fatal(err)
		}
		if story["start_date"] != start || story["end_date"] != end {
			t.Fatalf("dates = %v/%v, want %s/%s", story["start_date"], story["end_date"], start, end)
		}
	}
	rec := storyRequest(t, router, "GET", path, "", 200)
	assertDates(rec.Body.Bytes(), "2026-09-26", "2026-10-25")
	rec = storyRequest(t, router, "PUT", path, `{"start_date":"2026-09-27"}`, 200)
	assertDates(rec.Body.Bytes(), "2026-09-27", "2026-10-25")
	rec = storyRequest(t, router, "PUT", path, `{"end_date":"2026-10-26"}`, 200)
	assertDates(rec.Body.Bytes(), "2026-09-27", "2026-10-26")
	storyRequest(t, router, "PUT", path, `{"start_date":"2026-10-27"}`, 400)
	storyRequest(t, router, "PUT", path, `{"end_date":"2026-09-26"}`, 400)
	rec = storyRequest(t, router, "PATCH", path, `{"status":"active"}`, 200)
	assertDates(rec.Body.Bytes(), "2026-09-27", "2026-10-26")
	for _, fields := range []string{"", "&fields=id,start_date,end_date"} {
		url := fmt.Sprintf("/stories?filter[id]=%d&filter[start_date]=2026-09-27&filter[end_date][gte]=2026-10-26%s", id, fields)
		rec = storyRequest(t, router, "GET", url, "", 200)
		var list struct{ Data []json.RawMessage }
		if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		if len(list.Data) != 1 {
			t.Fatalf("filtered stories = %s", rec.Body.String())
		}
		assertDates(list.Data[0], "2026-09-27", "2026-10-26")
	}
	storyRequest(t, router, "DELETE", path, "", 204)
	rec = storyRequest(t, router, "PATCH", path, `{"deleted_at":""}`, 200)
	assertDates(rec.Body.Bytes(), "2026-09-27", "2026-10-26")
}
