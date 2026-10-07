//go:build integration

package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oszuidwest/zwfm-babbel/internal/audio"
	"github.com/oszuidwest/zwfm-babbel/internal/auth"
	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"github.com/oszuidwest/zwfm-babbel/internal/repository"
	"github.com/oszuidwest/zwfm-babbel/internal/services"
	"github.com/oszuidwest/zwfm-babbel/internal/utils"
	"gorm.io/datatypes"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func TestAuditEventsPermissionsAndFilters(t *testing.T) {
	db := auditIntegrationDB(t)
	user := models.User{Username: fmt.Sprintf("audit-%d", time.Now().UnixNano()), FullName: "Audit Actor", Role: models.RoleViewer}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Delete(&user).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Millisecond)
	eventIDs := []string{}
	for _, entity := range []string{"story", "tts_settings", "pronunciation_rules"} {
		event := models.AuditEvent{
			OccurredAt: now, ActorType: "user", UserID: &user.ID, EntityType: entity, EntityID: 1,
			Action: "update", Changes: datatypes.JSON(`{"title":{"old":"old","new":"new"}}`),
		}
		if err := db.Create(&event).Error; err != nil {
			t.Fatal(err)
		}
		eventIDs = append(eventIDs, fmt.Sprint(event.ID))
	}
	system := models.AuditEvent{OccurredAt: now, ActorType: "system", EntityType: "story", EntityID: 1,
		Action: "expire", Changes: datatypes.JSON(`{"status":{"old":"active","new":"expired"}}`)}
	if err := db.Create(&system).Error; err != nil {
		t.Fatal(err)
	}
	// Scope fixtures by ID, so historical audit rows from other tests cannot affect totals.
	eventIDs = append(eventIDs, fmt.Sprint(system.ID))
	base := "/audit-events?filter[id][in]=" + strings.Join(eventIDs, ",")
	tests := []struct {
		name                            string
		permissions                     auth.PermissionSet
		query                           string
		wantStatus, wantTotal, wantRows int
	}{
		{name: "story only", permissions: auth.PermissionSet{"stories": {"read"}}, wantStatus: 200, wantTotal: 2, wantRows: 2},
		{name: "settings only", permissions: auth.PermissionSet{"settings:tts": {"read"}}, wantStatus: 200, wantTotal: 1, wantRows: 1},
		{name: "pronunciations only", permissions: auth.PermissionSet{"pronunciation_rules": {"read"}}, wantStatus: 200, wantTotal: 1, wantRows: 1},
		{name: "write does not grant read", permissions: auth.PermissionSet{"stories": {"write"}}, wantStatus: 403},
		{name: "empty permissions", wantStatus: 403},
		{name: "filter cannot expose settings", permissions: auth.PermissionSet{"stories": {"read"}}, query: "&filter[entity_type]=tts_settings", wantStatus: 200},
		{name: "in filter cannot expose settings", permissions: auth.PermissionSet{"stories": {"read"}}, query: "&filter[entity_type][in]=story,tts_settings", wantStatus: 200, wantTotal: 2, wantRows: 2},
		{name: "actor and action filters", permissions: auth.PermissionSet{"stories": {"read"}}, query: fmt.Sprintf("&filter[user_id]=%d&filter[action]=update&filter[entity_id]=1", user.ID), wantStatus: 200, wantTotal: 1, wantRows: 1},
		{name: "system filter", permissions: auth.PermissionSet{"stories": {"read"}}, query: "&filter[user_id][null]=true", wantStatus: 200, wantTotal: 1, wantRows: 1},
		{name: "pagination", permissions: auth.PermissionSet{"stories": {"read"}}, query: "&limit=1&offset=1", wantStatus: 200, wantTotal: 2, wantRows: 1},
		{name: "date range", permissions: auth.PermissionSet{"stories": {"read"}}, query: "&filter[occurred_at][gte]=2000-01-01&filter[occurred_at][lt]=2001-01-01", wantStatus: 200},
		{name: "unknown filter", permissions: auth.PermissionSet{"stories": {"read"}}, query: "&filter[secret]=x", wantStatus: 422},
		{name: "unknown sort", permissions: auth.PermissionSet{"stories": {"read"}}, query: "&sort=secret", wantStatus: 422},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewAuditEventsHandler(repository.NewAuditEventRepository(db), func(role string) (auth.PermissionSet, error) {
				if role != "test-role" {
					t.Fatalf("permission subject = %q", role)
				}
				return tt.permissions, nil
			})
			router := auditTestRouter(user.ID)
			router.GET("/audit-events", handler.List)
			response := auditRequest(t, router, "GET", base+tt.query, "", tt.wantStatus)
			if tt.wantStatus != 200 {
				if response.Header().Get("Content-Type") != "application/problem+json" {
					t.Fatalf("expected problem details: %s", response.Body)
				}
				return
			}
			var result struct {
				Data  []models.AuditEvent
				Total int
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Total != tt.wantTotal || len(result.Data) != tt.wantRows {
				t.Fatalf("result = %s", response.Body)
			}
			for i, event := range result.Data {
				if i > 0 && event.ID > result.Data[i-1].ID {
					t.Fatalf("events are not newest first: %s", response.Body)
				}
				if event.UserID != nil && (event.Username == nil || *event.Username != user.Username || event.FullName == nil || *event.FullName != user.FullName) {
					t.Fatalf("deleted actor names missing: %+v", event)
				}
				if event.UserID == nil && (event.Username != nil || event.FullName != nil) {
					t.Fatalf("system actor names = %+v", event)
				}
			}
		})
	}
}

func TestStoryHandlersAuditActor(t *testing.T) {
	db := auditIntegrationDB(t)
	repo := repository.NewStoryRepository(db)
	service := services.NewStoryService(services.StoryServiceDeps{
		StoryRepo: repo, VoiceRepo: repository.NewVoiceRepository(db),
		PronunciationInjector: services.NewPronunciationInjector(repository.NewPronunciationRuleRepository(db)),
	})
	h := NewHandlers(HandlersDeps{StorySvc: service})
	router := auditTestRouter(307)
	router.POST("/stories", h.CreateStory)
	router.PUT("/stories/:id", h.UpdateStory)
	router.PATCH("/stories/:id", h.UpdateStoryStatus)
	router.DELETE("/stories/:id", h.DeleteStory)
	response := auditRequest(t, router, "POST", "/stories",
		`{"title":"Created","text":"Text","start_date":"2026-10-01","end_date":"2026-10-31"}`, 201)
	var created struct{ ID int64 }
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/stories/%d", created.ID)
	auditRequest(t, router, "PUT", path, `{"title":"Edited"}`, 200)
	auditRequest(t, router, "PATCH", path, `{"status":"active"}`, 200)
	auditRequest(t, router, "DELETE", path, "", 204)
	auditRequest(t, router, "PATCH", path, `{"deleted_at":""}`, 200)
	auditRequest(t, router, "PATCH", path, `{"deleted_at":"delete"}`, 204)
	var events []models.AuditEvent
	if err := db.Where("entity_type = ? AND entity_id = ?", "story", created.ID).Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	want := []string{"create", "update", "update", "delete", "restore", "delete"}
	if len(events) != len(want) {
		t.Fatalf("events = %+v", events)
	}
	for i, event := range events {
		if event.Action != want[i] || event.UserID == nil || *event.UserID != 307 || event.ActorType != "user" {
			t.Fatalf("event %d = %+v", i, event)
		}
	}
	// Audit reads remain available after the story has been deleted.
	list := NewAuditEventsHandler(repository.NewAuditEventRepository(db), func(string) (auth.PermissionSet, error) {
		return auth.PermissionSet{"stories": {"read"}}, nil
	})
	router.GET("/audit-events", list.List)
	response = auditRequest(t, router, "GET", fmt.Sprintf("/audit-events?filter[entity_type]=story&filter[entity_id]=%d&filter[action]=delete", created.ID), "", 200)
	if !strings.Contains(response.Body.String(), `"user_id":307`) {
		t.Fatalf("deletion attribution = %s", response.Body)
	}
}

func TestSettingsHandlersAudit(t *testing.T) {
	db := auditIntegrationDB(t)
	txManager := repository.NewTxManager(db)
	settings := services.NewTTSSettingsService(repository.NewTTSSettingsRepository(db), txManager)
	rules := services.NewPronunciationRulesService(repository.NewPronunciationRuleRepository(db), txManager)
	h := NewHandlers(HandlersDeps{TTSSettingsSvc: settings, PronunciationRulesSvc: rules, Config: &config.Config{}})
	router := auditTestRouter(307)
	router.PATCH("/settings/tts", h.UpdateTTSSettings)
	router.PUT("/settings/tts/pronunciations", h.UpdatePronunciationRules)
	// Establish controlled values while holding the singleton lock for this test.
	if err := db.Exec("UPDATE tts_settings SET stability = 0.8, seed = NULL WHERE id = 1").Error; err != nil {
		t.Fatal(err)
	}
	auditRequest(t, router, "PATCH", "/settings/tts", `{"stability":0.51,"seed":42}`, 200)
	auditRequest(t, router, "PATCH", "/settings/tts", `{"stability":0.51,"seed":42}`, 200)
	auditRequest(t, router, "PATCH", "/settings/tts", `{"seed":null}`, 200)
	events := settingsAuditEvents(t, db, "tts_settings")
	if len(events) != 2 {
		t.Fatalf("settings events = %+v", events)
	}
	assertHandlerAuditChange(t, events[0], "stability", 0.8, 0.51)
	assertHandlerAuditChange(t, events[0], "seed", nil, 42)
	assertHandlerAuditChange(t, events[1], "seed", 42, nil)

	if err := db.Exec("DELETE FROM pronunciation_rules").Error; err != nil {
		t.Fatal(err)
	}
	auditRequest(t, router, "PUT", "/settings/tts/pronunciations", `{"rules":[{"string_to_replace":"A","ipa":"one"},{"string_to_replace":"B","ipa":"two"}]}`, 200)
	auditRequest(t, router, "PUT", "/settings/tts/pronunciations", `{"rules":[{"string_to_replace":"B","ipa":"two"},{"string_to_replace":"A","ipa":"one"}]}`, 200)
	auditRequest(t, router, "PUT", "/settings/tts/pronunciations", `{"rules":[{"string_to_replace":"A","ipa":"changed","case_sensitive":false},{"string_to_replace":"C","ipa":"three"}]}`, 200)
	auditRequest(t, router, "PUT", "/settings/tts/pronunciations", `{"rules":[]}`, 200)
	auditRequest(t, router, "PUT", "/settings/tts/pronunciations", `{"rules":[]}`, 200)
	events = settingsAuditEvents(t, db, "pronunciation_rules")
	if len(events) != 3 {
		t.Fatalf("pronunciation events = %+v", events)
	}
	rule := func(ipa string, sensitive bool) map[string]any {
		return map[string]any{"ipa": ipa, "case_sensitive": sensitive, "word_boundaries": true}
	}
	assertHandlerAuditChange(t, events[0], "A", nil, rule("one", true))
	assertHandlerAuditChange(t, events[1], "A", rule("one", true), rule("changed", false))
	assertHandlerAuditChange(t, events[1], "B", rule("two", true), nil)
	assertHandlerAuditChange(t, events[1], "C", nil, rule("three", true))
	assertHandlerAuditChange(t, events[2], "A", rule("changed", false), nil)
}

func TestUploadStoryAudioAudit(t *testing.T) {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg not available")
	}
	ffprobe, err := exec.LookPath("ffprobe")
	if err != nil {
		t.Skip("ffprobe not available")
	}
	db := auditIntegrationDB(t)
	voices := []models.Voice{{Name: "Audit voice A"}, {Name: "Audit voice B"}}
	if err := db.Create(&voices).Error; err != nil {
		t.Fatal(err)
	}
	story := models.Story{Title: "Audio audit", Text: "Text", VoiceID: &voices[0].ID, StartDate: time.Now(), EndDate: time.Now()}
	if err := db.Create(&story).Error; err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input := filepath.Join(dir, "input.wav")
	// #nosec G204 - local FFmpeg and test-controlled arguments.
	if output, err := exec.CommandContext(t.Context(), ffmpeg, "-f", "lavfi", "-i", "sine=frequency=440:duration=1", "-y", input).CombinedOutput(); err != nil {
		t.Fatalf("generate audio: %v: %s", err, output)
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Audio: config.AudioConfig{FFmpegPath: ffmpeg, FFprobePath: ffprobe, ProcessedPath: dir}}
	service := services.NewStoryService(services.StoryServiceDeps{
		StoryRepo: repository.NewStoryRepository(db), VoiceRepo: repository.NewVoiceRepository(db),
		AudioSvc: audio.NewService(cfg, nil), Config: cfg,
		PronunciationInjector: services.NewPronunciationInjector(repository.NewPronunciationRuleRepository(db)),
	})
	h := NewHandlers(HandlersDeps{StorySvc: service})
	router := auditTestRouter(307)
	router.POST("/stories/:id/audio", h.UploadStoryAudio)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("audio", "input.wav")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(t.Context(), "POST", fmt.Sprintf("/stories/%d/audio?voice_id=%d", story.ID, voices[1].ID), &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != 201 {
		t.Fatalf("upload response = %d %s", response.Code, response.Body)
	}
	var event models.AuditEvent
	if err := db.Where("entity_type = ? AND entity_id = ?", "story", story.ID).First(&event).Error; err != nil {
		t.Fatal(err)
	}
	if event.Action != "audio" || event.UserID == nil || *event.UserID != 307 {
		t.Fatalf("audio event = %+v", event)
	}
	assertHandlerAuditChange(t, event, "voice_id", voices[0].ID, voices[1].ID)
}

func auditIntegrationDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := os.Getenv("BABBEL_TEST_DB_DSN")
	if dsn == "" {
		if os.Getenv("CI") == "true" {
			t.Fatal("BABBEL_TEST_DB_DSN is required in CI")
		}
		t.Skip("BABBEL_TEST_DB_DSN not set")
	}
	db, err := gorm.Open(gormmysql.Open(dsn), &gorm.Config{SkipDefaultTransaction: true})
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
	return tx
}

func auditTestRouter(actor int64) *gin.Engine {
	gin.SetMode(gin.TestMode)
	utils.InitializeValidators()
	router := gin.New()
	router.Use(func(c *gin.Context) { auth.SetUserContext(c, auth.UserContext{UserID: actor, Role: "test-role"}) })
	return router
}

func auditRequest(t *testing.T, router *gin.Engine, method, path, body string, status int) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != status {
		t.Fatalf("%s %s: %d %s, want %d", method, path, response.Code, response.Body, status)
	}
	return response
}

func settingsAuditEvents(t *testing.T, db *gorm.DB, entity string) []models.AuditEvent {
	t.Helper()
	var events []models.AuditEvent
	if err := db.Where("entity_type = ? AND user_id = ?", entity, 307).Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.EntityID != 1 || event.Action != "update" || event.ActorType != "user" {
			t.Fatalf("event = %+v", event)
		}
	}
	return events
}

func assertHandlerAuditChange(t *testing.T, event models.AuditEvent, field string, oldValue, newValue any) {
	t.Helper()
	var changes map[string]map[string]any
	if err := json.Unmarshal(event.Changes, &changes); err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(map[string]any{"old": oldValue, "new": newValue})
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(changes[field])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s = %s, want %s", field, got, want)
	}
}

func TestSettingsAuditFailureRollsBack(t *testing.T) {
	db := auditIntegrationDB(t)
	settingsRepo := repository.NewTTSSettingsRepository(db)
	service := services.NewTTSSettingsService(settingsRepo, repository.NewTxManager(db))
	before, err := settingsRepo.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("audit unavailable")
	if err := db.Callback().Create().Before("gorm:create").Register("test:reject_audit", func(tx *gorm.DB) {
		if tx.Statement.Table == "audit_events" {
			_ = tx.AddError(sentinel)
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Callback().Create().Remove("test:reject_audit"); err != nil {
			t.Error(err)
		}
	})
	_, err = service.Update(t.Context(), &services.UpdateTTSSettingsRequest{TTSStylePrefix: new("audit rollback")})
	if !errors.Is(err, sentinel) {
		t.Fatalf("update = %v", err)
	}
	after, err := settingsRepo.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if before.TTSStylePrefix != after.TTSStylePrefix {
		t.Fatal("settings write survived audit failure")
	}
	ruleService := services.NewPronunciationRulesService(repository.NewPronunciationRuleRepository(db), repository.NewTxManager(db))
	beforeRules, err := ruleService.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, err = ruleService.Update(t.Context(), &services.UpdatePronunciationRulesRequest{Rules: []services.PronunciationRuleUpdate{{StringToReplace: "Rollback", IPA: "test"}}})
	if !errors.Is(err, sentinel) {
		t.Fatalf("rules update = %v", err)
	}
	afterRules, err := ruleService.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	beforeJSON, _ := json.Marshal(beforeRules)
	afterJSON, _ := json.Marshal(afterRules)
	if !bytes.Equal(beforeJSON, afterJSON) {
		t.Fatal("rules replacement survived audit failure")
	}
}
