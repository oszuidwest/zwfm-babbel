//go:build integration

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/oszuidwest/zwfm-babbel/internal/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

func TestStoryAuditLifecycle(t *testing.T) {
	db := openIntegrationDB(t)
	repo := NewStoryRepository(db)
	actor := int64(307)
	voiceA, voiceB := createIntegrationVoice(t, db), createIntegrationVoice(t, db)
	story, err := repo.Create(t.Context(), &StoryCreateData{
		ActorUserID: &actor, Title: "First &amp; title", Text: "First text", VoiceID: &voiceA,
		Status: "draft", StartDate: time.Now(), EndDate: time.Now(), Weekdays: models.WeekdaysAll,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteIntegrationStory(t, db, story.ID) })
	events := storyAuditEvents(t, db, story.ID)
	if len(events) != 1 || events[0].Action != "create" {
		t.Fatalf("create events = %+v", events)
	}
	assertAuditChange(t, events[0], "title", nil, "First &amp; title")

	title, text, status := "Second title", "Second text", "active"
	start, end := time.Now().AddDate(0, 0, -1), time.Now().AddDate(0, 0, 1)
	weekdays, breaking := models.WeekdayMonday, true
	metadata := datatypes.JSONMap{"source": "test", "count": 1}
	if err := repo.Update(t.Context(), story.ID, &StoryUpdate{
		ActorUserID: &actor, Title: &title, Text: &text, Status: &status,
		StartDate: &start, EndDate: &end, Weekdays: &weekdays, IsBreaking: &breaking, Metadata: &metadata,
	}); err != nil {
		t.Fatal(err)
	}
	events = storyAuditEvents(t, db, story.ID)
	if len(events) != 2 {
		t.Fatalf("update event count = %d", len(events))
	}
	assertAuditChange(t, events[1], "title", "First &amp; title", title)
	assertAuditChange(t, events[1], "text", "First text", text)
	assertAuditChange(t, events[1], "status", "draft", "active")
	assertAuditChange(t, events[1], "is_breaking", false, true)
	assertAuditChange(t, events[1], "weekdays", 127, 2)
	assertAuditChange(t, events[1], "metadata", nil, metadata)
	assertAuditChange(t, events[1], "start_date", story.StartDate.Format("2006-01-02"), start.Format("2006-01-02"))
	assertAuditChange(t, events[1], "end_date", story.EndDate.Format("2006-01-02"), end.Format("2006-01-02"))

	if err := repo.SoftDelete(t.Context(), story.ID, &actor); err != nil {
		t.Fatal(err)
	}
	events = storyAuditEvents(t, db, story.ID)
	if len(events) != 3 || events[2].Action != "delete" {
		t.Fatalf("delete events = %+v", events)
	}
	var deleted models.Story
	if err := db.Unscoped().First(&deleted, story.ID).Error; err != nil {
		t.Fatal(err)
	}
	assertAuditChange(t, events[2], "deleted_at", nil, deleted.DeletedAt.Time)
	if err := repo.Restore(t.Context(), story.ID, &actor); err != nil {
		t.Fatal(err)
	}
	events = storyAuditEvents(t, db, story.ID)
	if len(events) != 4 || events[3].Action != "restore" {
		t.Fatalf("restore events = %+v", events)
	}
	assertAuditChange(t, events[3], "deleted_at", deleted.DeletedAt.Time, nil)

	if err := repo.UpdateAudio(t.Context(), story.ID, StoryAudioUpdate{
		ActorUserID: &actor, VoiceID: voiceB, AudioFile: "new.wav", DurationSeconds: 1.236,
		ExpectedVoiceID: &voiceA,
	}); err != nil {
		t.Fatal(err)
	}
	events = storyAuditEvents(t, db, story.ID)
	if len(events) != 5 || events[4].Action != "audio" {
		t.Fatalf("audio events = %+v", events)
	}
	assertAuditChange(t, events[4], "voice_id", voiceA, voiceB)
	assertAuditChange(t, events[4], "audio_file", "", "new.wav")
	assertAuditChange(t, events[4], "duration_seconds", nil, 1.24)

	if err := repo.UpdateAudio(t.Context(), story.ID, StoryAudioUpdate{
		ActorUserID: &actor, IsTTS: true, VoiceID: voiceB, AudioFile: "tts.wav", DurationSeconds: 2,
		ExpectedVoiceID: &voiceB, ExpectedAudioFile: "new.wav",
	}); err != nil {
		t.Fatal(err)
	}
	events = storyAuditEvents(t, db, story.ID)
	if len(events) != 6 || events[5].Action != "tts" {
		t.Fatalf("TTS events = %+v", events)
	}
	for _, event := range events {
		if event.ActorType != "user" || event.UserID == nil || *event.UserID != actor || event.OccurredAt.IsZero() {
			t.Fatalf("actor/time = %+v", event)
		}
	}
}

func TestStoryAuditNoOpAndConflict(t *testing.T) {
	db := openIntegrationDB(t)
	repo := NewStoryRepository(db)
	voice := createIntegrationVoice(t, db)
	id := createIntegrationStory(t, db, &voice, "old.wav")
	// Backdate updated_at so the identical title still changes the row (#303)
	// and the write commits; unchanged values must not add history.
	if err := db.Model(&models.Story{}).Where("id = ?", id).UpdateColumn("updated_at", time.Now().Add(-time.Hour)).Error; err != nil {
		t.Fatal(err)
	}
	title := "Integration story"
	if err := repo.Update(t.Context(), id, &StoryUpdate{Title: &title}); err != nil {
		t.Fatal(err)
	}
	err := repo.UpdateAudio(t.Context(), id, StoryAudioUpdate{
		VoiceID: voice, AudioFile: "stale.wav", ExpectedVoiceID: &voice, ExpectedAudioFile: "other.wav",
	})
	if !errors.Is(err, ErrStateConflict) {
		t.Fatalf("stale audio = %v", err)
	}
	if got := storyAuditEvents(t, db, id); len(got) != 0 {
		t.Fatalf("no-op/conflict events = %+v", got)
	}
}

func TestStoryAuditRollback(t *testing.T) {
	db := openIntegrationDB(t)
	repo := NewStoryRepository(db)
	id := createIntegrationStory(t, db, nil, "")
	sentinel := errors.New("rollback")
	err := NewTxManager(db).WithTransaction(t.Context(), func(ctx context.Context) error {
		if err := repo.SoftDelete(ctx, id, new(int64(307))); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("rollback error = %v", err)
	}
	if _, err := repo.GetByID(t.Context(), id); err != nil {
		t.Fatalf("rolled-back delete persisted: %v", err)
	}
	if got := storyAuditEvents(t, db, id); len(got) != 0 {
		t.Fatalf("rollback events = %+v", got)
	}

	rejectAuditWrites(t, db, sentinel)
	if err := repo.SoftDelete(t.Context(), id, nil); !errors.Is(err, sentinel) {
		t.Fatalf("audit failure = %v", err)
	}
	if _, err := repo.GetByID(t.Context(), id); err != nil {
		t.Fatalf("delete survived failed audit: %v", err)
	}
}

func TestAuditFailureRollsBackWrites(t *testing.T) {
	db := openIntegrationDB(t)
	stories := NewStoryRepository(db)
	rules := NewPronunciationRuleRepository(db)
	expiring := createIntegrationStory(t, db, nil, "")
	if err := db.Model(&models.Story{}).Where("id = ?", expiring).
		Updates(map[string]any{"status": "active", "end_date": time.Now().AddDate(0, 0, -2)}).Error; err != nil {
		t.Fatal(err)
	}
	rulesBefore, err := rules.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("audit unavailable")
	rejectAuditWrites(t, db, sentinel)

	title := fmt.Sprintf("Rolled back create %d", time.Now().UnixNano())
	if _, err := stories.Create(t.Context(), &StoryCreateData{
		Title: title, Text: "text", Status: "draft", StartDate: time.Now(), EndDate: time.Now(), Weekdays: models.WeekdaysAll,
	}); !errors.Is(err, sentinel) {
		t.Fatalf("create = %v", err)
	}
	var created int64
	if err := db.Unscoped().Model(&models.Story{}).Where("title = ?", title).Count(&created).Error; err != nil || created != 0 {
		t.Fatalf("create survived failed audit: count=%d err=%v", created, err)
	}

	if _, err := stories.ExpireStoriesPastEndDate(t.Context()); !errors.Is(err, sentinel) {
		t.Fatalf("expire = %v", err)
	}
	var status string
	if err := db.Table("stories").Where("id = ?", expiring).Pluck("status", &status).Error; err != nil || status != "active" {
		t.Fatalf("expiration survived failed audit: status=%q err=%v", status, err)
	}

	err = NewTxManager(db).WithTransaction(t.Context(), func(ctx context.Context) error {
		return rules.ReplaceAll(ctx, []models.PronunciationRule{{StringToReplace: title, IPA: "x"}}, nil)
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("replace rules = %v", err)
	}
	if rulesAfter, err := rules.List(t.Context()); err != nil || !reflect.DeepEqual(rulesAfter, rulesBefore) {
		t.Fatalf("rule replacement survived failed audit: %+v err=%v", rulesAfter, err)
	}
}

func TestMissingAuditTableHasItsOwnError(t *testing.T) {
	db := openIntegrationDB(t)
	missing := &mysql.MySQLError{Number: 1146, Message: "Table 'babbel.audit_events' doesn't exist"}
	rejectAuditWrites(t, db, missing)
	if err := db.Callback().Query().Before("gorm:query").Register("test:missing_audit_query", func(tx *gorm.DB) {
		if tx.Statement.Table == "audit_events" {
			_ = tx.AddError(missing)
		}
	}); err != nil {
		t.Fatal(err)
	}
	id := createIntegrationStory(t, db, nil, "")
	title := "Changed title"
	writeErr := NewStoryRepository(db).Update(t.Context(), id, &StoryUpdate{Title: &title})
	_, listErr := NewAuditEventRepository(db).List(t.Context(), NewListQuery(), []string{"story"}, false)
	for name, err := range map[string]error{"write": writeErr, "list": listErr} {
		// ErrSchemaUnavailable would make callers blame their own table.
		if !errors.Is(err, ErrAuditSchemaUnavailable) || errors.Is(err, ErrSchemaUnavailable) {
			t.Fatalf("%s error = %v, want only ErrAuditSchemaUnavailable", name, err)
		}
	}
}

func TestPronunciationRulesAudit(t *testing.T) {
	db := openIntegrationDB(t)
	repo := NewPronunciationRuleRepository(db)
	actor := int64(307)
	replace := func(ctx context.Context, rules ...models.PronunciationRule) {
		t.Helper()
		if err := NewTxManager(db).WithTransaction(ctx, func(ctx context.Context) error {
			return repo.ReplaceAll(ctx, rules, &actor)
		}); err != nil {
			t.Fatal(err)
		}
	}
	rule := func(term, ipa string) models.PronunciationRule {
		return models.PronunciationRule{StringToReplace: term, IPA: ipa, CaseSensitive: true}
	}
	value := func(ipa string) map[string]any {
		return map[string]any{"ipa": ipa, "case_sensitive": true, "word_boundaries": false}
	}
	original, err := repo.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lastEventID := func() int64 {
		var id int64
		if err := db.Model(&models.AuditEvent{}).Select("COALESCE(MAX(id), 0)").Scan(&id).Error; err != nil {
			t.Fatal(err)
		}
		return id
	}
	start := lastEventID()
	t.Cleanup(func() {
		// t.Context is already canceled when cleanup runs.
		replace(context.Background(), original...)
		if err := db.Where("entity_type = ? AND id > ?", "pronunciation_rules", start).Delete(&models.AuditEvent{}).Error; err != nil {
			t.Error(err)
		}
	})
	replace(t.Context(), rule("Alpha", "a"), rule("Bravo", "b"))
	baseline := lastEventID()
	events := func() []models.AuditEvent {
		var events []models.AuditEvent
		if err := db.Where("entity_type = ? AND id > ?", "pronunciation_rules", baseline).Order("id").Find(&events).Error; err != nil {
			t.Fatal(err)
		}
		return events
	}

	replace(t.Context(), rule("Bravo", "b2"), rule("Charlie", "c"))
	got := events()
	if len(got) != 1 || got[0].Action != "update" || got[0].EntityID != 1 || got[0].UserID == nil || *got[0].UserID != actor {
		t.Fatalf("events = %+v", got)
	}
	assertAuditChange(t, got[0], "Alpha", value("a"), nil)
	assertAuditChange(t, got[0], "Bravo", value("b"), value("b2"))
	assertAuditChange(t, got[0], "Charlie", nil, value("c"))

	replace(t.Context(), rule("Bravo", "b2"), rule("Charlie", "c"))
	if got := events(); len(got) != 1 {
		t.Fatalf("unchanged replacement added history: %+v", got)
	}

	if err := repo.ReplaceAll(t.Context(), nil, &actor); err == nil {
		t.Fatal("ReplaceAll without a transaction succeeded")
	}
	if rules, err := repo.List(t.Context()); err != nil || len(rules) != 2 {
		t.Fatalf("ReplaceAll without a transaction changed rules: %+v err=%v", rules, err)
	}
}

func rejectAuditWrites(t *testing.T, db *gorm.DB, err error) {
	t.Helper()
	if err := db.Callback().Create().Before("gorm:create").Register("test:reject_audit", func(tx *gorm.DB) {
		if tx.Statement.Table == "audit_events" {
			_ = tx.AddError(err)
		}
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStoryAuditConcurrentUpdates(t *testing.T) {
	db := openIntegrationDB(t)
	repo := NewStoryRepository(db)
	id := createIntegrationStory(t, db, nil, "")
	const writers = 5
	results := make(chan error, writers)
	for i := range writers {
		go func() {
			title := fmt.Sprintf("Concurrent title %d", i)
			results <- repo.Update(t.Context(), id, &StoryUpdate{Title: &title})
		}()
	}
	for range writers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	events := storyAuditEvents(t, db, id)
	if len(events) != writers {
		t.Fatalf("events = %d, want %d", len(events), writers)
	}
	previous := "Integration story"
	for _, event := range events {
		var changes map[string]struct {
			Old string
			New string
		}
		if err := json.Unmarshal(event.Changes, &changes); err != nil {
			t.Fatal(err)
		}
		if changes["title"].Old != previous {
			t.Fatalf("old value = %q, want %q", changes["title"].Old, previous)
		}
		previous = changes["title"].New
	}
}

func TestStoryAuditExpiration(t *testing.T) {
	db := openIntegrationDB(t)
	repo := NewStoryRepository(db)
	expiredIDs := []int64{}
	for range 2 {
		id := createIntegrationStory(t, db, nil, "")
		if err := db.Model(&models.Story{}).Where("id = ?", id).
			Updates(map[string]any{"status": "active", "end_date": time.Now().AddDate(0, 0, -2)}).Error; err != nil {
			t.Fatal(err)
		}
		expiredIDs = append(expiredIDs, id)
	}
	draft := createIntegrationStory(t, db, nil, "")
	deleted := createIntegrationStory(t, db, nil, "")
	if err := db.Model(&models.Story{}).Where("id = ?", deleted).
		Updates(map[string]any{"status": "active", "end_date": time.Now().AddDate(0, 0, -2), "deleted_at": time.Now()}).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ExpireStoriesPastEndDate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ExpireStoriesPastEndDate(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, id := range expiredIDs {
		events := storyAuditEvents(t, db, id)
		if len(events) != 1 || events[0].Action != "expire" || events[0].ActorType != "system" || events[0].UserID != nil {
			t.Fatalf("expiration events = %+v", events)
		}
		assertAuditChange(t, events[0], "status", "active", "expired")
	}
	for _, id := range []int64{draft, deleted} {
		if got := storyAuditEvents(t, db, id); len(got) != 0 {
			t.Fatalf("ineligible expiration events = %+v", got)
		}
	}
}

func storyAuditEvents(t *testing.T, db *gorm.DB, id int64) []models.AuditEvent {
	t.Helper()
	var events []models.AuditEvent
	if err := db.Where("entity_type = ? AND entity_id = ?", "story", id).Order("id").Find(&events).Error; err != nil {
		t.Fatal(err)
	}
	return events
}

func assertAuditChange(t *testing.T, event models.AuditEvent, field string, oldValue, newValue any) {
	t.Helper()
	var changes map[string]map[string]json.RawMessage
	if err := json.Unmarshal(event.Changes, &changes); err != nil {
		t.Fatal(err)
	}
	for side, want := range map[string]any{"old": oldValue, "new": newValue} {
		// Decode both sides because MySQL reformats JSON whitespace and key order.
		data, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		var got, wantJSON any
		if err := json.Unmarshal(changes[field][side], &got); err != nil {
			t.Fatalf("%s.%s: %v (%s)", field, side, err, event.Changes)
		}
		if err := json.Unmarshal(data, &wantJSON); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, wantJSON) {
			t.Fatalf("%s.%s = %s, want %s", field, side, changes[field][side], data)
		}
	}
}

func TestAuditActorNamesRequirePermission(t *testing.T) {
	db := openIntegrationDB(t)
	user := models.User{Username: fmt.Sprintf("audit-actor-%d", time.Now().UnixNano()), FullName: "Audit Actor", Role: models.RoleViewer}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Unscoped().Delete(&models.User{}, user.ID) })
	if err := db.Delete(&user).Error; err != nil {
		t.Fatal(err)
	}
	event := models.AuditEvent{
		ActorType: "user", UserID: &user.ID, EntityType: "story", EntityID: 1, Action: "update",
		Changes: datatypes.JSON(`{"title":{"old":"before","new":"after"}}`),
	}
	if err := db.Create(&event).Error; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Delete(&models.AuditEvent{}, event.ID) })
	query := NewListQuery()
	query.Filters = []FilterCondition{{Field: "id", Operator: FilterEquals, Value: event.ID}}
	for _, tt := range []struct {
		name         string
		includeNames bool
	}{
		{name: "users read allowed", includeNames: true},
		{name: "users read denied", includeNames: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NewAuditEventRepository(db).List(t.Context(), query, []string{"story"}, tt.includeNames)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Data) != 1 {
				t.Fatalf("events = %+v", result.Data)
			}
			got := result.Data[0]
			if got.UserID == nil || *got.UserID != user.ID {
				t.Fatalf("user_id = %v", got.UserID)
			}
			if !tt.includeNames {
				if got.Username != nil || got.FullName != nil {
					t.Fatalf("actor names disclosed: %+v", got)
				}
				return
			}
			if got.Username == nil || *got.Username != user.Username || got.FullName == nil || *got.FullName != user.FullName {
				t.Fatalf("soft-deleted actor names = %+v", got)
			}
		})
	}
}

func TestAuditEntityScopeCannotBeBroadenedByFilters(t *testing.T) {
	db := openIntegrationDB(t)
	events := []models.AuditEvent{
		{ActorType: "system", EntityType: "story", EntityID: 1, Action: "update"},
		{ActorType: "system", EntityType: "pronunciation_rules", EntityID: 1, Action: "update"},
	}
	if err := db.Create(&events).Error; err != nil {
		t.Fatal(err)
	}
	ids := []int64{events[0].ID, events[1].ID}
	t.Cleanup(func() { db.Delete(&models.AuditEvent{}, ids) })
	for _, tt := range []struct {
		name   string
		filter *FilterCondition
		want   int64
	}{
		{name: "unfiltered", want: 1},
		{name: "excluded entity", filter: &FilterCondition{Field: "entity_type", Operator: FilterEquals, Value: "pronunciation_rules"}},
		{name: "mixed IN filter", filter: &FilterCondition{Field: "entity_type", Operator: FilterIn, Value: []string{"story", "pronunciation_rules"}}, want: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			query := NewListQuery()
			query.Filters = []FilterCondition{{Field: "id", Operator: FilterIn, Value: ids}}
			if tt.filter != nil {
				query.Filters = append(query.Filters, *tt.filter)
			}
			result, err := NewAuditEventRepository(db).List(t.Context(), query, []string{"story"}, false)
			if err != nil {
				t.Fatal(err)
			}
			if result.Total != tt.want || int64(len(result.Data)) != tt.want {
				t.Fatalf("result = %+v", result)
			}
			for _, event := range result.Data {
				if event.EntityType != "story" {
					t.Fatalf("excluded entity disclosed: %+v", event)
				}
			}
		})
	}
}
