package notify

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

type recordedMessage struct {
	recipients []string
	subject    string
	body       string
}

type recordingMailer struct {
	mu       sync.Mutex
	messages []recordedMessage
	notify   chan struct{}
}

func newRecordingMailer() *recordingMailer {
	return &recordingMailer{notify: make(chan struct{}, 20)}
}

func (m *recordingMailer) SendMail(_ context.Context, recipients []string, subject, body string) error {
	m.mu.Lock()
	m.messages = append(m.messages, recordedMessage{
		recipients: append([]string(nil), recipients...),
		subject:    subject,
		body:       body,
	})
	m.mu.Unlock()
	m.notify <- struct{}{}
	return nil
}

func (m *recordingMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.messages)
}

func (m *recordingMailer) waitForCount(t *testing.T, expected int) {
	t.Helper()
	deadline := time.After(time.Second)
	for m.count() < expected {
		select {
		case <-m.notify:
		case <-deadline:
			t.Fatalf("message count = %d, want %d", m.count(), expected)
		}
	}
}

func newTestService(now *time.Time) (*Service, *recordingMailer) {
	cfg := &config.NotificationConfig{
		Email: config.GraphConfig{
			TenantID: "tenant", ClientID: "client", ClientSecret: "secret",
			FromAddress: "sender@example.com", Recipients: "one@example.com, two@example.com",
		},
		Cooldown:         time.Hour,
		FailureThreshold: 3,
		FailureWindow:    10 * time.Minute,
	}
	mailer := newRecordingMailer()
	svc := New(cfg)
	svc.mailer = mailer
	svc.now = func() time.Time { return *now }
	return svc, mailer
}

func TestServiceContinuousAlertThresholdCooldownAndRecovery(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	svc, mailer := newTestService(&now)
	defer svc.Close()
	event := Event{Key: "tts:rate-limit", Summary: "TTS rate limited", Details: "quota", Kind: KindContinuous}

	svc.Alert(t.Context(), event)
	svc.Alert(t.Context(), event)
	if got := mailer.count(); got != 0 {
		t.Fatalf("messages before threshold = %d, want 0", got)
	}

	svc.Alert(t.Context(), event)
	mailer.waitForCount(t, 1)
	svc.Alert(t.Context(), event)
	time.Sleep(10 * time.Millisecond)
	if got := mailer.count(); got != 1 {
		t.Fatalf("messages during cooldown = %d, want 1", got)
	}

	now = now.Add(time.Hour)
	svc.Alert(t.Context(), event)
	svc.Alert(t.Context(), event)
	svc.Alert(t.Context(), event)
	mailer.waitForCount(t, 2)

	svc.Resolve(t.Context(), event.Key, "TTS recovered", "requests succeed")
	mailer.waitForCount(t, 3)
	svc.Resolve(t.Context(), event.Key, "TTS recovered", "requests succeed")
	time.Sleep(10 * time.Millisecond)
	if got := mailer.count(); got != 3 {
		t.Fatalf("messages after duplicate recovery = %d, want 3", got)
	}
}

func TestServiceResolveClearsFailuresBeforeThreshold(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	svc, mailer := newTestService(&now)
	defer svc.Close()
	event := Event{Key: "database:connection", Summary: "Database down", Kind: KindContinuous}

	svc.Alert(t.Context(), event)
	svc.Alert(t.Context(), event)
	svc.Resolve(t.Context(), event.Key, "Database recovered", "")
	svc.Alert(t.Context(), event)
	svc.Alert(t.Context(), event)
	if got := mailer.count(); got != 0 {
		t.Fatalf("messages after successful reset = %d, want 0", got)
	}
	svc.Alert(t.Context(), event)
	mailer.waitForCount(t, 1)
}

func TestServicePreservesActiveAlertUntilRecovery(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	svc, mailer := newTestService(&now)
	defer svc.Close()
	active := Event{Key: "storage:output", Summary: "Storage unavailable", Kind: KindImmediate}

	svc.Alert(t.Context(), active)
	mailer.waitForCount(t, 1)

	// Trigger pruning well beyond the normal retention period with an unrelated,
	// below-threshold incident. Active state must survive until Resolve observes it.
	now = now.Add(3 * time.Hour)
	svc.Alert(t.Context(), Event{Key: "database:other", Summary: "Other failure", Kind: KindContinuous})
	svc.Resolve(t.Context(), active.Key, "Storage recovered", "output is available again")

	mailer.waitForCount(t, 2)
	if got := mailer.messages[1].subject; got != "[OK] Storage recovered - Babbel" {
		t.Fatalf("recovery subject = %q, want active-alert recovery", got)
	}
}

func TestServiceImmediateAlertsAreIsolatedByKey(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	svc, mailer := newTestService(&now)
	defer svc.Close()

	svc.Alert(t.Context(), Event{Key: "bulletin:no-stories:station:1", Summary: "No stories 1", Kind: KindImmediate})
	svc.Alert(t.Context(), Event{Key: "bulletin:no-stories:station:2", Summary: "No stories 2", Kind: KindImmediate})
	mailer.waitForCount(t, 2)
}

func TestServiceDisabledWithoutGraphConfiguration(t *testing.T) {
	svc := New(&config.NotificationConfig{})
	if svc.IsConfigured() {
		t.Fatal("service unexpectedly configured")
	}
	svc.Alert(t.Context(), Event{Key: "x", Summary: "x", Kind: KindImmediate})
	svc.Close()
}
