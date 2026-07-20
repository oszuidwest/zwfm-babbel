package notify

import (
	"context"
	"errors"
	"strings"
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

// flakyMailer fails the first failuresLeft deliveries and records successful
// ones in the wrapped recorder.
type flakyMailer struct {
	inner        *recordingMailer
	mu           sync.Mutex
	failuresLeft int
	attempts     int
}

func (m *flakyMailer) SendMail(ctx context.Context, recipients []string, subject, body string) error {
	m.mu.Lock()
	m.attempts++
	fail := m.failuresLeft > 0
	if fail {
		m.failuresLeft--
	}
	m.mu.Unlock()
	if fail {
		return errors.New("graph unavailable")
	}
	return m.inner.SendMail(ctx, recipients, subject, body)
}

func (m *flakyMailer) attemptCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.attempts
}

// gatedMailer blocks deliveries whose subject contains gateSubject until
// release is closed, so tests can hold an alert in flight. An empty
// gateSubject blocks every delivery.
type gatedMailer struct {
	inner       *recordingMailer
	started     chan struct{}
	release     chan struct{}
	gateSubject string
}

func (m *gatedMailer) SendMail(ctx context.Context, recipients []string, subject, body string) error {
	if strings.Contains(subject, m.gateSubject) {
		m.started <- struct{}{}
		<-m.release
	}
	return m.inner.SendMail(ctx, recipients, subject, body)
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

func TestServiceThresholdedAlertCooldownAndRecovery(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	svc, mailer := newTestService(&now)
	defer svc.Close()
	event := Event{Key: "tts:rate-limit", Summary: "TTS rate limited", Details: "quota", RequiresThreshold: true}

	svc.Alert(t.Context(), event)
	svc.Alert(t.Context(), event)
	if got := mailer.count(); got != 0 {
		t.Fatalf("messages before threshold = %d, want 0", got)
	}

	svc.Alert(t.Context(), event)
	mailer.waitForCount(t, 1)
	svc.Alert(t.Context(), event)
	svc.work.Wait()
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
	svc.work.Wait()
	if got := mailer.count(); got != 3 {
		t.Fatalf("messages after duplicate recovery = %d, want 3", got)
	}
}

func TestServiceResolveClearsFailuresBeforeThreshold(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	svc, mailer := newTestService(&now)
	defer svc.Close()
	event := Event{Key: "database:connection", Summary: "Database down", RequiresThreshold: true}

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
	active := Event{Key: "storage:output", Summary: "Storage unavailable"}

	svc.Alert(t.Context(), active)
	mailer.waitForCount(t, 1)

	// Trigger pruning well beyond the normal retention period with an unrelated,
	// below-threshold incident. Active state must survive until Resolve observes it.
	now = now.Add(3 * time.Hour)
	svc.Alert(t.Context(), Event{Key: "database:other", Summary: "Other failure", RequiresThreshold: true})
	svc.Resolve(t.Context(), active.Key, "Storage recovered", "output is available again")

	mailer.waitForCount(t, 2)
	if got := mailer.messages[1].subject; got != "[RESOLVED] Storage recovered - Babbel" {
		t.Fatalf("recovery subject = %q, want active-alert recovery", got)
	}
}

func TestServiceImmediateAlertsAreIsolatedByKey(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	svc, mailer := newTestService(&now)
	defer svc.Close()

	svc.Alert(t.Context(), Event{Key: "bulletin:no-stories:station:1", Summary: "No stories 1"})
	svc.Alert(t.Context(), Event{Key: "bulletin:no-stories:station:2", Summary: "No stories 2"})
	mailer.waitForCount(t, 2)
}

func TestServiceFailedDeliveryDoesNotStartCooldown(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	svc, recorder := newTestService(&now)
	defer svc.Close()
	flaky := &flakyMailer{inner: recorder, failuresLeft: 1}
	svc.mailer = flaky
	event := Event{Key: "storage:output", Summary: "Storage unavailable"}

	svc.Alert(t.Context(), event)
	svc.work.Wait()
	if got := recorder.count(); got != 0 {
		t.Fatalf("messages after failed delivery = %d, want 0", got)
	}

	// The failure must not have started a cooldown or marked the alert active:
	// the next occurrence retries immediately.
	svc.Alert(t.Context(), event)
	recorder.waitForCount(t, 1)
	if got := recorder.messages[0].subject; got != "[ALERT] Storage unavailable - Babbel" {
		t.Fatalf("retry subject = %q, want alert", got)
	}

	svc.work.Wait()
	svc.Resolve(t.Context(), event.Key, "Storage recovered", "")
	recorder.waitForCount(t, 2)
	if got := recorder.messages[1].subject; got != "[RESOLVED] Storage recovered - Babbel" {
		t.Fatalf("recovery subject = %q, want recovery", got)
	}
}

func TestServiceSkipsRecoveryForUndeliveredAlert(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	svc, recorder := newTestService(&now)
	defer svc.Close()
	flaky := &flakyMailer{inner: recorder, failuresLeft: 100}
	svc.mailer = flaky
	event := Event{Key: "storage:output", Summary: "Storage unavailable"}

	svc.Alert(t.Context(), event)
	svc.work.Wait()
	svc.Resolve(t.Context(), event.Key, "Storage recovered", "")
	svc.work.Wait()

	if got := recorder.count(); got != 0 {
		t.Fatalf("messages after undelivered alert = %d, want 0", got)
	}
	if got := flaky.attemptCount(); got != 1 {
		t.Fatalf("delivery attempts = %d, want 1 (no recovery attempt)", got)
	}
}

func TestServiceRecoveryIsDeliveredAfterInFlightAlert(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	svc, recorder := newTestService(&now)
	defer svc.Close()
	gate := &gatedMailer{inner: recorder, started: make(chan struct{}, 2), release: make(chan struct{})}
	svc.mailer = gate
	event := Event{Key: "database:connection", Summary: "Database down"}

	svc.Alert(t.Context(), event)
	select {
	case <-gate.started:
	case <-time.After(time.Second):
		t.Fatal("alert delivery never started")
	}

	// The recovery arrives while the alert e-mail is still in flight.
	svc.Resolve(t.Context(), event.Key, "Database recovered", "")
	if got := recorder.count(); got != 0 {
		t.Fatalf("messages while alert in flight = %d, want 0", got)
	}

	close(gate.release)
	recorder.waitForCount(t, 2)
	if got := recorder.messages[0].subject; got != "[ALERT] Database down - Babbel" {
		t.Fatalf("first message = %q, want alert before recovery", got)
	}
	if got := recorder.messages[1].subject; got != "[RESOLVED] Database recovered - Babbel" {
		t.Fatalf("second message = %q, want recovery after alert", got)
	}
}

func TestServiceFlappingAlertCancelsQueuedRecovery(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	svc, recorder := newTestService(&now)
	defer svc.Close()
	gate := &gatedMailer{inner: recorder, started: make(chan struct{}, 2), release: make(chan struct{})}
	svc.mailer = gate
	event := Event{Key: "database:connection", Summary: "Database down"}

	svc.Alert(t.Context(), event)
	select {
	case <-gate.started:
	case <-time.After(time.Second):
		t.Fatal("alert delivery never started")
	}

	// The condition flaps while the alert e-mail is still in flight: the
	// recovery must be cancelled by the alert that follows it.
	svc.Resolve(t.Context(), event.Key, "Database recovered", "")
	svc.Alert(t.Context(), event)

	close(gate.release)
	svc.work.Wait()
	if got := recorder.count(); got != 1 {
		t.Fatalf("messages after flap = %d, want 1 (no recovery)", got)
	}

	// The incident is still active, so a real recovery still notifies.
	svc.Resolve(t.Context(), event.Key, "Database recovered", "")
	recorder.waitForCount(t, 2)
	if got := recorder.messages[1].subject; got != "[RESOLVED] Database recovered - Babbel" {
		t.Fatalf("recovery subject = %q, want recovery", got)
	}
}

func TestServiceIndependentKeysDeliverConcurrently(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	svc, recorder := newTestService(&now)
	defer svc.Close()
	gate := &gatedMailer{
		inner: recorder, started: make(chan struct{}, 2), release: make(chan struct{}),
		gateSubject: "Database down",
	}
	svc.mailer = gate

	svc.Alert(t.Context(), Event{Key: "database:connection", Summary: "Database down"})
	select {
	case <-gate.started:
	case <-time.After(time.Second):
		t.Fatal("alert delivery never started")
	}

	// A different key must not wait behind the blocked delivery.
	svc.Alert(t.Context(), Event{Key: "storage:output", Summary: "Storage unavailable"})
	recorder.waitForCount(t, 1)
	if got := recorder.messages[0].subject; got != "[ALERT] Storage unavailable - Babbel" {
		t.Fatalf("first delivered message = %q, want unblocked key", got)
	}

	close(gate.release)
	recorder.waitForCount(t, 2)
}

func TestServiceStaleRecoveryNeverFollowsNewAlert(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	svc, recorder := newTestService(&now)
	defer svc.Close()
	event := Event{Key: "database:connection", Summary: "Database down"}

	// First incident: alert delivered and marked active.
	svc.Alert(t.Context(), event)
	recorder.waitForCount(t, 1)
	svc.work.Wait()

	// Hold the delivery chain so the enqueue order becomes observable, then
	// resolve and immediately re-alert (the /health vs background-check race).
	gate := &gatedMailer{inner: recorder, started: make(chan struct{}, 2), release: make(chan struct{})}
	svc.mailer = gate
	svc.Resolve(t.Context(), event.Key, "Database recovered", "")
	select {
	case <-gate.started:
	case <-time.After(time.Second):
		t.Fatal("recovery delivery never started")
	}
	svc.Alert(t.Context(), event)

	close(gate.release)
	svc.work.Wait()
	if got := recorder.count(); got != 3 {
		t.Fatalf("delivered messages = %d, want 3", got)
	}
	if got := recorder.messages[1].subject; got != "[RESOLVED] Database recovered - Babbel" {
		t.Fatalf("second message = %q, want recovery before new alert", got)
	}
	if got := recorder.messages[2].subject; got != "[ALERT] Database down - Babbel" {
		t.Fatalf("last message = %q, want new alert after stale recovery", got)
	}
}

func TestServiceDisabledWithoutGraphConfiguration(t *testing.T) {
	svc := New(&config.NotificationConfig{})
	if svc.IsConfigured() {
		t.Fatal("service unexpectedly configured")
	}
	svc.Alert(t.Context(), Event{Key: "x", Summary: "x"})
	svc.Close()
}
