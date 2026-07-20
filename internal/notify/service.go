package notify

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
	"github.com/oszuidwest/zwfm-babbel/pkg/logger"
)

const sendTimeout = 2 * time.Minute

// Kind controls whether a single event alerts or must repeat within a window.
// The zero value is KindImmediate.
type Kind int

const (
	KindImmediate Kind = iota
	KindContinuous
)

// Event describes one operational condition. Key must be stable and include
// the affected resource when alerts should be isolated per resource.
type Event struct {
	Key     string
	Summary string
	Details string
	Kind    Kind
}

// Alerter is the shared operational-alert contract used by application layers.
type Alerter interface {
	Alert(context.Context, Event)
	Resolve(context.Context, string, string, string)
}

// Discard drops every event. Use it where notifications are intentionally absent.
var Discard Alerter = discardAlerter{}

// OrDiscard returns Discard when alerts is nil, so constructors can accept an
// optional alerter without repeating the nil guard.
func OrDiscard(alerts Alerter) Alerter {
	if alerts == nil {
		return Discard
	}
	return alerts
}

type discardAlerter struct{}

func (discardAlerter) Alert(context.Context, Event)                    {}
func (discardAlerter) Resolve(context.Context, string, string, string) {}

type mailer interface {
	SendMail(context.Context, []string, string, string) error
}

type alertState struct {
	windowStarted time.Time
	count         int
	lastSent      time.Time
	lastSeen      time.Time
	isActive      bool
	sendPending   bool
	queuedResolve *queuedResolve
}

// queuedResolve holds a recovery that arrived while the alert e-mail for the
// same key was still in flight. It is decided once that delivery completes:
// sent after a delivered alert, dropped after a failed one.
type queuedResolve struct {
	ctx     context.Context
	summary string
	details string
	at      time.Time
}

// Service applies occurrence thresholds and cooldowns before sending mail.
type Service struct {
	config     *config.NotificationConfig
	recipients []string
	mailer     mailer
	configured bool
	now        func() time.Time

	stateMu sync.Mutex
	states  map[string]*alertState

	workMu   sync.Mutex
	work     sync.WaitGroup
	chains   map[string]chan struct{}
	isClosed bool
}

// New returns a notification service. Empty Graph settings disable delivery.
func New(cfg *config.NotificationConfig) *Service {
	s := &Service{
		config: cfg,
		now:    time.Now,
		states: make(map[string]*alertState),
		chains: make(map[string]chan struct{}),
	}
	if cfg == nil {
		return s
	}
	s.recipients = cfg.Email.RecipientList()
	s.configured = cfg.Email.IsComplete()
	if s.configured {
		s.mailer = NewGraphClient(&cfg.Email)
	}
	return s
}

// IsConfigured reports whether all Microsoft Graph delivery settings exist.
func (s *Service) IsConfigured() bool { return s != nil && s.configured }

// Alert records an occurrence and sends only when its policy permits it.
func (s *Service) Alert(ctx context.Context, event Event) {
	if s == nil || !s.configured || event.Key == "" || event.Summary == "" {
		return
	}

	now := s.now()
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.pruneStates(now)
	state := s.states[event.Key]
	if state == nil {
		state = &alertState{windowStarted: now, lastSeen: now}
		s.states[event.Key] = state
	}
	state.lastSeen = now
	// A re-occurrence cancels a recovery still waiting on the in-flight alert
	// e-mail: the incident never actually cleared, so the [OK] must not go out.
	state.queuedResolve = nil
	if now.Sub(state.windowStarted) > s.config.FailureWindow {
		state.windowStarted = now
		state.count = 0
	}
	state.count++
	threshold := 1
	if event.Kind == KindContinuous {
		threshold = s.config.FailureThreshold
	}
	shouldSend := !state.sendPending && state.count >= threshold &&
		(state.lastSent.IsZero() || now.Sub(state.lastSent) >= s.config.Cooldown)
	if !shouldSend {
		return
	}

	// Enqueue while holding stateMu so the per-key delivery order always
	// matches the state-transition order.
	state.sendPending = true
	subject, body := formatMessage("[ERROR]", event, now, state.count)
	if !s.sendAsync(ctx, event.Key, subject, body, func(err error) { s.finishAlertSend(event.Key, now, err) }) {
		state.sendPending = false
	}
}

// finishAlertSend applies the delivery outcome for an alert key. Success marks
// the incident active and starts the cooldown; failure leaves the state
// untouched so the next occurrence retries immediately. A recovery queued
// while the alert was in flight is sent only when the alert was delivered.
func (s *Service) finishAlertSend(key string, sentAt time.Time, sendErr error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	state := s.states[key]
	if state == nil {
		return
	}
	state.sendPending = false
	if sendErr == nil {
		state.lastSent = sentAt
		state.isActive = true
	}
	resolve := state.queuedResolve
	state.queuedResolve = nil
	if resolve == nil {
		return
	}
	delete(s.states, key)
	if state.isActive {
		subject, body := formatMessage("[OK]", Event{Key: key, Summary: resolve.summary, Details: resolve.details}, resolve.at, 0)
		s.sendAsync(resolve.ctx, key, subject, body, nil)
	}
}

// AlertSync sends a critical process-lifecycle event before the process exits.
func (s *Service) AlertSync(ctx context.Context, event Event) error {
	if s == nil || !s.configured {
		return nil
	}
	subject, body := formatMessage("[ERROR]", event, s.now(), 1)
	return s.send(ctx, subject, body)
}

// Resolve sends one recovery message only when an alert was previously active.
func (s *Service) Resolve(ctx context.Context, key, summary, details string) {
	if s == nil || !s.configured || key == "" {
		return
	}

	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	state := s.states[key]
	if state == nil {
		return
	}
	if state.sendPending {
		state.queuedResolve = &queuedResolve{ctx: context.WithoutCancel(ctx), summary: summary, details: details, at: s.now()}
		return
	}
	delete(s.states, key)
	if !state.isActive {
		return
	}

	// Enqueue while holding stateMu: an Alert racing with this Resolve either
	// sees the state and is absorbed, or enqueues its alert after this recovery.
	subject, body := formatMessage("[OK]", Event{Key: key, Summary: summary, Details: details}, s.now(), 0)
	s.sendAsync(ctx, key, subject, body, nil)
}

// Close waits for in-flight alert e-mails and rejects new background sends.
func (s *Service) Close() {
	if s == nil {
		return
	}
	s.workMu.Lock()
	s.isClosed = true
	s.workMu.Unlock()
	s.work.Wait()
}

// sendAsync queues a bounded background delivery that survives request
// cancellation. Deliveries for the same alert key run in enqueue order, so an
// alert always leaves before the recovery or follow-up alert behind it;
// independent keys deliver concurrently. onDone, when set, receives the
// delivery outcome after the attempt completes. It reports whether the
// delivery was enqueued; a closed service drops it and the caller must undo
// any pending state itself. Callers may hold stateMu: enqueueing never blocks
// and onDone is never invoked synchronously.
func (s *Service) sendAsync(parent context.Context, key, subject, body string, onDone func(error)) bool {
	s.workMu.Lock()
	if s.isClosed {
		s.workMu.Unlock()
		logger.Warn("Notification e-mail dropped because service is closed", "subject", subject)
		return false
	}

	prev := s.chains[key]
	done := make(chan struct{})
	s.chains[key] = done
	s.work.Go(func() {
		defer func() {
			close(done)
			s.workMu.Lock()
			if s.chains[key] == done {
				delete(s.chains, key)
			}
			s.workMu.Unlock()
		}()
		if prev != nil {
			<-prev
		}
		ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), sendTimeout)
		defer cancel()
		err := s.send(ctx, subject, body)
		if err != nil {
			logger.Error("Failed to send notification e-mail", "error", err, "subject", subject)
		} else {
			logger.Info("Notification e-mail sent", "subject", subject)
		}
		if onDone != nil {
			onDone(err)
		}
	})
	s.workMu.Unlock()
	return true
}

// pruneStates removes stale inactive incidents while retaining active incidents
// until their corresponding recovery is observed and incidents with an
// in-flight delivery until their outcome is recorded.
func (s *Service) pruneStates(now time.Time) {
	retention := max(s.config.Cooldown, s.config.FailureWindow) * 2
	for key, state := range s.states {
		if !state.isActive && !state.sendPending && now.Sub(state.lastSeen) > retention {
			delete(s.states, key)
		}
	}
}

// send delegates a formatted message to the configured mail transport.
func (s *Service) send(ctx context.Context, subject, body string) error {
	return s.mailer.SendMail(ctx, s.recipients, subject, body)
}

// formatMessage renders the shared e-mail layout; count 0 omits the occurrence line.
func formatMessage(prefix string, event Event, timestamp time.Time, count int) (string, string) {
	var body strings.Builder
	fmt.Fprintf(&body, "%s\n\nTimestamp: %s\nAlert key: %s", event.Summary, timestamp.Format(time.RFC3339), event.Key)
	if count > 0 {
		fmt.Fprintf(&body, "\nOccurrences in current window: %d", count)
	}
	if event.Details != "" {
		body.WriteString("\n\n")
		body.WriteString(event.Details)
	}
	return prefix + " " + event.Summary + " - Babbel", body.String()
}

var _ Alerter = (*Service)(nil)
