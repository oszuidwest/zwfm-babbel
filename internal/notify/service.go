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
type Kind int

const (
	KindImmediate Kind = iota + 1
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

type mailer interface {
	SendMail(context.Context, []string, string, string) error
}

type alertState struct {
	windowStarted time.Time
	count         int
	lastSent      time.Time
	lastSeen      time.Time
	isActive      bool
}

// Service applies occurrence thresholds and cooldowns before sending mail.
type Service struct {
	config     *config.NotificationConfig
	recipients []string
	mailer     mailer
	configured bool
	now        func() time.Time

	stateMu  sync.Mutex
	states   map[string]*alertState
	clientMu sync.Mutex

	workMu   sync.Mutex
	work     sync.WaitGroup
	isClosed bool
}

// New returns a notification service. Empty Graph settings disable delivery.
func New(cfg *config.NotificationConfig) *Service {
	s := &Service{
		config: cfg,
		now:    time.Now,
		states: make(map[string]*alertState),
	}
	if cfg == nil {
		return s
	}
	s.recipients = parseRecipients(cfg.Email.Recipients)
	s.configured = cfg.Email.TenantID != "" && cfg.Email.ClientID != "" &&
		cfg.Email.ClientSecret != "" && cfg.Email.FromAddress != "" && len(s.recipients) > 0
	return s
}

// IsConfigured reports whether all Microsoft Graph delivery settings exist.
func (s *Service) IsConfigured() bool { return s != nil && s.configured }

// Alert records an occurrence and sends only when its policy permits it.
func (s *Service) Alert(ctx context.Context, event Event) {
	if s == nil || !s.configured || event.Key == "" || event.Summary == "" {
		return
	}
	if event.Kind == 0 {
		event.Kind = KindImmediate
	}

	now := s.now()
	s.stateMu.Lock()
	s.pruneStates(now)
	state := s.states[event.Key]
	if state == nil {
		state = &alertState{windowStarted: now, lastSeen: now}
		s.states[event.Key] = state
	}
	state.lastSeen = now
	if now.Sub(state.windowStarted) > s.config.FailureWindow {
		state.windowStarted = now
		state.count = 0
	}
	state.count++
	threshold := 1
	if event.Kind == KindContinuous {
		threshold = s.config.FailureThreshold
	}
	shouldSend := state.count >= threshold &&
		(state.lastSent.IsZero() || now.Sub(state.lastSent) >= s.config.Cooldown)
	if shouldSend {
		state.lastSent = now
		state.isActive = true
	}
	count := state.count
	s.stateMu.Unlock()

	if shouldSend {
		subject, body := formatAlert(event, now, count)
		s.sendAsync(ctx, subject, body)
	}
}

// AlertSync sends a critical process-lifecycle event before the process exits.
func (s *Service) AlertSync(ctx context.Context, event Event) error {
	if s == nil || !s.configured {
		return nil
	}
	subject, body := formatAlert(event, s.now(), 1)
	return s.send(ctx, subject, body)
}

// Resolve sends one recovery message only when an alert was previously active.
func (s *Service) Resolve(ctx context.Context, key, summary, details string) {
	if s == nil || !s.configured || key == "" {
		return
	}

	s.stateMu.Lock()
	state := s.states[key]
	if state == nil {
		s.stateMu.Unlock()
		return
	}
	delete(s.states, key)
	wasActive := state.isActive
	s.stateMu.Unlock()
	if !wasActive {
		return
	}

	now := s.now()
	body := fmt.Sprintf("%s\n\nTimestamp: %s\nAlert key: %s", summary, now.Format(time.RFC3339), key)
	if details != "" {
		body += "\n\n" + details
	}
	s.sendAsync(ctx, "[OK] "+summary+" - Babbel", body)
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

func (s *Service) sendAsync(parent context.Context, subject, body string) {
	s.workMu.Lock()
	if s.isClosed {
		s.workMu.Unlock()
		logger.Warn("Notification e-mail dropped because service is closed", "subject", subject)
		return
	}
	s.work.Add(1)
	s.workMu.Unlock()

	go func() {
		defer s.work.Done()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), sendTimeout)
		defer cancel()
		if err := s.send(ctx, subject, body); err != nil {
			logger.Error("Failed to send notification e-mail", "error", err, "subject", subject)
			return
		}
		logger.Info("Notification e-mail sent", "subject", subject)
	}()
}

func (s *Service) pruneStates(now time.Time) {
	retention := max(s.config.Cooldown, s.config.FailureWindow) * 2
	for key, state := range s.states {
		if now.Sub(state.lastSeen) > retention {
			delete(s.states, key)
		}
	}
}

func (s *Service) send(ctx context.Context, subject, body string) error {
	s.clientMu.Lock()
	if s.mailer == nil {
		client, err := NewGraphClient(&s.config.Email)
		if err != nil {
			s.clientMu.Unlock()
			return fmt.Errorf("create graph mail client: %w", err)
		}
		s.mailer = client
	}
	client := s.mailer
	s.clientMu.Unlock()
	return client.SendMail(ctx, s.recipients, subject, body)
}

func formatAlert(event Event, timestamp time.Time, count int) (string, string) {
	var body strings.Builder
	fmt.Fprintf(&body, "%s\n\nTimestamp: %s\nAlert key: %s\nOccurrences in current window: %d",
		event.Summary, timestamp.Format(time.RFC3339), event.Key, count)
	if event.Details != "" {
		body.WriteString("\n\n")
		body.WriteString(event.Details)
	}
	return "[ERROR] " + event.Summary + " - Babbel", body.String()
}

var _ Alerter = (*Service)(nil)
