// Package notify sends deduplicated operational alerts through Microsoft Graph.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/oszuidwest/zwfm-babbel/internal/config"
)

const (
	graphBaseURL     = "https://graph.microsoft.com/v1.0"
	graphScope       = "https://graph.microsoft.com/.default"
	tokenURLTemplate = "https://login.microsoftonline.com/%s/oauth2/v2.0/token" //nolint:gosec // URL template, not a credential
	graphHTTPTimeout = 30 * time.Second
	maxRetries       = 3
	initialRetryWait = time.Second
	maxRetryWait     = 30 * time.Second
)

// GraphClient sends plain-text mail through Microsoft Graph.
type GraphClient struct {
	fromAddress string
	baseURL     string
	httpClient  *http.Client
	wait        func(context.Context, time.Duration) error
}

// NewGraphClient returns a Microsoft Graph mail client using OAuth2 client
// credentials. The caller must pass a complete configuration; startup
// validation in the config package enforces this.
func NewGraphClient(cfg *config.GraphConfig) *GraphClient {
	credentials := &clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     fmt.Sprintf(tokenURLTemplate, cfg.TenantID),
		Scopes:       []string{graphScope},
	}
	baseClient := &http.Client{Timeout: graphHTTPTimeout}
	oauthCtx := context.WithValue(context.Background(), oauth2.HTTPClient, baseClient)

	return &GraphClient{
		fromAddress: cfg.FromAddress,
		baseURL:     graphBaseURL,
		httpClient:  credentials.Client(oauthCtx),
	}
}

type graphMailRequest struct {
	Message graphMessage `json:"message"`
}

type graphMessage struct {
	Subject      string           `json:"subject"`
	Body         graphBody        `json:"body"`
	ToRecipients []graphRecipient `json:"toRecipients"`
}

type graphBody struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

type graphRecipient struct {
	EmailAddress graphEmailAddress `json:"emailAddress"`
}

type graphEmailAddress struct {
	Address string `json:"address"`
}

// SendMail sends one plain-text message to already-validated recipient
// addresses. Context cancellation also stops retries.
func (c *GraphClient) SendMail(ctx context.Context, recipients []string, subject, body string) error {
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients specified")
	}
	toRecipients := make([]graphRecipient, 0, len(recipients))
	for _, address := range recipients {
		toRecipients = append(toRecipients, graphRecipient{EmailAddress: graphEmailAddress{Address: address}})
	}

	payload, err := json.Marshal(graphMailRequest{Message: graphMessage{
		Subject:      subject,
		Body:         graphBody{ContentType: "Text", Content: body},
		ToRecipients: toRecipients,
	}})
	if err != nil {
		return fmt.Errorf("marshal graph mail request: %w", err)
	}
	return c.doWithRetry(ctx, payload)
}

// doWithRetry retries transient Graph failures and returns the last failure
// after the configured attempt limit.
func (c *GraphClient) doWithRetry(ctx context.Context, payload []byte) error {
	endpoint := fmt.Sprintf("%s/users/%s/sendMail", c.baseURL, url.PathEscape(c.fromAddress))
	var lastErr error
	var retryWait time.Duration

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("graph mail request cancelled: %w", err)
		}
		if attempt > 0 {
			if retryWait <= 0 {
				retryWait = backoffDelay(attempt)
			}
			if err := c.waitForRetry(ctx, retryWait); err != nil {
				return fmt.Errorf("graph mail retry cancelled: %w", err)
			}
		}

		var retry bool
		retryWait, retry, lastErr = c.sendAttempt(ctx, endpoint, payload)
		if lastErr == nil {
			return nil
		}
		if !retry {
			return lastErr
		}
	}

	return fmt.Errorf("graph mail retries exhausted: %w", lastErr)
}

// sendAttempt performs one Graph request and reports whether its failure is
// transient. A positive delay overrides exponential backoff for the next try.
func (c *GraphClient) sendAttempt(ctx context.Context, endpoint string, payload []byte) (time.Duration, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return 0, false, fmt.Errorf("create graph mail request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, true, fmt.Errorf("send graph mail request: %w", err)
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	closeErr := resp.Body.Close()
	if readErr != nil {
		return 0, false, fmt.Errorf("read graph mail response: %w", readErr)
	}
	if closeErr != nil {
		return 0, false, fmt.Errorf("close graph mail response: %w", closeErr)
	}

	switch resp.StatusCode {
	case http.StatusAccepted, http.StatusOK, http.StatusNoContent:
		return 0, false, nil
	case http.StatusTooManyRequests:
		return retryAfterDelay(resp.Header.Get("Retry-After")), true,
			fmt.Errorf("graph API rate limited: %s", responseBody)
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return 0, true, fmt.Errorf("graph API returned %d: %s", resp.StatusCode, responseBody)
	default:
		return 0, false, fmt.Errorf("graph API returned %d: %s", resp.StatusCode, responseBody)
	}
}

// retryAfterDelay parses Graph's delta-seconds Retry-After value without
// allowing a server-controlled delay or duration conversion to exceed the cap.
func retryAfterDelay(value string) time.Duration {
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil || seconds <= 0 {
		return 0
	}
	seconds = min(seconds, int64(maxRetryWait/time.Second))
	return time.Duration(seconds) * time.Second
}

// backoffDelay returns capped exponential backoff with up to 50 percent jitter.
func backoffDelay(attempt int) time.Duration {
	delay := min(initialRetryWait<<(attempt-1), maxRetryWait)
	delay += rand.N(delay / 2) //nolint:gosec // retry jitter is not security-sensitive
	return min(delay, maxRetryWait)
}

// waitForRetry waits for the next attempt while respecting cancellation. Tests
// can replace the wait function to verify retry timing without sleeping.
func (c *GraphClient) waitForRetry(ctx context.Context, delay time.Duration) error {
	if c.wait != nil {
		return c.wait(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
