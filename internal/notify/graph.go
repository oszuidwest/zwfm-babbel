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
				// Exponential backoff with up to 50% jitter, capped at maxRetryWait.
				retryWait = min(initialRetryWait<<(attempt-1), maxRetryWait)
				retryWait += rand.N(retryWait / 2) //nolint:gosec // retry jitter is not security-sensitive
			}
			if err := sleepWithContext(ctx, retryWait); err != nil {
				return fmt.Errorf("graph mail retry cancelled: %w", err)
			}
			retryWait = 0
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("create graph mail request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("send graph mail request: %w", err)
			continue
		}
		responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		closeErr := resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read graph mail response: %w", readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close graph mail response: %w", closeErr)
		}

		switch resp.StatusCode {
		case http.StatusAccepted, http.StatusOK, http.StatusNoContent:
			return nil
		case http.StatusTooManyRequests:
			if retryAfter, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && retryAfter > 0 {
				retryWait = time.Duration(retryAfter) * time.Second
			}
			lastErr = fmt.Errorf("graph API rate limited: %s", responseBody)
		case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			lastErr = fmt.Errorf("graph API returned %d: %s", resp.StatusCode, responseBody)
		default:
			return fmt.Errorf("graph API returned %d: %s", resp.StatusCode, responseBody)
		}
	}

	return fmt.Errorf("graph mail retries exhausted: %w", lastErr)
}

func sleepWithContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
