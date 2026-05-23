package main

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// healthcheckTimeout bounds the Docker healthcheck request.
const healthcheckTimeout = 3 * time.Second

// runHealthcheck probes the HTTP health endpoint and returns an error on failure.
func runHealthcheck(ctx context.Context, targetURL string) error {
	if targetURL == "" {
		return fmt.Errorf("healthcheck URL is required")
	}

	ctx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("create healthcheck request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("perform healthcheck request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // Healthcheck response close errors do not affect readiness.

	if resp.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("healthcheck returned HTTP %d", resp.StatusCode)
	}

	return nil
}
