package config

import (
	"errors"
	"net/url"
	"strings"
)

// normalizeOrigin returns the canonical, lowercased scheme://host[:port] form of
// a bare absolute origin. Default ports (:80 for http, :443 for https) are
// omitted to match web origin serialization. A single trailing slash is
// tolerated; path, query, fragment, and userinfo components are rejected.
func normalizeOrigin(raw string) (string, error) {
	parsed, err := parseAbsoluteURL(raw)
	if err != nil {
		return "", err
	}

	if parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("must be a bare origin without path, query, or fragment")
	}

	return canonicalOrigin(parsed), nil
}

// originFromURL returns the canonical, lowercased scheme://host[:port] origin for
// an absolute URL. The URL may include path, query, or fragment components, but
// must not include userinfo.
func originFromURL(raw string) (string, error) {
	parsed, err := parseAbsoluteURL(raw)
	if err != nil {
		return "", err
	}

	return canonicalOrigin(parsed), nil
}

// OriginChecker matches request origins against a set of allowed origins that
// is normalized once at construction time, so per-request checks only
// normalize the incoming value.
type OriginChecker struct {
	allowed map[string]struct{}
}

// NewOriginChecker normalizes the comma-separated allowedOrigins list into a
// set. Malformed configured entries are skipped: they are rejected at startup
// by validateAllowedOrigins, so skipping them here is defense-in-depth, not
// the primary safeguard.
func NewOriginChecker(allowedOrigins string) *OriginChecker {
	allowed := make(map[string]struct{})
	for allowedOrigin := range strings.SplitSeq(allowedOrigins, ",") {
		normalized, err := normalizeOrigin(allowedOrigin)
		if err != nil {
			continue
		}
		allowed[normalized] = struct{}{}
	}
	return &OriginChecker{allowed: allowed}
}

// Allowed reports whether origin matches one of the configured bare origins.
// Invalid candidates are treated as non-matches.
func (oc *OriginChecker) Allowed(origin string) bool {
	normalizedOrigin, err := normalizeOrigin(origin)
	if err != nil {
		return false
	}

	return oc.contains(normalizedOrigin)
}

func (oc *OriginChecker) contains(normalizedOrigin string) bool {
	_, ok := oc.allowed[normalizedOrigin]
	return ok
}

// IsURLAllowedByOrigin reports whether rawURL has an origin present in the
// configured bare origins list. Invalid URLs or configured entries are treated
// as non-matches.
func IsURLAllowedByOrigin(rawURL, allowedOrigins string) bool {
	normalizedOrigin, err := originFromURL(rawURL)
	if err != nil {
		return false
	}

	return NewOriginChecker(allowedOrigins).contains(normalizedOrigin)
}

func parseAbsoluteURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("must not be empty")
	}

	parsed, err := url.Parse(strings.TrimSuffix(raw, "/"))
	if err != nil {
		return nil, err
	}

	switch {
	case !parsed.IsAbs():
		return nil, errors.New("missing scheme (expected scheme://host)")
	case parsed.Host == "":
		return nil, errors.New("missing host")
	case parsed.User != nil:
		return nil, errors.New("must not contain user information")
	}

	return parsed, nil
}

func canonicalOrigin(parsed *url.URL) string {
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()

	if port != "" && !isDefaultPort(scheme, port) {
		host += ":" + port
	}

	return scheme + "://" + host
}

func isDefaultPort(scheme, port string) bool {
	return (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
}
