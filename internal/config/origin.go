package config

import (
	"errors"
	"net/url"
	"strings"
)

// normalizeOrigin returns the canonical scheme://host form of a bare absolute
// origin. A single trailing slash is tolerated; path, query, fragment, and
// userinfo components are rejected.
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

// originFromURL returns the canonical scheme://host origin for an absolute URL.
// The URL may include path, query, or fragment components, but must not include
// userinfo.
func originFromURL(raw string) (string, error) {
	parsed, err := parseAbsoluteURL(raw)
	if err != nil {
		return "", err
	}

	return canonicalOrigin(parsed), nil
}

// IsOriginAllowed reports whether origin matches one of the configured bare
// origins. Invalid candidates or configured entries are treated as non-matches.
func IsOriginAllowed(origin, allowedOrigins string) bool {
	normalizedOrigin, err := normalizeOrigin(origin)
	if err != nil {
		return false
	}

	return isNormalizedOriginAllowed(normalizedOrigin, allowedOrigins)
}

// IsURLAllowedByOrigin reports whether rawURL has an origin present in the
// configured bare origins list. Invalid URLs or configured entries are treated
// as non-matches.
func IsURLAllowedByOrigin(rawURL, allowedOrigins string) bool {
	normalizedOrigin, err := originFromURL(rawURL)
	if err != nil {
		return false
	}

	return isNormalizedOriginAllowed(normalizedOrigin, allowedOrigins)
}

func isNormalizedOriginAllowed(normalizedOrigin, allowedOrigins string) bool {
	for allowedOrigin := range strings.SplitSeq(allowedOrigins, ",") {
		normalizedAllowedOrigin, err := normalizeOrigin(allowedOrigin)
		if err == nil && normalizedOrigin == normalizedAllowedOrigin {
			return true
		}
	}

	return false
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
	return strings.ToLower(parsed.Scheme + "://" + parsed.Host)
}
