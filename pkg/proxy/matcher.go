package proxy

import (
	"fmt"
	"strings"
)

// hostMatcher returns true if the hostname is allowed.
type hostMatcher func(host string) bool

// ValidateAllowedDomain returns the canonical form of entry, or an error if
// the entry would silently grant overly broad access (e.g. "*.com", "*",
// "*.io") or is otherwise malformed (contains scheme/port/path/whitespace,
// or contains non-ASCII characters that would not literally match the
// ASCII-form Host header from CONNECT).
//
// Wildcard requirements:
//   - must start with "*." (no bare "*" or prefix wildcards)
//   - the suffix after "*." must have at least 2 labels (so *.example.com
//     is fine but *.com is not)
//
// Non-ASCII (IDN) entries are rejected with a clear error; callers should
// punycode them explicitly. This avoids a hidden dependency on x/net/idna
// and forces the allowlist author to think about which form they mean.
func ValidateAllowedDomain(entry string) (string, error) {
	t := strings.TrimSpace(strings.ToLower(entry))
	if t == "" {
		return "", fmt.Errorf("empty allowlist entry")
	}
	host := t
	wildcard := false
	switch {
	case strings.HasPrefix(t, "*."):
		wildcard = true
		host = t[2:]
	case strings.HasPrefix(t, "*"):
		return "", fmt.Errorf("invalid allowlist entry %q: bare or prefix wildcards not allowed (use *.<domain>)", entry)
	}
	if host == "" {
		return "", fmt.Errorf("invalid allowlist entry %q: empty host", entry)
	}
	if strings.ContainsAny(host, "/:\t\n\r ") {
		return "", fmt.Errorf("invalid allowlist entry %q: contains scheme, port, path, or whitespace", entry)
	}
	for _, r := range host {
		if r > 127 {
			return "", fmt.Errorf("invalid allowlist entry %q: non-ASCII character %q (use Punycode form e.g. xn--...)", entry, r)
		}
	}
	if strings.Contains(host, "..") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return "", fmt.Errorf("invalid allowlist entry %q: malformed labels", entry)
	}
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if l == "" {
			return "", fmt.Errorf("invalid allowlist entry %q: empty label", entry)
		}
	}
	if wildcard && len(labels) < 2 {
		return "", fmt.Errorf("invalid allowlist entry %q: wildcard suffix must have at least two labels (e.g. *.example.com, not *.%s)", entry, host)
	}
	if wildcard {
		return "*." + host, nil
	}
	return host, nil
}

// ValidateAllowedDomains validates each entry. Returns the canonicalized
// list on success; on first failure returns the error and a nil list. Empty
// entries are skipped silently (matches the existing compileMatcher behavior).
func ValidateAllowedDomains(entries []string) ([]string, error) {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.TrimSpace(e) == "" {
			continue
		}
		c, err := ValidateAllowedDomain(e)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// compileMatcher builds a case-insensitive matcher from an allowlist that
// may contain exact entries (e.g. "api.example.com") and wildcard
// entries (e.g. "*.openai.com"). A wildcard requires a dot boundary:
// "*.openai.com" matches "api.openai.com" and "x.y.openai.com" but
// neither "openai.com" itself nor "openai.com.evil.io".
//
// compileMatcher does NOT validate entries — it silently drops empty entries.
// Callers wanting strict validation should call ValidateAllowedDomains first.
func compileMatcher(allowed []string) hostMatcher {
	exact := make(map[string]struct{})
	suffix := make([]string, 0)
	for _, raw := range allowed {
		t := strings.TrimSpace(strings.ToLower(raw))
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "*.") {
			suffix = append(suffix, t[1:]) // store as ".openai.com"
		} else {
			exact[t] = struct{}{}
		}
	}
	return func(host string) bool {
		h := strings.ToLower(host)
		if _, ok := exact[h]; ok {
			return true
		}
		for _, s := range suffix {
			if strings.HasSuffix(h, s) {
				return true
			}
		}
		return false
	}
}
