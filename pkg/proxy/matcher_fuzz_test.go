package proxy

import (
	"strings"
	"testing"
)

// FuzzValidateAllowedDomain ensures arbitrary allowlist entries don't panic
// and that any input which passes validation produces a host the matcher
// will accept literally.
func FuzzValidateAllowedDomain(f *testing.F) {
	for _, s := range []string{
		"", "*", "*.com", "*.example.com", "api.example.com",
		"127.0.0.1", "[::1]", "*.evil/path", "foo:443",
		"\x00", "café.example", "space here",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, entry string) {
		canon, err := ValidateAllowedDomain(entry)
		if err != nil {
			return
		}
		m := compileMatcher([]string{canon})
		host := strings.TrimPrefix(canon, "*.")
		if !m(host) && !m(canon) {
			t.Fatalf("validated %q but matcher does not accept its canonical form %q", entry, canon)
		}
	})
}
