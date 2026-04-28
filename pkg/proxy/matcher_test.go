package proxy

import "testing"

func TestMatcher_Exact(t *testing.T) {
	m := compileMatcher([]string{"api.example.com"})
	if !m("api.example.com") {
		t.Error("expected exact match")
	}
	if m("evil.api.example.com") {
		t.Error("exact-only entry should not match longer hostname")
	}
}

func TestMatcher_Wildcard(t *testing.T) {
	m := compileMatcher([]string{"*.openai.com"})
	if !m("api.openai.com") {
		t.Error("wildcard should match subdomain")
	}
	if !m("nested.deep.openai.com") {
		t.Error("wildcard should match multi-level subdomain")
	}
	// Critical: must not be defeated by suffix prefixed onto evil host.
	if m("openai.com.evil.io") {
		t.Error("wildcard must require dot boundary; saw false match for openai.com.evil.io")
	}
	// Wildcard does NOT match the bare domain itself.
	if m("openai.com") {
		t.Error("*.openai.com should not match bare openai.com")
	}
}

func TestMatcher_CaseInsensitive(t *testing.T) {
	m := compileMatcher([]string{"GitHub.com"})
	if !m("github.com") {
		t.Error("expected case-insensitive match")
	}
	if !m("GITHUB.COM") {
		t.Error("expected case-insensitive match (uppercase)")
	}
}

func TestMatcher_Empty(t *testing.T) {
	m := compileMatcher(nil)
	if m("anything.com") {
		t.Error("empty matcher should deny everything")
	}
}

func TestMatcher_TrimsWhitespace(t *testing.T) {
	m := compileMatcher([]string{" api.foo.com ", "  ", "*.bar.com"})
	if !m("api.foo.com") || !m("x.bar.com") {
		t.Error("matcher should trim entries and ignore empties")
	}
}

func TestValidateAllowedDomain_RejectsOverlyBroadWildcards(t *testing.T) {
	cases := []string{
		"*.com",
		"*.io",
		"*.co",
		"*.org",
		"*",
		"*.",
		"*evil.com", // bare * prefix without dot
		"*foo.com",
	}
	for _, c := range cases {
		if _, err := ValidateAllowedDomain(c); err == nil {
			t.Errorf("ValidateAllowedDomain(%q) should fail but did not", c)
		}
	}
}

func TestValidateAllowedDomain_RejectsMalformed(t *testing.T) {
	cases := []string{
		"",
		"   ",
		"https://example.com",
		"example.com:443",
		"foo bar.com",
		"example..com",
		".example.com",
		"example.com.",
		"café.example", // non-ASCII
		"foo/bar.com",
	}
	for _, c := range cases {
		if _, err := ValidateAllowedDomain(c); err == nil {
			t.Errorf("ValidateAllowedDomain(%q) should fail but did not", c)
		}
	}
}

func TestValidateAllowedDomain_AcceptsValidEntries(t *testing.T) {
	cases := map[string]string{
		"api.example.com":         "api.example.com",
		"  GitHub.com  ":          "github.com",
		"*.openai.com":            "*.openai.com",
		"*.api.example.com":       "*.api.example.com",
		"xn--caf-dma.example.com": "xn--caf-dma.example.com", // punycoded IDN
	}
	for input, want := range cases {
		got, err := ValidateAllowedDomain(input)
		if err != nil {
			t.Errorf("ValidateAllowedDomain(%q) unexpected error: %v", input, err)
			continue
		}
		if got != want {
			t.Errorf("ValidateAllowedDomain(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestValidateAllowedDomains_StopsOnFirstError(t *testing.T) {
	if _, err := ValidateAllowedDomains([]string{"good.com", "*.com"}); err == nil {
		t.Error("expected error, got nil")
	}
}

func TestValidateAllowedDomains_SkipsEmpties(t *testing.T) {
	out, err := ValidateAllowedDomains([]string{"", " ", "good.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 || out[0] != "good.com" {
		t.Errorf("got %v, want [good.com]", out)
	}
}
