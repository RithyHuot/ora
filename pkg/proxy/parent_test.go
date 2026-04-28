package proxy

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestResolveParentProxy_FromEnv(t *testing.T) {
	got := ResolveParentProxy(map[string]string{
		"HTTPS_PROXY": "http://proxy.corp:3128",
		"NO_PROXY":    "localhost,127.0.0.1,.internal",
	})
	if got == nil {
		t.Fatal("expected non-nil parent proxy")
	}
	want, _ := url.Parse("http://proxy.corp:3128")
	if got.URL.Host != want.Host {
		t.Errorf("URL.Host = %q, want %q", got.URL.Host, want.Host)
	}
	if !got.shouldBypass("api.internal") {
		t.Error("api.internal should be bypassed (matches .internal suffix)")
	}
	if got.shouldBypass("api.example.com") {
		t.Error("api.example.com should NOT be bypassed")
	}
}

func TestResolveParentProxy_NoneSet(t *testing.T) {
	if got := ResolveParentProxy(map[string]string{}); got != nil {
		t.Errorf("expected nil when no proxy env set, got %+v", got)
	}
}

func TestResolveParentProxy_AuthEncoded(t *testing.T) {
	got := ResolveParentProxy(map[string]string{"HTTPS_PROXY": "http://user:p@ss:w0rd@proxy.corp:3128"})
	if got == nil {
		t.Fatal("expected non-nil")
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:p@ss:w0rd"))
	if got.authHeader != want {
		t.Errorf("authHeader = %q, want %q", got.authHeader, want)
	}
}

func TestShouldBypass_BareEntryMatchesSubdomain(t *testing.T) {
	// Match Go stdlib NO_PROXY semantics: an entry without a leading dot
	// should match the host AND any subdomain of it. Operators porting a
	// working NO_PROXY=example.com from curl/Go stdlib expect this.
	got := ResolveParentProxy(map[string]string{
		"HTTPS_PROXY": "http://proxy:3128",
		"NO_PROXY":    "example.com",
	})
	if got == nil {
		t.Fatal("expected non-nil")
	}
	if !got.shouldBypass("example.com") {
		t.Error("example.com should bypass")
	}
	if !got.shouldBypass("api.example.com") {
		t.Error("api.example.com should bypass when NO_PROXY=example.com")
	}
	if got.shouldBypass("evil-example.com") {
		t.Error("evil-example.com should NOT bypass")
	}
}

func TestResolveParentProxy_RejectsInvalidScheme(t *testing.T) {
	got := ResolveParentProxy(map[string]string{"HTTPS_PROXY": "ftp://proxy:21"})
	if got != nil {
		t.Errorf("expected nil for ftp scheme, got %+v", got)
	}
}

func TestResolveParentProxy_AcceptsHTTPS(t *testing.T) {
	got := ResolveParentProxy(map[string]string{"HTTPS_PROXY": "https://proxy.corp:8443"})
	if got == nil {
		t.Fatal("expected non-nil for https scheme")
	}
	if got.URL.Scheme != "https" {
		t.Errorf("expected scheme=https, got %q", got.URL.Scheme)
	}
}
