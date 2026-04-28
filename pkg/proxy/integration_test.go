//go:build integration

package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// TestEgress_RealAllowlistedHost verifies HTTPS CONNECT to a real allowlisted host.
func TestEgress_RealAllowlistedHost(t *testing.T) {
	e := &Egress{Allowed: []string{"api.github.com"}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	port, err := e.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	tr := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{},
	}
	client := &http.Client{Transport: tr, Timeout: 8 * time.Second}

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/nonexistent", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET via proxy failed: %v (egress allowlist or network down?)", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Errorf("expected 4xx from host, got %d", resp.StatusCode)
	}
}

func TestEgress_DenyExternalHost(t *testing.T) {
	e := &Egress{Allowed: []string{"only-this.example"}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	port, err := e.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	resp, err := client.Get("https://example.com/")
	if err == nil {
		resp.Body.Close()
		t.Fatalf("expected error for denied host, got status %d", resp.StatusCode)
	}
	// Error message should mention 403 from the proxy or proxy refusal.
	t.Logf("denied request error (expected): %v", err)
}
