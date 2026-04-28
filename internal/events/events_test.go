package events

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestEmitter_NetworkBlocked(t *testing.T) {
	var buf bytes.Buffer
	e := NewEmitter(&buf)
	e.NetworkBlocked("evil.com", 443, "not_allowlisted", "")
	line := strings.TrimSpace(buf.String())
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatal(err)
	}
	if got["type"] != "network_blocked" || got["host"] != "evil.com" {
		t.Errorf("event = %v", got)
	}
	// Empty hint must be omitted from JSON to keep existing consumers
	// unaffected; presence with empty value would still affect strict
	// schema parsers.
	if _, present := got["hint"]; present {
		t.Errorf("empty hint must be omitted from JSON; got %v", got)
	}
}

// TestEmitter_NetworkBlocked_WithHint verifies that a non-empty hint
// is surfaced in the JSON event so structured consumers can act on it.
func TestEmitter_NetworkBlocked_WithHint(t *testing.T) {
	var buf bytes.Buffer
	e := NewEmitter(&buf)
	e.NetworkBlocked("api.mycorp.com", 443, "not_allowlisted",
		"add `api.mycorp.com` to ORA_ALLOWED_DOMAINS or egress.extra_domains in .ora.toml")
	var got map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &got); err != nil {
		t.Fatal(err)
	}
	hint, ok := got["hint"].(string)
	if !ok || !strings.Contains(hint, "ORA_ALLOWED_DOMAINS") {
		t.Errorf("expected hint mentioning ORA_ALLOWED_DOMAINS; got %v", got["hint"])
	}
}

// TestEmitter_FsDeny_WithHint verifies the same behavior on the FS
// path: empty hint omitted, non-empty surfaced.
func TestEmitter_FsDeny_WithHint(t *testing.T) {
	var buf bytes.Buffer
	e := NewEmitter(&buf)
	e.FsDeny("file-read-data", "/Users/x/code/proj/.git/config",
		"set `paths.allow_git_config = true` in .ora.toml ...")
	var got map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &got); err != nil {
		t.Fatal(err)
	}
	if got["type"] != "fs_deny" {
		t.Errorf("type = %v, want fs_deny", got["type"])
	}
	if hint, _ := got["hint"].(string); !strings.Contains(hint, "allow_git_config") {
		t.Errorf("expected hint mentioning allow_git_config; got %v", got["hint"])
	}
}

func TestEmitter_DisabledIsNoop(t *testing.T) {
	var buf bytes.Buffer
	e := NewEmitter(nil) // nil writer = disabled
	e.NetworkBlocked("evil.com", 443, "x", "")
	if buf.Len() != 0 {
		t.Error("disabled emitter must not write")
	}
}
