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
	e.NetworkBlocked("evil.com", 443, "not_allowlisted")
	line := strings.TrimSpace(buf.String())
	var got map[string]any
	if err := json.Unmarshal([]byte(line), &got); err != nil {
		t.Fatal(err)
	}
	if got["type"] != "network_blocked" || got["host"] != "evil.com" {
		t.Errorf("event = %v", got)
	}
}

func TestEmitter_DisabledIsNoop(t *testing.T) {
	var buf bytes.Buffer
	e := NewEmitter(nil) // nil writer = disabled
	e.NetworkBlocked("evil.com", 443, "x")
	if buf.Len() != 0 {
		t.Error("disabled emitter must not write")
	}
}
