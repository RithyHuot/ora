package denials

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestDiscard_DoesNotPanic(t *testing.T) {
	Discard.Push(context.Background(), Event{Kind: KindNetwork})
	Discard.Push(context.Background(), Event{Kind: KindFs})
	Discard.Push(context.Background(), Event{Kind: KindStderrSignature})
}

// TestSink_PushHonorsCancelledContext documents that a Sink implementation
// can choose to skip work when the caller's context is already cancelled.
// Without a context parameter on Push, sinks that do I/O cannot be
// cancelled alongside the rest of the session. v1.x Sink contract: Push
// receives a context; the discardSink ignores it; richer sinks may abort.
func TestSink_PushHonorsCancelledContext(t *testing.T) {
	t.Parallel()
	var calls int
	s := SinkFunc(func(ctx context.Context, _ Event) {
		if ctx.Err() != nil {
			return // caller cancelled; do nothing
		}
		calls++
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Push(ctx, Event{Kind: KindNetwork, Host: "x"})
	if calls != 0 {
		t.Fatalf("Push under cancelled ctx should be a no-op for honoring sinks; got %d", calls)
	}
}

// SinkFunc is a test helper that adapts a function to the Sink interface
// so test sinks can be written inline. Lives in the test file so it does
// not bloat the public surface.
type SinkFunc func(context.Context, Event)

// Push implements Sink.
func (f SinkFunc) Push(ctx context.Context, e Event) { f(ctx, e) }

func TestKind_MarshalJSON_RoundTrips(t *testing.T) {
	for _, k := range []Kind{KindNetwork, KindFs, KindStderrSignature} {
		b, err := json.Marshal(k)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			t.Errorf("output is not valid JSON string: %s", b)
		}
		if s != k.String() {
			t.Errorf("round-trip mismatch: got %q want %q", s, k.String())
		}
	}
}

// TestEvent_MarshalsLowercaseFieldNames pins the JSON shape so a future
// edit can't silently rename fields. External aggregators index on these
// names; renaming "host" → "hostname" is a downstream-breaking change.
func TestEvent_MarshalsLowercaseFieldNames(t *testing.T) {
	t.Parallel()
	e := Event{
		Kind:      KindNetwork,
		Host:      "api.example.com",
		Port:      443,
		Reason:    "not_allowlisted",
		Operation: "",
		Path:      "",
		Snippet:   "",
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, want := range []string{`"kind":`, `"host":`, `"port":`, `"reason":`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("Event JSON missing %s; got %s", want, b)
		}
	}
	for _, banned := range []string{`"Host":`, `"Port":`, `"Operation":`, `"Path":`} {
		if strings.Contains(string(b), banned) {
			t.Errorf("Event JSON leaks Go-default field name %s; got %s", banned, b)
		}
	}
}

// TestEvent_OmitEmpty asserts that unrelated fields are dropped from the
// JSON output so an external aggregator sees a narrow per-Kind shape.
func TestEvent_OmitEmpty(t *testing.T) {
	t.Parallel()
	e := Event{Kind: KindNetwork, Host: "api.example.com", Port: 443, Reason: "not_allowlisted"}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, banned := range []string{`"operation":`, `"path":`, `"snippet":`} {
		if strings.Contains(string(b), banned) {
			t.Errorf("Network Event must omit %s; got %s", banned, b)
		}
	}
}
