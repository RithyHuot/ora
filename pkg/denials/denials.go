package denials

import (
	"context"
	"encoding/json"
	"fmt"
)

// Kind discriminates Event payloads.
type Kind int

const (
	// KindNetwork is an egress proxy block (host disallowed or non-443).
	KindNetwork Kind = iota
	// KindFs is a Seatbelt filesystem denial parsed from the unified log.
	KindFs
	// KindStderrSignature is a denial-shaped substring observed in the
	// sandboxed child's stderr (locale-dependent, best-effort).
	KindStderrSignature
)

// String returns the stable lowercase name for k. Names are part of the
// pkg/denials public API and will not change between minor versions.
// An unknown Kind returns "kind(<int>)".
func (k Kind) String() string {
	switch k {
	case KindNetwork:
		return "network"
	case KindFs:
		return "fs"
	case KindStderrSignature:
		return "stderr"
	default:
		return fmt.Sprintf("kind(%d)", int(k))
	}
}

// MarshalJSON implements json.Marshaler so Event serializes Kind as its
// stable string name rather than the underlying iota integer.
func (k Kind) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.String())
}

// UnmarshalJSON implements json.Unmarshaler so an Event written by a previous
// invocation can be read back. Only the stable names produced by String are
// accepted; an unknown name (including the diagnostic "kind(N)" form for
// out-of-range Kinds) returns an error so consumers fail loudly on schema
// drift instead of silently coercing to KindNetwork (the iota zero value).
func (k *Kind) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("denials.Kind: expected JSON string, got %s: %w", data, err)
	}
	switch s {
	case "network":
		*k = KindNetwork
	case "fs":
		*k = KindFs
	case "stderr":
		*k = KindStderrSignature
	default:
		return fmt.Errorf("denials.Kind: unknown name %q", s)
	}
	return nil
}

// Event is one denial signal. JSON field names are pinned via struct tags
// so the wire format is stable across future field renames in Go code.
//
// Each field is emitted only when relevant to the Kind:
//   - KindNetwork:           host, port, reason
//   - KindFs:                operation, path
//   - KindStderrSignature:   snippet
//
// Fields outside the relevant kind are omitted via `omitempty` to keep
// JSON-Lines output narrow.
type Event struct {
	Kind      Kind   `json:"kind"`
	Host      string `json:"host,omitempty"`      // KindNetwork
	Port      int    `json:"port,omitempty"`      // KindNetwork
	Reason    string `json:"reason,omitempty"`    // KindNetwork ("non_443", "not_allowlisted", "tunnel_cap")
	Operation string `json:"operation,omitempty"` // KindFs (e.g. "file-write-create")
	Path      string `json:"path,omitempty"`      // KindFs
	Snippet   string `json:"snippet,omitempty"`   // KindStderrSignature
}

// Sink receives denial events. Implementations must be safe for concurrent
// Push calls (the proxy and log-monitor goroutines invoke Push in parallel).
//
// Push receives a context so implementations that do I/O can honor caller
// cancellation. Implementations that do not block (Discard, Counter,
// in-memory aggregators) may ignore the context.
type Sink interface {
	Push(ctx context.Context, e Event)
}

// Discard is a Sink that drops every event. Useful as a default to avoid
// nil checks in producers.
var Discard Sink = discardSink{}

type discardSink struct{}

// Push implements Sink by discarding the event. The context is ignored.
func (discardSink) Push(context.Context, Event) {}
