// Package events emits machine-readable JSON-Lines events for ora's
// sandbox lifecycle when --json is set. Emitter also implements the
// denials.Sink interface so it can plug into the unified denial pipeline.
package events

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/rithyhuot/ora/pkg/denials"
)

// EventVersion is the schema version stamped onto each emitted event line.
// Bump on incompatible field changes so SIEM consumers can pin against the
// constant.
const EventVersion = 1

// Emitter writes JSON-Lines events to a writer.
type Emitter struct {
	mu             sync.Mutex
	w              io.Writer // nil = disabled
	marshalErrOnce sync.Once
	writeErrOnce   sync.Once
}

// NewEmitter returns an Emitter that writes to w. If w is nil, the emitter is disabled.
func NewEmitter(w io.Writer) *Emitter { return &Emitter{w: w} }

func (e *Emitter) emit(payload map[string]any) {
	if e == nil || e.w == nil {
		return
	}
	payload["version"] = EventVersion
	payload["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	payload["pid"] = os.Getpid()

	buf, err := json.Marshal(payload)
	if err != nil {
		e.marshalErrOnce.Do(func() {
			slog.Warn("events: marshal failed; further errors suppressed", "err", err)
		})
		return
	}
	buf = append(buf, '\n')

	e.mu.Lock()
	defer e.mu.Unlock()
	if _, werr := e.w.Write(buf); werr != nil {
		e.writeErrOnce.Do(func() {
			slog.Warn("events: emitter write failed; further errors suppressed", "err", werr)
		})
	}
}

// NetworkBlocked emits a network_blocked event.
func (e *Emitter) NetworkBlocked(host string, port int, reason string) {
	e.emit(map[string]any{"type": "network_blocked", "host": host, "port": port, "reason": reason})
}

// FsDeny emits an fs_deny event.
func (e *Emitter) FsDeny(operation, path string) {
	e.emit(map[string]any{"type": "fs_deny", "operation": operation, "path": path})
}

// SandboxSummary emits a sandbox_summary event.
func (e *Emitter) SandboxSummary(exitCode int, durationMs int64, networkBlocks int) {
	e.emit(map[string]any{
		"type":           "sandbox_summary",
		"exit_code":      exitCode,
		"duration_ms":    durationMs,
		"network_blocks": networkBlocks,
	})
}

// Push implements denials.Sink: maps a denial Event onto the equivalent
// JSON event line so a single producer call lands in both the human and
// machine-readable streams. The context is currently unused — the emitter
// does a synchronous in-process JSON marshal + write that returns
// promptly. A future I/O-backed emitter could honor cancellation here.
func (e *Emitter) Push(_ context.Context, ev denials.Event) {
	switch ev.Kind {
	case denials.KindNetwork:
		e.NetworkBlocked(ev.Host, ev.Port, ev.Reason)
	case denials.KindFs:
		e.FsDeny(ev.Operation, ev.Path)
	case denials.KindStderrSignature:
		// Not currently emitted as JSON; the runner already prints a
		// SANDBOX DENIED summary on exit when this fires.
	}
}
