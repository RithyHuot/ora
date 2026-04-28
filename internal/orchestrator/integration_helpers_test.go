//go:build darwin && integration

package orchestrator

import (
	"io"
	"log/slog"
	"testing"

	"github.com/rithyhuot/ora/internal/config"
	"github.com/rithyhuot/ora/internal/events"
)

// minimalConfigForTest returns a config sufficient to exercise Runner.Run
// inside the //go:build darwin && integration tests. NativeKernel must be
// true so the runner takes the sandboxed path (not the unsandboxed bypass)
// — the whole point of these tests is to verify Seatbelt-driven behavior.
func minimalConfigForTest(_ *testing.T) config.Config {
	return config.Config{
		NativeKernel: true,
		AuthDirMode:  "readwrite",
	}
}

func newDiscardEmitter() *events.Emitter { return events.NewEmitter(nil) }

func newDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}
