//go:build !darwin

package sandbox

import (
	"context"
	"errors"
)

// ErrLogMonitorUnsupported is returned by StartLogMonitor and
// SelfTestLogStream on platforms that do not support the macOS unified log.
var ErrLogMonitorUnsupported = errors.New("sandbox log monitor requires macOS")

// SandboxDenyEvent is one parsed deny line from the macOS unified log.
// On non-Darwin platforms the struct is defined but never populated.
type SandboxDenyEvent struct {
	Operation string
	Path      string
	Raw       string
}

// StartLogMonitor always returns ErrLogMonitorUnsupported on non-Darwin
// platforms.
func StartLogMonitor(_ context.Context, _ func(SandboxDenyEvent)) (func(), error) {
	return func() {}, ErrLogMonitorUnsupported
}

// SelfTestLogStream always returns ErrLogMonitorUnsupported on non-Darwin
// platforms.
func SelfTestLogStream(_ context.Context) error {
	return ErrLogMonitorUnsupported
}
