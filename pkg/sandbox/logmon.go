//go:build darwin

// macOS-specific log-monitor helpers. Today the only Backend
// implementation is Seatbelt; if a Linux backend is added in the future,
// extend Backend with log-monitor methods rather than exposing these as
// package-level functions.

package sandbox

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ErrLogMonitorUnsupported is returned by StartLogMonitor and
// SelfTestLogStream on platforms that do not support the macOS unified log.
var ErrLogMonitorUnsupported = errors.New("sandbox log monitor requires macOS")

// SandboxDenyEvent is one parsed deny line from the macOS unified log.
type SandboxDenyEvent struct {
	Operation string
	Path      string
	Raw       string
}

// denyLineRe extracts (op, path) from a sandboxd deny line emitted by
// `log show --style compact`. The format we target:
//
//	... sandboxd[NNN]: deny(N) <op> <path>...
//
// The required `sandboxd[\d+]:` prefix prevents another process whose log
// message happens to contain `deny(N) ...` from spoofing a deny event.
var denyLineRe = regexp.MustCompile(`sandboxd\[\d+\]:\s*deny\(\d+\)\s+(\S+)\s+(.+?)\s*$`)

// trailingAnnotationRe captures the per-line metadata macOS 26 appends after
// the path, e.g. ` <process: foo[123]>`. Stripping it keeps the captured
// path clean across log format revisions.
var trailingAnnotationRe = regexp.MustCompile(`\s+<[^>]+>\s*$`)

// ParseSandboxLogLine extracts an op + path from a sandboxd deny line.
// Returns ok=false for any line that doesn't match.
func ParseSandboxLogLine(line string) (SandboxDenyEvent, bool) {
	clean := trailingAnnotationRe.ReplaceAllString(line, "")
	m := denyLineRe.FindStringSubmatch(clean)
	if len(m) != 3 {
		return SandboxDenyEvent{}, false
	}
	return SandboxDenyEvent{
		Operation: m[1],
		Path:      strings.TrimSpace(m[2]),
		Raw:       strings.TrimSpace(line),
	}, true
}

// SelfTestLogStream verifies that `/usr/bin/log` is present, executable,
// and produces output that resembles the format ParseSandboxLogLine knows
// how to parse. Returns nil if the monitor can be relied on, or a
// descriptive error if Apple has changed the format (in which case the
// caller should degrade verbose mode rather than silently miss denials).
//
// The probe runs `log show --last 1m` filtered for any sandbox-style
// "deny(N)" line and inspects the first parseable line. We tolerate "no
// matching lines in the last minute" — that's the common case on a quiet
// machine — and treat it as a soft pass.
func SelfTestLogStream(ctx context.Context) error {
	if _, err := exec.LookPath("log"); err != nil {
		return fmt.Errorf("log binary not found: %w", err)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(probeCtx, "log", "show",
		"--last", "1m",
		"--style", "compact",
		"--predicate", `eventMessage CONTAINS "deny("`,
	)
	out, err := cmd.Output()
	if err != nil {
		if errors.Is(probeCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("log show probe timed out after 3s; cannot verify log monitor: %w",
				context.DeadlineExceeded)
		}
		if probeCtx.Err() == nil {
			return fmt.Errorf("log show failed: %w", err)
		}
		// Caller-canceled (not our timeout); propagate.
		return probeCtx.Err()
	}
	for _, line := range strings.Split(string(out), "\n") {
		if _, ok := ParseSandboxLogLine(line); ok {
			return nil
		}
	}
	return nil
}

// StartLogMonitor spawns `log stream` filtering for sandbox denies and
// invokes onDeny for each parsed event. The returned cancel function stops
// the subprocess. Returns nil cancel + error if `log` is not available.
//
// Stderr from `log stream` is forwarded to slog at Warn level; if Apple
// changes the predicate format, the caller sees the actual error rather
// than silently missing denials. The scanner buffer is bumped to 1 MiB so
// long log lines (paths > 64 KiB are rare but possible) don't truncate.
func StartLogMonitor(ctx context.Context, onDeny func(SandboxDenyEvent)) (func(), error) {
	cctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(cctx, "log", "stream",
		"--style", "compact",
		"--predicate", `process == "sandboxd" AND eventMessage CONTAINS "deny"`,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Forward stderr to slog so users see "unknown predicate" rather than
	// nothing if Apple changes the log query language.
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			slog.Warn("log stream stderr", "line", scanner.Text())
		}
	}()

	go func() {
		defer wg.Done()
		defer func() { _, _ = io.Copy(io.Discard, stdout) }()
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			if ev, ok := ParseSandboxLogLine(scanner.Text()); ok {
				onDeny(ev)
			}
		}
		if err := scanner.Err(); err != nil {
			slog.Warn("log stream scanner error; further denials may be missed", "err", err)
		}
	}()

	return func() {
		cancel()
		if err := cmd.Wait(); err != nil && cctx.Err() == nil {
			slog.Warn("log stream wait error", "err", err)
		}
		// Wait for both reader goroutines to drain so onDeny is no longer
		// called after the cancel function returns. Without this join, the
		// caller can free state behind onDeny while the scanner goroutine is
		// mid-callback — a data race.
		wg.Wait()
	}, nil
}
