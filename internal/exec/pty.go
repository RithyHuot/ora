package exec

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/term"
)

// StdinIsTTY reports whether ora's stdin is a terminal. When true, callers
// should use RunPTY instead of RunWithSignals so interactive prompts from
// the wrapped CLI render correctly.
func StdinIsTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// RunPTY runs bin with args inside a freshly-allocated PTY, copying I/O
// between ora's stdio and the PTY master. Unlike RunWithSignals (which is
// suitable for non-interactive children), RunPTY:
//   - allocates a PTY (the child sees a real terminal)
//   - forwards SIGWINCH so the child's TIOCGWINSZ reports the right size
//   - returns the child's actual ProcessState — exit code 130 for
//     SIGINT-killed children flows through unchanged (unlike /usr/bin/script,
//     which masks signal-driven exit codes)
//
// stderr is written to the PTY master alongside stdout (a PTY presents a
// single byte stream); the parameter exists for API symmetry with
// RunWithSignals but is otherwise unused.
func RunPTY(ctx context.Context, bin string, args []string, env []string, cwd string, _ io.Writer) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	cmd.Dir = cwd
	if runtime.GOOS != "windows" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	}

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("pty.Start: %w", err)
	}

	// Resize forwarding: when ora's terminal resizes, propagate to the PTY.
	winchCh := make(chan os.Signal, 1)
	signal.Notify(winchCh, syscall.SIGWINCH)
	// signal.Stop drains registration but does NOT close winchCh; we close it
	// ourselves so the resize-forwarding goroutine exits rather than blocking
	// on an idle channel for the rest of the process lifetime.
	defer func() {
		signal.Stop(winchCh)
		close(winchCh)
	}()
	go func() {
		for range winchCh {
			_ = pty.InheritSize(os.Stdin, ptmx)
		}
	}()
	// Initial sizing: the channel is cap=1 and signal.Notify may already have
	// queued a real SIGWINCH between the goroutine starting and us reaching
	// here. A blocking send would deadlock in that race; the resize goroutine
	// will pick up either the manual nudge or the real signal — dropping the
	// duplicate is fine.
	select {
	case winchCh <- syscall.SIGWINCH:
	default:
	}

	// Put ora's stdin into raw mode so keystrokes flow to the child verbatim
	// (otherwise the local terminal cooks input and the child never sees
	// raw arrow keys, Ctrl-C, etc.).
	if term.IsTerminal(int(os.Stdin.Fd())) {
		oldState, rerr := term.MakeRaw(int(os.Stdin.Fd()))
		if rerr == nil {
			defer func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }()
		}
	}

	// stdin → pty (background); pty → stdout (foreground until child exits).
	//
	// We dup ora's stdin fd so we can close OUR copy without affecting the
	// real os.Stdin (the embedder may want to keep using it after RunPTY
	// returns). Closing the dup is the only reliable way to unblock a
	// goroutine sitting in Read on stdin: a closed fd returns EBADF
	// immediately, whereas closing ptmx (the historical approach) only fails
	// the eventual Write and leaves Read blocked until the next keystroke.
	dupFd, err := syscall.Dup(int(os.Stdin.Fd()))
	if err != nil {
		// Best-effort: fall back to the historical bounded-leak path.
		_ = ptmx.Close()
		return fmt.Errorf("dup stdin: %w", err)
	}
	stdinDup := os.NewFile(uintptr(dupFd), "ora-stdin-dup")
	stdinDone := make(chan struct{})
	go func() {
		defer close(stdinDone)
		_, _ = io.Copy(ptmx, stdinDup)
	}()

	_, _ = io.Copy(os.Stdout, ptmx)

	// Close OUR stdin dup first to unblock the goroutine deterministically;
	// then close ptmx; then wait for the goroutine to exit.
	_ = stdinDup.Close()
	_ = ptmx.Close()
	<-stdinDone

	return cmd.Wait()
}
