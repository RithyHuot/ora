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
)

// forwardedSignals lists every signal ora forwards to the wrapped child's
// process group. SIGTSTP/SIGCONT must be forwarded so the child can be
// backgrounded and resumed normally; without them Ctrl-Z stops only ora,
// detaching the child. SIGQUIT is forwarded so Ctrl-\ produces a stack
// trace of the wrapped CLI rather than ora itself.
var forwardedSignals = []os.Signal{
	syscall.SIGINT,
	syscall.SIGTERM,
	syscall.SIGHUP,
	syscall.SIGQUIT,
	syscall.SIGTSTP,
	syscall.SIGCONT,
}

// RunWithSignals starts bin with args and env, forwarding os signals to the
// process group. On context cancellation, the process group is killed via
// exec.CommandContext (which delivers SIGKILL via the os/exec package).
// There is no separate SIGTERM grace period.
//
// stderr receives the child's stderr output. Pass os.Stderr for the default
// behavior; pass a custom writer (e.g. a classifier) to inspect stderr.
func RunWithSignals(ctx context.Context, bin string, args []string, env []string, cwd string, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = stderr
	cmd.Env = env
	cmd.Dir = cwd
	if runtime.GOOS != "windows" {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	// Defensively call Setpgid in case the kernel hasn't picked up the
	// SysProcAttr request yet — idempotent if already set.
	if runtime.GOOS != "windows" {
		_ = syscall.Setpgid(cmd.Process.Pid, cmd.Process.Pid)
	}
	pgid := cmd.Process.Pid

	// Register signal forwarding AFTER Start so a signal arriving in the
	// race window (before the child exists) doesn't get sent to pgid=0,
	// which would kill ora itself.
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, forwardedSignals...)
	defer signal.Stop(sigCh)

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	for {
		select {
		case sig := <-sigCh:
			// Send to the group (negative pid). Errors ignored — the group may
			// be partially exited already.
			if runtime.GOOS != "windows" {
				_ = syscall.Kill(-pgid, sig.(syscall.Signal))
			} else {
				_ = cmd.Process.Signal(sig)
			}
			// After forwarding SIGTSTP to the child group, stop ora itself
			// so the shell sees the foreground process group stop and the
			// prompt returns. We use SIGSTOP (uncatchable) rather than
			// resending SIGTSTP because signal.Notify is still active and
			// would re-enter this branch. On SIGCONT from `fg`, the runtime
			// resumes this goroutine and SIGCONT is delivered through sigCh
			// in a future iteration, which forwards to the child.
			if sig == syscall.SIGTSTP && runtime.GOOS != "windows" {
				_ = syscall.Kill(syscall.Getpid(), syscall.SIGSTOP)
			}
		case err := <-done:
			return err
		}
	}
}
