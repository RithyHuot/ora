package orchestrator

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
)

// stderrSignatures are case-insensitive substrings that, if present in a
// child's stderr, indicate a sandbox-induced denial. Only English strerror
// strings produced by macOS are matched. Symbolic errno names (EPERM,
// EACCES, EROFS) are intentionally excluded — they don't appear in real
// macOS stderr output and would false-positive on benign substrings like
// `/lib/eaccess.log`.
var stderrSignatures = []string{
	"operation not permitted",
	"permission denied",
	"read-only file system",
}

// StderrClassifier wraps an underlying io.Writer (typically os.Stderr) and
// scans written bytes for sandbox denial signatures. It is safe for use as
// cmd.Stderr in os/exec.Command and safe to read from another goroutine —
// os/exec writes to cmd.Stderr from an internal copy goroutine, so the
// mutex is required to give HasSandboxDenial a happens-before relationship
// with the writer.
type StderrClassifier struct {
	w   io.Writer
	mu  sync.Mutex
	buf bytes.Buffer
	// hasDeny and annotated are guarded by mu.
	hasDeny   bool
	annotated bool
}

// NewStderrClassifier returns a classifier that writes to w.
func NewStderrClassifier(w io.Writer) *StderrClassifier {
	return &StderrClassifier{w: w}
}

// inlineDenialNote is the one-time annotation emitted directly after the
// first stderr line that matches a sandbox signature. Without it, the
// raw "Operation not permitted" / "Permission denied" output looks like
// a generic system error — users miss that ora's sandbox is the cause
// and try things like `sudo` or alternative paths instead of opting in
// to the right path/host. The `[SANDBOX]` prefix matches the
// exit-time `[SANDBOX DENIED]` banner family so users can grep for
// `[SANDBOX` and find every sandbox-emitted line in their output.
const inlineDenialNote = "[SANDBOX] the \"Operation not permitted\" / \"Permission denied\" / \"Read-only file system\" message above is a sandbox denial — see `ora doctor` for opt-ins, or run with --verbose to see which path/host was blocked\n"

// Write implements io.Writer. All bytes are forwarded to the underlying
// writer. The trailing 4 KB of output is scanned for sandbox signatures;
// on the first match a one-time annotation is appended so a bare denial
// line in the child's output doesn't look like a generic system error.
func (c *StderrClassifier) Write(p []byte) (n int, err error) {
	n, err = c.w.Write(p)
	if n > 0 {
		c.mu.Lock()
		c.buf.Write(p[:n])
		if c.buf.Len() > 4096 {
			c.buf.Next(c.buf.Len() - 4096)
		}
		if !c.hasDeny {
			c.hasDeny = containsSignature(c.buf.String())
		}
		// Emit the inline note exactly once, immediately after the
		// matching write. Failure to write the note is non-fatal —
		// the exit-time [SANDBOX DENIED] banner still fires.
		if c.hasDeny && !c.annotated {
			c.annotated = true
			_, _ = fmt.Fprint(c.w, inlineDenialNote)
		}
		c.mu.Unlock()
	}
	return n, err
}

// HasSandboxDenial returns true if any sandbox signature was observed.
func (c *StderrClassifier) HasSandboxDenial() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hasDeny
}

func containsSignature(s string) bool {
	lower := strings.ToLower(s)
	for _, sig := range stderrSignatures {
		if strings.Contains(lower, sig) {
			return true
		}
	}
	return false
}

// classifySandboxFailure returns a human-readable label for the type of
// sandbox boundary that was hit.
func classifySandboxFailure(hasFsDeny bool, networkBlocks int) string {
	switch {
	case hasFsDeny && networkBlocks > 0:
		return "filesystem and network policy boundary"
	case hasFsDeny:
		return "filesystem policy boundary"
	case networkBlocks > 0:
		return "network policy boundary"
	default:
		return "policy boundary"
	}
}
