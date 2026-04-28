package cli

import (
	"fmt"
	"io"
)

// prefixWriter wraps an io.Writer and absorbs per-call error returns, keeping
// the first write error so callers can check it once at the end instead of
// per fmt.Fprintf call. This avoids noisy errcheck violations on diagnostic
// output that is always written to a buffer or stdout.
type prefixWriter struct {
	w   io.Writer
	err error
}

func (pw *prefixWriter) printf(format string, a ...any) {
	if pw.err != nil {
		return
	}
	_, pw.err = fmt.Fprintf(pw.w, format, a...)
}

func (pw *prefixWriter) println(s string) {
	if pw.err != nil {
		return
	}
	_, pw.err = fmt.Fprintln(pw.w, s)
}
