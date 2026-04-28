package orchestrator

import (
	"strings"
	"testing"
)

func TestSanitizeForTerminal_PassesPlainPaths(t *testing.T) {
	t.Parallel()
	for _, in := range []string{
		"/Users/alice/.ssh/id_rsa",
		"/private/var/folders/aa/bb/T/ora-sandbox-01.sb",
		"/path with spaces/file",
		"/Users/alice/résumé.pdf", // multi-byte rune, fully printable
	} {
		if got := sanitizeForTerminal(in); got != in {
			t.Errorf("sanitizeForTerminal(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestSanitizeForTerminal_EscapesC0AndDEL(t *testing.T) {
	t.Parallel()
	// ESC + [2J + [H: clear screen, home cursor — classic ANSI screen-rewrite
	// attempt embedded in a path the sandboxed agent could attempt.
	in := "/tmp/\x1b[2J\x1b[H/exfil"
	got := sanitizeForTerminal(in)
	if strings.Contains(got, "\x1b") {
		t.Errorf("ESC byte not escaped: %q", got)
	}
	if !strings.Contains(got, `\x1b`) {
		t.Errorf("expected literal \\x1b in output; got %q", got)
	}
}

func TestSanitizeForTerminal_EscapesNullAndDEL(t *testing.T) {
	t.Parallel()
	in := "/tmp/\x00null\x7fdel"
	got := sanitizeForTerminal(in)
	for _, banned := range []string{"\x00", "\x7f"} {
		if strings.Contains(got, banned) {
			t.Errorf("control byte %q passed through: %q", banned, got)
		}
	}
	if !strings.Contains(got, `\x00`) || !strings.Contains(got, `\x7f`) {
		t.Errorf("expected \\x00 and \\x7f literals; got %q", got)
	}
}

func TestSanitizeForTerminal_EscapesC1(t *testing.T) {
	t.Parallel()
	// U+009B is CSI (Control Sequence Introducer); on some terminals it is
	// the 8-bit equivalent of ESC [. Use the \u escape so the source stays
	// valid UTF-8 and staticcheck does not flag a raw control byte.
	in := "/tmp/\u009b2K"
	got := sanitizeForTerminal(in)
	if strings.ContainsRune(got, '\u009b') {
		t.Errorf("C1 0x9b not escaped: %q", got)
	}
	if !strings.Contains(got, `\x9b`) {
		t.Errorf("expected \\x9b literal; got %q", got)
	}
}
