//go:build darwin

package sandbox

import "testing"

// FuzzParseSandboxLogLine exercises ParseSandboxLogLine against arbitrary
// inputs. Apple has changed the unified-log compact format more than once;
// the parser must never panic regardless of what shows up.
func FuzzParseSandboxLogLine(f *testing.F) {
	seeds := []string{
		"",
		"unrelated log line",
		"sandboxd[123]: deny(1) file-read /Users/me/.ssh/id_rsa",
		"2026-04-26 10:00:00.000 sandboxd[123]: deny(1) network-outbound 1.2.3.4:443",
		"sandboxd[1]: deny(99) file-write* /private/etc/foo  <process: claude[42]>",
		"sandboxd[99]: deny(1) file-read /tmp/with space.txt",
		"sandboxd[99]: deny(0)\tfile-read\t/tmp/tabs",
		"DENY(1) file-read /case-sensitive",
		"\x00malformed\x00binary",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		_, _ = ParseSandboxLogLine(line) // must not panic
	})
}
