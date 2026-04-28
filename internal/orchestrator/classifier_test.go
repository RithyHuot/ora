package orchestrator

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestStderrClassifier_ForwardsOutput(t *testing.T) {
	var buf bytes.Buffer
	c := NewStderrClassifier(&buf)

	n, err := c.Write([]byte("hello world"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 11 {
		t.Errorf("n = %d, want 11", n)
	}
	if got := buf.String(); got != "hello world" {
		t.Errorf("buf = %q, want %q", got, "hello world")
	}
}

func TestStderrClassifier_DetectsOperationNotPermitted(t *testing.T) {
	var buf bytes.Buffer
	c := NewStderrClassifier(&buf)

	_, _ = c.Write([]byte("some normal output\n"))
	if c.HasSandboxDenial() {
		t.Error("should not flag normal output")
	}

	_, _ = c.Write([]byte("sh: /path/file: Operation not permitted\n"))
	if !c.HasSandboxDenial() {
		t.Error("should flag 'Operation not permitted'")
	}
}

func TestStderrClassifier_DetectsPermissionDenied(t *testing.T) {
	var buf bytes.Buffer
	c := NewStderrClassifier(&buf)

	_, _ = c.Write([]byte("Error: Permission denied\n"))
	if !c.HasSandboxDenial() {
		t.Error("should flag 'Permission denied'")
	}
}

func TestStderrClassifier_DetectsReadOnlyFileSystem(t *testing.T) {
	var buf bytes.Buffer
	c := NewStderrClassifier(&buf)

	_, _ = c.Write([]byte("mkdir: Read-only file system\n"))
	if !c.HasSandboxDenial() {
		t.Error("should flag 'Read-only file system'")
	}
}

func TestStderrClassifier_DoesNotFlagSymbolicErrno(t *testing.T) {
	cases := []string{
		"open(/etc/foo): EACCES",
		"write failed: EPERM",
		"mkdir: EROFS",
	}
	for _, s := range cases {
		var buf bytes.Buffer
		c := NewStderrClassifier(&buf)
		_, _ = c.Write([]byte(s + "\n"))
		if c.HasSandboxDenial() {
			t.Errorf("should NOT flag symbolic errno in %q", s)
		}
	}
}

func TestStderrClassifier_DoesNotFlagBenignSubstrings(t *testing.T) {
	t.Parallel()
	cases := []string{
		"loaded /lib/eaccess.so\n",
		"writing to teach-mode.log\n",
		"reading user-eperm.json\n",
	}
	for _, in := range cases {
		c := NewStderrClassifier(io.Discard)
		_, _ = c.Write([]byte(in))
		if c.HasSandboxDenial() {
			t.Errorf("benign input %q flagged as deny", in)
		}
	}
}

func TestStderrClassifier_CaseInsensitive(t *testing.T) {
	var buf bytes.Buffer
	c := NewStderrClassifier(&buf)

	_, _ = c.Write([]byte("OPERATION NOT PERMITTED\n"))
	if !c.HasSandboxDenial() {
		t.Error("should flag uppercase variant")
	}
}

func TestStderrClassifier_NoFalsePositive(t *testing.T) {
	var buf bytes.Buffer
	c := NewStderrClassifier(&buf)

	// Each phrase contains a near-miss substring that the classifier must
	// NOT match: "permission granted" shares "permission" with "permission
	// denied"; "not permitted to enter the building" shares "not permitted"
	// with "operation not permitted" but lacks the leading "operation".
	phrases := []string{
		"build succeeded",
		"permission granted",
		"operation completed successfully",
		"not permitted to enter the building",
	}
	for _, p := range phrases {
		_, _ = c.Write([]byte(p + "\n"))
		if c.HasSandboxDenial() {
			t.Errorf("false positive for %q", p)
		}
	}
}

func TestStderrClassifier_RollingBuffer(t *testing.T) {
	var buf bytes.Buffer
	c := NewStderrClassifier(&buf)

	// Write a lot of normal text first.
	large := strings.Repeat("a", 5000)
	_, _ = c.Write([]byte(large))
	if c.HasSandboxDenial() {
		t.Error("should not flag plain text")
	}

	// Now write the denial. The classifier keeps the last 4 KB, so this
	// should still be detected even though the total written exceeds 4 KB.
	_, _ = c.Write([]byte("Operation not permitted"))
	if !c.HasSandboxDenial() {
		t.Error("should flag denial in rolling window")
	}
}
