package sandbox

import (
	"strings"
	"testing"
)

func TestSeatbelt_NameIsStable(t *testing.T) {
	if name := (Seatbelt{}).Name(); name != "seatbelt" {
		t.Errorf("Name() = %q, want %q", name, "seatbelt")
	}
}

func TestSeatbelt_WrapInvokesSandboxExec(t *testing.T) {
	bin, args := (Seatbelt{}).Wrap("/tmp/profile.sb", "/bin/echo", []string{"hi"})
	if !strings.HasSuffix(bin, "sandbox-exec") {
		t.Errorf("Wrap should invoke sandbox-exec, got %q", bin)
	}
	wantArgs := []string{"-f", "/tmp/profile.sb", "/bin/echo", "hi"}
	if len(args) != len(wantArgs) {
		t.Fatalf("argv length: got %v, want %v", args, wantArgs)
	}
	for i, w := range wantArgs {
		if args[i] != w {
			t.Errorf("argv[%d]: got %q, want %q", i, args[i], w)
		}
	}
}

func TestDefaultBackend_IsSeatbelt(t *testing.T) {
	if _, ok := DefaultBackend().(Seatbelt); !ok {
		t.Errorf("DefaultBackend() should be Seatbelt, got %T", DefaultBackend())
	}
}
