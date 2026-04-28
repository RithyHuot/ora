package sandbox

// Backend isolates the kernel-level sandbox primitive. Today there is one
// implementation (Seatbelt on macOS); the interface exists to document the
// boundary so a future Linux/Landlock backend can slot in without rewriting
// callers.
type Backend interface {
	// Name returns a stable identifier for diagnostics ("seatbelt").
	Name() string
	// Wrap returns the argv that runs bin under the profile at profilePath.
	Wrap(profilePath, bin string, args []string) (string, []string)
}

// Seatbelt is the macOS implementation of Backend. The zero value is
// usable.
type Seatbelt struct{}

// Name implements Backend.
func (Seatbelt) Name() string { return "seatbelt" }

// sandboxExecPath is the absolute path to Apple's sandbox-exec on every
// supported macOS release.
const sandboxExecPath = "/usr/bin/sandbox-exec"

// Wrap implements Backend.
func (Seatbelt) Wrap(profilePath, bin string, args []string) (string, []string) {
	out := make([]string, 0, 3+len(args))
	out = append(out, "-f", profilePath, bin)
	out = append(out, args...)
	return sandboxExecPath, out
}

// DefaultBackend returns the Backend ora uses on the current platform.
// Today this is always Seatbelt; on a hypothetical Linux build a
// Landlock implementation would be returned here.
func DefaultBackend() Backend { return Seatbelt{} }
