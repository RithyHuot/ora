//go:build darwin && integration

// Run with: go test -tags integration -fuzz=FuzzGenerateProfile -fuzztime=10s ./pkg/sandbox/...
//
// FuzzGenerateProfile_CompilesUnderSeatbelt asserts that any path that
// passes validatePath produces a profile sandbox-exec accepts. This is the
// load-bearing guarantee of the lit() / escapeSeatbeltLiteral consolidation:
// no validate-passing path should ever yield a malformed S-expression.
package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func FuzzGenerateProfile_CompilesUnderSeatbelt(f *testing.F) {
	f.Add("/Users/me/project")
	f.Add("/path with \"quotes\"")
	f.Add(`/path/with/backslash\here`)
	f.Add(`/p\"q`)
	f.Fuzz(func(t *testing.T, writablePath string) {
		if err := validatePath(writablePath); err != nil {
			t.Skip()
		}
		profile, err := GenerateProfile(ProfileOptions{
			HomeDir:       "/Users/me",
			WritablePaths: []string{writablePath},
		})
		if err != nil {
			t.Skip()
		}
		mandatoryDenyPatterns := []string{
			`.ssh`,
			`.aws`,
			`.env`,
			`.pem`,
			`.key`,
			`id_rsa`,
			`id_ed25519`,
			`.git/hooks`,
		}
		for _, pat := range mandatoryDenyPatterns {
			if !strings.Contains(profile, pat) {
				t.Errorf("profile missing mandatory deny pattern %q", pat)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sandbox-exec", "-f", "/dev/stdin", "/usr/bin/true")
		cmd.Stdin = strings.NewReader(profile)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("profile failed to compile for input %q: %v\n%s", writablePath, err, out)
		}
	})
}
