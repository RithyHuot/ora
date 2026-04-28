package sandbox_test

import (
	"fmt"
	"os"

	"github.com/rithyhuot/ora/pkg/sandbox"
)

func ExampleGenerateProfile() {
	home, _ := os.UserHomeDir()
	profile, err := sandbox.GenerateProfile(sandbox.ProfileOptions{
		HomeDir:       home,
		WritablePaths: []string{"/tmp/my-project"},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate: %v\n", err)
		return
	}
	fmt.Printf("profile length: %d bytes\n", len(profile))
}
