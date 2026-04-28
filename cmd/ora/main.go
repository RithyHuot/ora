// Package main is the entry point for the ora CLI.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/rithyhuot/ora/internal/cli"
)

// version is injected via -ldflags at build time (Makefile / goreleaser).
// `go install github.com/rithyhuot/ora/cmd/ora@vX.Y.Z` does not apply ldflags,
// so resolveVersion falls back to the module version embedded by the Go
// toolchain in that case.
var version = "dev"

func resolveVersion() string {
	return resolveVersionFrom(version, debug.ReadBuildInfo)
}

func resolveVersionFrom(injected string, readBuildInfo func() (*debug.BuildInfo, bool)) string {
	if injected != "dev" {
		return injected
	}
	if info, ok := readBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return injected
}

func main() {
	// The carrier defaults to 0; runWrapped sets it to the wrapped child's
	// actual exit code. cobra-internal commands (--version, --help, unknown
	// flag) never call runWrapped, so they keep the default — we override
	// to 1 only when Execute returns an error.
	carrier := &cli.ExitCodeCarrier{Code: 0}
	ctx := cli.WithExitCodeCarrier(context.Background(), carrier)
	root := cli.NewRootCommand(resolveVersion())
	if err := root.ExecuteContext(ctx); err != nil {
		if !errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "ora:", err)
		}
		if carrier.Code == 0 {
			carrier.Code = 1
		}
	}
	os.Exit(carrier.Code)
}
