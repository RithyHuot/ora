// Package main is the entry point for the ora CLI.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/rithyhuot/ora/internal/cli"
)

// version is injected via -ldflags at build time.
var version = "dev"

func main() {
	// The carrier defaults to 0; runWrapped sets it to the wrapped child's
	// actual exit code. cobra-internal commands (--version, --help, unknown
	// flag) never call runWrapped, so they keep the default — we override
	// to 1 only when Execute returns an error.
	carrier := &cli.ExitCodeCarrier{Code: 0}
	ctx := cli.WithExitCodeCarrier(context.Background(), carrier)
	root := cli.NewRootCommand(version)
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
