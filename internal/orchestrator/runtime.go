// Package orchestrator owns the per-invocation lifecycle: it reads the
// resolved Config, builds the Seatbelt profile, starts the egress proxy,
// runs the wrapped child, and reports a single RunResult. cli/ wires
// cobra commands; orchestrator/ does the actual work.
package orchestrator

import "context"

// RuntimeOptions holds the persistent flags every ora subcommand reads.
// Values are bound by cli.NewRootCommand and stashed on cmd.Context() so
// nothing needs to live as a package-level mutable global.
type RuntimeOptions struct {
	Verbose             bool
	JSON                bool
	AdHocAllowedDomains []string
}

type runtimeKey struct{}

// WithRuntimeOptions returns a context carrying opts.
func WithRuntimeOptions(ctx context.Context, opts *RuntimeOptions) context.Context {
	return context.WithValue(ctx, runtimeKey{}, opts)
}

// RuntimeFromContext returns the options previously attached, or a zero
// value (everything off, no extra domains) when nothing was attached.
func RuntimeFromContext(ctx context.Context) *RuntimeOptions {
	if v, ok := ctx.Value(runtimeKey{}).(*RuntimeOptions); ok && v != nil {
		return v
	}
	return &RuntimeOptions{}
}
