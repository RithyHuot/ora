// Package providers describes the AI coding CLIs ora knows how to wrap.
// Each ProviderSpec carries the binary name, auth-dir resolver, and
// OwnEnvKeys list that the orchestrator consults when building the
// sandboxed child's spawn environment. The orchestrator strips every key
// in the union of all registered providers' OwnEnvKeys except the invoked
// provider's own, preventing cross-provider credential leaks.
//
// Builtin providers (claude, gemini, codex, opencode, ollama) cannot be
// overridden via Register so a downstream init() cannot weaken their
// security knobs. New providers may be added by calling Register from
// `init()` before any goroutine consults the registry.
//
// Stability: this package is part of ora's public API. Exported symbols
// are stable within a major version.
package providers
