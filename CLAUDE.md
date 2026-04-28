# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`ora` is a single Go binary that wraps an AI coding CLI (`claude`, `gemini`, `codex`, `opencode`, `ollama`) in a per-invocation macOS Seatbelt (`sandbox-exec`) sandbox. There are no daemons and no persisted state between runs — each invocation generates a fresh profile, starts a loopback HTTPS-CONNECT proxy, spawns the wrapped CLI, and tears everything down on exit.

**Platform:** macOS-only at runtime. Most code is portable Go and tests run on any OS, but anything that touches `sandbox-exec` or `log stream` requires darwin.

## Common commands

```sh
make build       # → bin/ora (with version from `git describe`)
make test        # go test ./...                       (portable unit tests)
make test-int    # go test -tags=integration ./...     (macOS only)
make lint        # golangci-lint run
make install     # go install to $GOPATH/bin
make snapshot    # goreleaser local build, no publish
```

Run a single package's tests:

```sh
go test ./pkg/proxy/...
go test -run TestEgress_DeniesUnlistedHost ./pkg/proxy/...
```

Integration tests live behind two build-tag patterns and **do not run with plain `go test ./...`**:
- `//go:build integration` (e.g. `pkg/proxy/integration_test.go`)
- `//go:build darwin && integration` (e.g. `internal/orchestrator/sandbox_denied_integration_test.go`) — these spawn real `sandbox-exec` and require macOS.

`internal/exec/pty_test.go` is `//go:build darwin` (no integration tag) and is skipped automatically on non-darwin hosts.

## Architecture

The full lifecycle is documented in `docs/ARCHITECTURE.md`. The minimum to be productive:

### Layout: `pkg/` is public API, `internal/` is private

| Path | Stable? | What it does |
|---|---|---|
| `cmd/ora` | — | Entry point; `version` injected via ldflags |
| `pkg/sandbox` | **Public** | `Backend` interface, `Seatbelt` impl, `GenerateProfile`, `DefaultPolicy`, log monitor |
| `pkg/proxy` | **Public** | `Egress` (loopback HTTPS-CONNECT), `ValidateAllowedDomain`, parent-proxy chaining |
| `pkg/providers` | **Public** | `ProviderSpec`, `Registry`, `Register`/`Lookup`/`Names`, per-provider auth resolvers |
| `pkg/denials` | **Public** | `Sink` interface + `Event` taxonomy used by every denial source |
| `internal/cli` | private | Cobra commands (`root`, `run`, `doctor`, `policy`, `shell`, `trust`) |
| `internal/orchestrator` | private | `Runner.Run()` — per-invocation lifecycle; `StderrClassifier` |
| `internal/config` | private | TOML + env precedence merge, trust gate for project `.ora.toml` |
| `internal/trust` | private | TOFU trust DB at `~/.config/ora/trust.toml` |
| `internal/session`, `internal/exec`, `internal/events` | private | ULID + LIFO cleanup; spawn env/PTY/signals; JSON-Lines emitter |

**`pkg/` symbols listed in `docs/STABILITY.md` are part of the v1.x API contract.** Changes there must be flagged in PR descriptions and `CHANGELOG.md`. `internal/` may be reorganized freely.

### Per-invocation flow (one `ora claude --model opus`)

1. `internal/config.Resolve` merges CLI flags → project `.ora.toml` (walks to git root, **gated by `internal/trust`**) → user `~/.config/ora/config.toml` → env vars → defaults. Slice fields concatenate; scalars use first-set-wins.
2. `pkg/providers.Lookup` finds the spec; `exec.LookPath` resolves the binary; auth dirs are filtered to existing-only.
3. Workdir resolves: `ORA_WORKDIR` > `workdir_scope = "git_root"` (walks to `.git`) > cwd. Linked worktrees also get the shared `.git` common dir added.
4. `internal/session.New()` mints a ULID and profile path; `OnCleanup` registers teardown hooks (LIFO).
5. `pkg/proxy.Egress.Start` binds `127.0.0.1:0`, compiles the domain matcher, optionally chains through host `HTTPS_PROXY`. Rejects non-CONNECT, non-443, non-allowlisted.
6. `pkg/sandbox.GenerateProfile` (pure function) emits the Seatbelt S-expression; written `0600`.
7. `internal/exec.BuildSpawnEnv` strips secret env vars and other providers' API keys, injects `HTTPS_PROXY` pointing at the loopback proxy.
8. `sandbox-exec -f <profile> <bin> <args>` is spawned via `internal/exec.RunWithSignals` (process group + SIGINT/SIGTERM forwarding; `script(1)` PTY wrap when stdin is a TTY).
9. Three denial producers feed one `denials.Sink`: `proxy.Egress` (network), `sandbox.StartLogMonitor` (FS, only with `--verbose`), `orchestrator.StderrClassifier` (stderr signature). `events.Emitter` translates to JSON-Lines when `--json` is set.
10. Deferred cleanup stops the proxy (2s graceful, then force) and deletes the profile.

### Profile structure (in `pkg/sandbox`)

Three layers, evaluated in order:
1. **Capability grants** — `process-exec`, `process-fork`, loopback-only network, etc.
2. **Path allows** — workspace, auth dirs, system read-only, Homebrew, version managers, Node bin, temp, `/dev/null`, PTY.
3. **Mandatory denies** — applied **after** all allows so a later `deny` overrides an earlier `allow`. Includes home-relative (`.ssh`, `.aws`, shell rc, `.git-credentials`), regex (`*.env`, `*.pem`, `*.key`, `id_rsa*`, `id_ed25519*`), workspace-relative (`.git/hooks`, `.gitmodules`, `.mcp.json`, `.git/config` unless opted in), and **ancestor `file-write-create` denies** to prevent symlink-bypass.

## Invariants worth knowing

These are easy to break by accident — preserve them.

- **`NativeKernel` is not subject to the config merge.** It can only be set by `LoadEnv` and only when `ORA_I_UNDERSTAND_UNSANDBOXED=1` is also set. Project or user TOML files cannot disable the sandbox. Do not "fix" this by adding it to the merge.
- **Project `.ora.toml` is untrusted by default.** `internal/config.Resolve` consults `~/.config/ora/trust.toml` for a SHA-256 match. Untrusted or hash-mismatched configs return an error. `ORA_TRUST_PROJECT_CONFIG=1` bypasses for CI. If the file changes, trust must be re-granted.
- **Domain validation is strict.** Every entry through `proxy.ValidateAllowedDomain` rejects `*.com`, bare wildcards, IDN, and entries with embedded scheme/port/path. ASCII Punycode only.
- **Mandatory denies live `pkg/sandbox.DefaultPolicy()`.** Adding a path to "always deny" goes here, not into a one-off allow site.
- **Cross-provider env stripping is automatic.** Every provider's `OwnEnvKeys` is stripped when running a *different* provider. When adding a provider, fill in `OwnEnvKeys` accurately — that field is what protects users from cross-provider key leaks. Always-strip credentials (`AWS_*`, `SSH_AUTH_SOCK`, `VAULT_TOKEN`, `DYLD_*`, `NODE_OPTIONS`, etc.) live in `internal/exec.alwaysStripKeys`, **not** on the spec.
- **`Register()` refuses to overwrite a builtin provider.** Out-of-tree code cannot weaken `OwnEnvKeys` for `claude`/`gemini`/`codex`/`opencode`/`ollama`.
- **Fail-closed.** Missing `sandbox-exec`, profile compile failure, or proxy bind failure must exit non-zero with a remediation hint. Never silently downgrade to unsandboxed.
- **Stderr classifier signatures are case-insensitive English only.** `operation not permitted` / `permission denied` / `read-only file system`. Numeric `errno N` is intentionally NOT matched (false-positive rate). Non-English locales are accepted as out of scope.

## Adding a new provider

1. Add an `AuthResolver` in `pkg/providers/auth.go`.
2. Add an entry to `pkg/providers.registry` in `pkg/providers/registry.go` with `Name`, `BinNames`, `AuthDirsRW`, `LoginCommand`, `OwnEnvKeys` (vendor's API keys), `ProbeHost`, `builtin: true`. Optionally:
   - `AllowedDomains` — domains the CLI requires beyond the global default list (e.g. a hosted catalog like opencode's `models.dev`). Each entry is validated through `proxy.ValidateAllowedDomain`.
   - `EnvDefaults` — KEY=VAL pairs to set unless the user already did. Use sparingly — these change wrapped-CLI behavior. Current example: `DISABLE_TELEMETRY=1` for claude to suppress its Datadog flush.
3. Tests in `pkg/providers/registry_test.go` and `pkg/providers/auth_test.go`.

Out-of-tree providers register at runtime via `providers.Register(spec)` — see `CONTRIBUTING.md` for the example.

## Updating docs alongside code

When a change touches the categories below, update the corresponding doc in the **same PR** (and same commit when practical). Reviewers will catch missing entries — adding them after the fact creates churn.

| If you change… | Update |
|---|---|
| Add/remove/rename an exported `pkg/` symbol (function, type, struct field, constant) | `docs/STABILITY.md` — "Stable" list under the right `pkg/` heading, **and** bump the "last reconciled" date in the `Audit log` section at the bottom. Breaking renames or signature changes also go in "Recent breaking changes (pre-1.0)". |
| Add/remove/modify a path-allow or path-deny in the generated profile | `docs/ARCHITECTURE.md` — "Profile anatomy" → Layer 2 (allows) or Layer 3 (denies). Mention *why* the grant exists (which CLI / call needs it) — that's what readers come for. |
| Fix a user-visible bug, change CLI behavior, add a feature, or change defaults | `CHANGELOG.md` `[Unreleased]` — `### Fixed` / `### Added` / `### Changed`. Match the existing prose style: explain the *why* and the *symptom*, not just the diff. |
| Add a config knob (env var, `.ora.toml` field, CLI flag) | `docs/CONFIGURATION.md` plus `CHANGELOG.md` `### Added`. |
| Tighten or weaken a security boundary | `docs/SECURITY.md` ("Security boundaries" table in `docs/ARCHITECTURE.md` mirrors this — keep them consistent) plus `CHANGELOG.md`. |
| Add/change error handling or exit-code semantics | `docs/SANDBOX_ERROR_BEHAVIOR.md`. |
| Add a new provider | `pkg/providers/registry.go` + tests; the `## Adding a new provider` section above already lists the hot path. No separate doc, but mention in `CHANGELOG.md` `### Added`. |
| Change release tooling, goreleaser config, or CI | `docs/RELEASE.md`. |
| Edit an example in the README's "Denied by default" / allow tables | Verify the example path is actually denied/allowed by the current profile before merging — run `ora policy show` or check `pkg/sandbox/profile.go` and `DefaultPolicy()`. The default `/tmp` allow tripped this once: `echo x > /tmp/outside` looks denied but isn't. |

If a change crosses multiple categories (e.g. a fix that adds a new exported helper and changes the profile), update each doc — they exist for different audiences (embedders read STABILITY, operators read ARCHITECTURE, users read CHANGELOG).

### When tagging a release

Tagging `vX.Y.Z` is not just `git tag`. In the same commit (or release PR):

1. Cut `CHANGELOG.md` `[Unreleased]` into a dated `## [X.Y.Z] - YYYY-MM-DD` section. Leave `[Unreleased]` as just the header (no `### Added` / `### Fixed` subsections) until the next user-visible change lands.
2. Add a compare-link ref at the bottom: `[X.Y.Z]: https://github.com/rithyhuot/ora/releases/tag/vX.Y.Z`. Update the `[Unreleased]` ref to compare against the new tag: `compare/vX.Y.Z...HEAD`.
3. Bump `VERSION=vX.Y.Z` shell examples in `README.md` (cosign-verify block, install snippets) so copy-paste users land on a real release.

Skipping any of these is what makes `[Unreleased]` grow into a multi-release blob — v0.2.0 / v0.2.1 / v0.2.2 all shipped without cutting, and the catch-up was a separate doc PR. Cut at tag time, not later.

## Linter notes

`.golangci.yml` intentionally suppresses some rules:
- `gosec` G204/G306/G115 — this project's whole job is `exec`'ing user-supplied tools and writing world-readable profiles to predictable paths.
- `gocritic` `ifElseChain`/`hugeParam`/`paramTypeCombine` — too noisy.
- `noctx` is suppressed for `pkg/proxy/proxy.go` because the CONNECT path uses `net.DialTimeout` for clear per-tunnel timeout semantics.
- `_test.go` files get a blanket `gosec`/`noctx`/`bodyclose` exemption.

Don't paper over a new finding by extending these exclusions — fix the code unless there's a real reason.

## Go version

`go.mod` is `go 1.23.0` — the floor for `go install`. CI runs the build against 1.23 / 1.24 / 1.25.
