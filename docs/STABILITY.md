# API Stability

`ora` is a CLI first and a library second. Most users invoke it from the
shell; the Go API surface under `pkg/` exists for embedders who want to
reuse the sandbox primitives or the egress proxy in their own tools.

This document tracks what's stable, what's not, and what's intentionally
unexported.

## Stable

These exported symbols are intended to form ora's v1.x public API. They are
stable as of v0.1.0; until v1.0 is tagged, breaking changes are still
possible but each will be called out in CHANGELOG.md. After v1.0, breaking
changes require a major-version bump.

### `pkg/sandbox`

- `Backend` interface (`Name`, `Wrap`)
- `Seatbelt` struct + `DefaultBackend()`
- `DefaultPolicy()`, `Policy` struct, `Policy.HomeDenies / WorkspaceDenies / GlobalDenies`
- `DenyEntry`, `DenyKind`, `DenyScope` types
  - `DenyKind.String`, `DenyKind.MarshalJSON`, `DenyKind.UnmarshalJSON`
  - `DenyScope.String`, `DenyScope.MarshalJSON`, `DenyScope.UnmarshalJSON`
- `ProfileOptions` struct + `GenerateProfile`
- `ProfilePolicy` struct
- `ParseSandboxLogLine`, `SandboxDenyEvent`
- `ErrLogMonitorUnsupported`
- `StartLogMonitor`, `SelfTestLogStream` (macOS-only at runtime; will move
  onto `Backend` if a non-macOS backend lands)
- `DetectGitCommonDir`, `DetectNodeBinDir`, `DetectHomebrewRoots`,
  `DetectVersionMgrDirs`, `ExistingPaths`

### `pkg/proxy`

- `Egress` struct (only the documented exported fields are stable;
  `testPorts` is unexported and never part of the API)
- `Egress.Start(ctx)`, `Egress.Stop()`, `Egress.NetworkBlocks()`
- `ParentProxy`, `ResolveParentProxy`, `ParentProxy.HasEmbeddedCredentials()`
- `ValidateAllowedDomain`, `ValidateAllowedDomains`
- `DefaultMaxConcurrentTunnels`, `DefaultTunnelIdleTimeout`,
  `DefaultShutdownTimeout`

### `pkg/providers`

- `ProviderSpec` struct
- `ProviderSpec.IsBuiltin()`
- `AuthResolver` type
- `AuthDirEntry` struct, `AuthDirKind` type (`AuthDirKindDir`, `AuthDirKindFile`)
- `Lookup`, `Register`, `Unregister`, `Names`, `Detect(name)`
- `AllOwnedEnvKeys`, `NoAuth`

### `pkg/denials`

- `Sink` interface, `Event` struct, `Kind` type
- `Kind` constants: `KindNetwork`, `KindFs`, `KindStderrSignature`
- `Kind.String`, `Kind.MarshalJSON`, `Kind.UnmarshalJSON`
- `Discard` sink

`Event` JSON shape (pinned via struct tags):

```json
{"kind":"network","host":"…","port":443,"reason":"not_allowlisted"}
{"kind":"fs","operation":"file-write-create","path":"/…"}
{"kind":"stderr","snippet":"…"}
```

Unset fields are omitted via `omitempty`.

## Intentionally unexported

These were considered for export and rejected; documenting the choice
prevents the next contributor from "fixing" them.

- `pkg/proxy.compileMatcher` / `hostMatcher` — internal to the package;
  external callers compose via `Egress.Allowed` instead.
- `pkg/sandbox.sandboxExecPath` — implementation detail of `Seatbelt.Wrap`.
- `pkg/sandbox.isSymlinkOutsideBoundary` — path boundary checks are an
  internal detail of profile generation; the rules may need to change for
  a future Linux/Landlock backend.
- `pkg/providers.claudeAuthDirs`, `geminiAuthDirs`, `codexAuthDirs`,
  `opencodeAuthDirs` — callers use `Lookup(name).AuthDirsRW(home, env)`
  instead. Exporting these would lock four function signatures into v1.0
  with no extension headroom.
- `pkg/providers.providerSpec.builtin` — use the `ProviderSpec.IsBuiltin()`
  method instead. The field is set internally by `Register`; struct-literal
  callers cannot meaningfully control it.
- `pkg/proxy.ParentProxy.authHeader` — credentials are forwarded
  internally; external consumers use `ParentProxy.HasEmbeddedCredentials()`
  to check for their presence. Exposing the raw header would let a
  struct-literal caller bypass the base64 invariant.
- `pkg/sandbox.mandatoryDeny*` / `workspaceDeny*` slices — read via
  `DefaultPolicy()` accessors so the deny dataset is not a mutable global.
- `pkg/providers` registry map — `Lookup` / `Register` / `Unregister` /
  `Names` accessors guard concurrent mutation with a `sync.RWMutex`.

## Internal-only (not stable)

Anything under `internal/` (orchestrator, cli, exec, config, trust,
session, events) is not part of the public API. ora can rename, move, or
remove these between any two releases.

## Versioning

ora follows semver. Until v1.0.0 the API may change without major-version
bumps; a CHANGELOG entry will note any breaking change. After v1.0.0,
breaking changes to the symbols listed under "Stable" above require a
major-version bump.

## Recent breaking changes (pre-1.0)

- `pkg/sandbox.DetectNodeBinDir` now returns `[]string` and takes two
  additional parameters: `providerName string` (the canonical CLI name,
  used to find the wrapper's delegate by searching PATH) and `home string`
  (the user's HOME directory, used to classify resolved symlink targets
  as safe). Callers that previously did
  `NodeBinDir: sandbox.DetectNodeBinDir(bin, logger)` now write
  `NodeBinDirs: sandbox.DetectNodeBinDir(bin, name, home, logger)`. Pass
  `""` for either string to disable the corresponding lookup branch.
- `pkg/sandbox.ProfileOptions.NodeBinDir string` renamed to `NodeBinDirs
  []string`. Existing struct-literal callers must wrap their value in a
  slice.

Both changes were made to support real-world installer layouts where the
provider-binary symlink target lives outside the bin dir's own subtree
(Anthropic claude, npm Node CLIs, Bun standalones in Homebrew Cellar).
The previous boundary check rejected nearly every legitimate symlink, then
fell back to a dirname that didn't include the actual binary, causing the
wrapped CLI to die at runtime when trying to read its own executable.

## Audit log

This document was last reconciled against `go doc -all` on 2026-04-27.
When making any change to a `pkg/` exported symbol, update this file in
the same commit. Run `go doc -all ./pkg/...` and grep against this file
to catch drift.
