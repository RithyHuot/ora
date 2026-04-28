# Release Process

This document describes how to release `ora` binaries.

## Prerequisites

- Go 1.23+
- [GoReleaser](https://goreleaser.com/install/) (for local releases)
- GitHub repository with `GITHUB_TOKEN` or `GH_TOKEN` env var set

## Automated release (recommended)

Use `make release` to prep the release commit and tag, then push to trigger
the GitHub Actions release workflow:

```bash
# 1. Sync main
git checkout main
git pull origin main

# 2. Prep the release: cuts CHANGELOG.md [Unreleased] into a dated
#    ## [X.Y.Z] section, bumps VERSION=vX.Y.Z in README.md, runs lint
#    and tests, asks for confirmation, then commits and tags.
make release VERSION=vX.Y.Z

# 3. Push the commit and tag — the tag push is what triggers the
#    release workflow, so this step is intentionally manual.
git push origin main
git push origin vX.Y.Z
```

If `make release` refuses, fix the reported gate (e.g. `[Unreleased]` is
empty, working tree dirty, branch out of sync) and re-run. To skip the
interactive confirmation in scripted contexts, set `RELEASE_YES=1` or pass
`--yes` directly to `scripts/release.sh`.

The `.github/workflows/release.yml` workflow will:

1. Check out the tag
2. Run tests
3. Build `darwin/amd64` and `darwin/arm64` binaries via GoReleaser
4. Create a **draft** GitHub Release with:
   - `ora_vX.Y.Z_darwin_amd64.tar.gz`
   - `ora_vX.Y.Z_darwin_arm64.tar.gz`
   - `checksums.txt`
   - `checksums.txt.bundle`

After the workflow completes, review the draft release on GitHub and publish it.

## Manual release (local)

If you need to publish a release from your local machine instead of CI
(e.g. the workflow is broken and you need to ship now):

```bash
# 1. Prep and tag the same way as the automated flow.
make release VERSION=vX.Y.Z

# 2. Set your GitHub token so GoReleaser can create the draft release.
export GITHUB_TOKEN=$(gh auth token)

# 3. Push so the tag exists on origin (GoReleaser reads it from origin).
git push origin main
git push origin vX.Y.Z

# 4. Run GoReleaser locally. Requires syft and cosign on $PATH —
#    install via `brew install syft cosign` if missing.
make release-publish

# Snapshot build (no tag, no publish — useful for verifying the
# goreleaser config or generating local artifacts):
make snapshot
```

## Version numbering

Follows [Semantic Versioning](https://semver.org/):

- **MAJOR** — Breaking changes to CLI interface, config format, or sandbox behavior
- **MINOR** — New providers, new config options, new commands
- **PATCH** — Bug fixes, doc updates, security hardening

## Pre-release checklist

`make release` enforces most of these as preflight gates and refuses to
continue if any fail. The remaining items (marked *manual*) are not
automatable and need eyeballs:

- [x] `make test` passes — gated by `make release`
- [x] `make lint` passes — gated by `make release`
- [x] `CHANGELOG.md` `[Unreleased]` is non-empty — gated by `make release`
- [x] `README.md` `VERSION=v…` example bumped — done by `make release`
- [ ] **manual:** `make test-int` passes (macOS only; integration tests
      are not run by `make release`)
- [ ] **manual:** `make build` produces a working binary
- [ ] **manual:** smoke-tested `ora claude` (or another provider) against
      a non-trivial repo to confirm no spurious `[SANDBOX DENIED]` banners
- [ ] **manual:** `docs/STABILITY.md` audit-log date is current if any
      `pkg/` symbol changed since the last tag
- [ ] **manual:** `docs/ARCHITECTURE.md` profile-anatomy section reflects
      any new path allow / deny landed since the last tag

## Artifacts

Each release produces:

| Artifact | Description |
|---|---|
| `ora_vX.Y.Z_darwin_amd64.tar.gz` | Intel Mac binary |
| `ora_vX.Y.Z_darwin_arm64.tar.gz` | Apple Silicon binary |
| `checksums.txt` | SHA256 checksums |
| `checksums.txt.bundle` | Cosign signature bundle for verifying `checksums.txt` |
| `ora_vX.Y.Z_darwin_amd64.tar.gz.sbom.json` | Syft SBOM (SPDX JSON) for the Intel archive |
| `ora_vX.Y.Z_darwin_arm64.tar.gz.sbom.json` | Syft SBOM (SPDX JSON) for the Apple Silicon archive |

Both archives contain:
- `ora` — the compiled binary
- `LICENSE`
- `README.md`

## Troubleshooting

### "dirty git state" error from GoReleaser

Ensure working tree is clean: `git status` should show nothing.

### Integration tests fail on CI

Integration tests require macOS + `sandbox-exec`. They are skipped on non-darwin. Ensure the release workflow runs on `macos-latest`.

### Draft release not created

GoReleaser creates drafts by default (see `.goreleaser.yml: draft: true`). You must manually publish the release on GitHub.

### `exec: "syft": executable file not found in $PATH` (or same for `cosign`)

`.goreleaser.yml` declares per-archive SBOMs (`sboms:`) and keyless cosign
signing of `checksums.txt` (`signs:`). Both shell out to external binaries
that goreleaser does not install for you. The release workflow installs
them via `anchore/sbom-action/download-syft@v0` and
`sigstore/cosign-installer@v3` before the goreleaser step — if you fork
the workflow or run goreleaser locally, install both first.
