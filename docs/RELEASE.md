# Release Process

This document describes how to release `ora` binaries.

## Prerequisites

- Go 1.23+
- [GoReleaser](https://goreleaser.com/install/) (for local releases)
- GitHub repository with `GITHUB_TOKEN` or `GH_TOKEN` env var set

## Automated release (recommended)

Push a version tag to trigger the GitHub Actions release workflow:

```bash
# 1. Ensure main is green
git checkout main
git pull origin main
make test
make test-int   # macOS only

# 2. Update CHANGELOG.md with the new version
# 3. Commit any final changes
git add -A
git commit -m "chore: bump version for vX.Y.Z"

# 4. Tag and push
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin main --follow-tags
```

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

If you need to release from your local machine:

```bash
# 1. Ensure clean working tree and tests pass
make test
make lint

# 2. Set your GitHub token
export GITHUB_TOKEN=$(gh auth token)

# 3. Create and push the tag
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0

# 4. Run GoReleaser
make release

# Or with snapshot (no tag required, for testing):
goreleaser release --snapshot --clean
```

## Version numbering

Follows [Semantic Versioning](https://semver.org/):

- **MAJOR** — Breaking changes to CLI interface, config format, or sandbox behavior
- **MINOR** — New providers, new config options, new commands
- **PATCH** — Bug fixes, doc updates, security hardening

## Pre-release checklist

Before tagging a release:

- [ ] `make test` passes
- [ ] `make test-int` passes (macOS)
- [ ] `make lint` passes
- [ ] `make build` produces a working binary
- [ ] `CHANGELOG.md` is updated
- [ ] `README.md` install instructions reference the correct version
- [ ] Smoke-tested `ora claude` (or another provider) against a non-trivial
      repo to confirm no spurious `[SANDBOX DENIED]` banners

## Artifacts

Each release produces:

| Artifact | Description |
|---|---|
| `ora_vX.Y.Z_darwin_amd64.tar.gz` | Intel Mac binary |
| `ora_vX.Y.Z_darwin_arm64.tar.gz` | Apple Silicon binary |
| `checksums.txt` | SHA256 checksums |
| `checksums.txt.bundle` | Cosign signature bundle for verifying `checksums.txt` |

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
