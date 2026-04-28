---
name: release
description: Use when shipping a new ora release. Auto-detects which phase to run — Phase 1 opens a release-prep PR with doc updates if commits since the last tag aren't yet reflected in CHANGELOG/STABILITY/etc.; Phase 2 (after PR merges) cuts `[Unreleased]` and tags. Triggers on `/release`, "ship a release", "tag v0.2.3", "release ora".
---

# Releasing ora

End-to-end release flow. Run from latest `main`. The skill auto-detects which of two phases to execute:

- **Phase 1 — release-prep PR.** Commits have landed since the last tag but the docs (CHANGELOG, STABILITY audit-log, ARCHITECTURE, etc.) don't reflect them yet. Open a PR with the doc updates so the prose gets human review. **No tag, no `release:` commit.**
- **Phase 2 — cut and tag.** Docs are already current (Phase 1 PR was merged, or the user updated them by hand). Run `make release VERSION=vX.Y.Z` from main to cut `[Unreleased]` into a dated section and create the tag.

Tags are only **pushed** once the tagged commit is reachable from `origin/main` with its original SHA. If `main` is protected (the release commit can't go in directly), the release commit lands via a PR that **must** be merged with "Create a merge commit" — squash/rebase generates a new SHA and orphans the tag.

Pause for user input only at points marked **CONFIRM**.

## Step 1 — Discover state and pick the phase

Run in parallel:

```bash
git fetch --quiet origin main
git rev-parse --abbrev-ref HEAD                       # current branch
git status --porcelain                                # uncommitted changes
LAST=$(git describe --tags --abbrev=0); echo "last tag: $LAST"
git log "$LAST..origin/main" --oneline                # commits since last tag (on main)
gh pr list --state open --search "release-prep in:head" \
   --json number,headRefName,title                    # is a prep PR already open?
```

**Refuse to continue and CONFIRM with the user if:**
- working tree is dirty
- not on `main`, or local `main` is behind `origin/main` (run `git checkout main && git pull --ff-only origin main`)
- a `release-prep/*` PR is already open — direct the user to merge or close it before starting another, then exit

If `git log $LAST..origin/main` is empty, tell the user there's nothing to release and stop.

### Pending tag push?

Before phase detection, check whether a previous Phase 2 run left a local tag that hasn't been pushed yet. This happens when the release commit had to land via a PR (Step 4b) and the user re-runs `/release` after merging it.

```bash
LOCAL_LATEST=$(git tag --list 'v*' --sort=-version:refname | head -1)
LOCAL_LATEST_SHA=$(git rev-parse "$LOCAL_LATEST^{}" 2>/dev/null)
ORIGIN_HAS=$(git ls-remote --tags origin "$LOCAL_LATEST" | wc -l | tr -d ' ')
```

If `ORIGIN_HAS=0` AND `git merge-base --is-ancestor "$LOCAL_LATEST_SHA" origin/main` succeeds, the tagged commit is on `origin/main` with its original SHA but the tag itself was never pushed. **Skip phase detection and jump to Step 4c (push the tag).**

If `ORIGIN_HAS=0` but the commit is *not* an ancestor of `origin/main`, the PR was squash/rebase-merged (orphaning the tag) or got closed without merging — see "Failure modes" below.

### Decide the phase

For each commit since `$LAST`, read `git show --stat <sha>` and classify:

- **User-visible** (bug fix, feature, behavior change, default change, security boundary change, new public symbol) → must have a `CHANGELOG.md [Unreleased]` bullet
- **Internal-only** (CI, lint fixes, test refactors with no behavior change, in-tree style cleanups) → no CHANGELOG entry needed

Then walk this gap table (mirrors `CLAUDE.md` "Updating docs alongside code"):

| If a commit touches… | Doc that must be current |
|---|---|
| Exported `pkg/` symbol | `docs/STABILITY.md` Stable list |
| Any `pkg/` symbol at all | `docs/STABILITY.md` audit-log date (mechanical) |
| `pkg/sandbox/profile.go` path allow / deny | `docs/ARCHITECTURE.md` Profile anatomy |
| Env var, `.ora.toml` field, or CLI flag | `docs/CONFIGURATION.md` |
| Security boundary | `docs/SECURITY.md` + boundaries table in `docs/ARCHITECTURE.md` |
| Error message or exit-code semantic | `docs/SANDBOX_ERROR_BEHAVIOR.md` |
| `.github/workflows/release.yml` or `.goreleaser.yml` | `docs/RELEASE.md` |
| README "Denied by default" / allow example | example must match live profile (`pkg/sandbox/profile.go` + `DefaultPolicy()`) |
| Any user-visible change | `CHANGELOG.md [Unreleased]` bullet |

Compare the table against what's actually in the docs on `origin/main`.

- **Any gap → Phase 1.** Tell the user which gaps you found, then proceed to Step 2.
- **No gaps → Phase 2.** Tell the user "all docs are current", then proceed to Step 3.

## Step 2 — Phase 1: release-prep PR

State entering: on `main`, working tree clean, gaps to fix.

1. **Compute the proposed version.** Use semver against the change set:
   - **PATCH** — bug fixes, doc-only, security hardening, additive `pkg/` symbols with no behavior change
   - **MINOR** — new providers, new flags, new commands, new public behavior; pre-1.0, this is also the bump for any STABILITY "Recent breaking changes" entry
   - **MAJOR** — breaking CLI/config/sandbox change (post-1.0 only; pre-1.0 these still bump MINOR)

   State your reasoning ("PATCH bump from $LAST: N commits since, all bug fixes, no new public symbols, no breaking-changes entry") and **CONFIRM** the version with the user. The version is used for the branch name and PR title; it can still change at Phase 2 if review shifts the scope.

2. **Create the prep branch:**

   ```bash
   git checkout -b release-prep/v<X.Y.Z>
   ```

3. **Apply doc fixes.** Two categories:

   **Mechanical (do silently, no per-edit confirmation):**
   - Bump `docs/STABILITY.md` audit-log date to today
   - Fix README "Denied by default" / allow examples that don't match the live profile (verify with `ora policy show` or grep `pkg/sandbox/profile.go`)

   **Substantive prose (draft → CONFIRM → write):**
   - For each missing CHANGELOG `[Unreleased]` bullet: read the commit (`git show <sha>`), draft a bullet matching the prose style of prior versions (explain *why* and the *symptom*, not the diff). Show the user the draft, get confirmation, then add to the right `### Added` / `### Fixed` / `### Changed` subsection.
   - For each missing STABILITY / ARCHITECTURE / CONFIGURATION / SECURITY / SANDBOX_ERROR_BEHAVIOR / RELEASE entry: same pattern.
   - For ARCHITECTURE entries especially, mention *which CLI / call needs the grant* — that's what readers come for.

   Never fabricate motivation. If a commit's intent isn't clear from its message + diff, ask the user.

4. **Commit the doc fixes:**

   ```bash
   git add CHANGELOG.md README.md docs/
   git commit -m "docs: prep release v<X.Y.Z>"
   ```

5. **Push and open the PR:**

   ```bash
   git push -u origin release-prep/v<X.Y.Z>
   gh pr create --title "docs: prep release v<X.Y.Z>" --body "$(cat <<EOF
   ## Summary

   Catches up docs for the upcoming v<X.Y.Z> release. Docs-only — no code changes.

   - <list of CHANGELOG bullets added, one per line>
   - <other doc updates>

   After merge, re-run \`/release\` (or \`make release VERSION=v<X.Y.Z>\`) on \`main\` to cut \`[Unreleased]\` into the dated section and tag.

   ## Test plan

   - [ ] CHANGELOG bullets accurately describe the user-visible changes since v<LAST>
   - [ ] No code changes (this PR is docs-only)
   - [ ] STABILITY audit-log date matches today

   🤖 Generated with [Claude Code](https://claude.com/claude-code)
   EOF
   )"
   ```

6. **Tell the user and stop:**

   > Opened release-prep PR #N. Review and merge it, then re-run `/release` to cut and tag.

   Do **not** run `make release`. Do **not** create a tag. Stop here.

## Step 3 — Phase 2: cut and tag

State entering: on `main` (synced with `origin/main`), working tree clean, no doc gaps.

1. **CONFIRM the version.** The most recent merged release-prep PR encodes the proposed version in its branch name:

   ```bash
   gh pr list --state merged --search "release-prep in:head" --limit 1 \
      --json headRefName --jq '.[0].headRefName'
   ```

   Use that as the default and **CONFIRM** with the user. They may have decided to bump differently after reviewing the merged PR.

2. **Run the release script:**

   ```bash
   RELEASE_YES=1 make release VERSION=v<X.Y.Z>
   ```

   `RELEASE_YES=1` skips the script's interactive prompt — you've already confirmed at Step 1. The script enforces all preflight gates (semver, branch, clean tree, sync, no dup tag, `[Unreleased]` non-empty, `make lint` + `make test` pass) and then:
   - Cuts `CHANGELOG.md [Unreleased]` into `## [X.Y.Z] - <today>`
   - Refreshes the compare-link refs at the bottom
   - Bumps `VERSION=vX.Y.Z` in `README.md`
   - Creates `release: vX.Y.Z` commit + annotated tag

   If a gate refuses, **read the error and fix the underlying issue.** Never bypass a gate by editing the script.

3. **Show the user the new commit and tag:**

   ```bash
   git log -1
   git show v<X.Y.Z> --stat
   ```

## Step 4 — Push to publish

The script stops before `git push`. The tag push triggers GoReleaser, so it stays explicit. Two paths depending on whether `main` is protected. Always try 4a first — if it succeeds, you're done; if it's rejected, fall back to 4b without losing the local tag.

### 4a — Direct push (try first)

**CONFIRM** with the user, then:

```bash
git push origin main
git push origin v<X.Y.Z>
```

If both succeed, jump to "After publish" below. If `git push origin main` fails with `protected branch hook declined` / `GH013` / "Changes must be made through a pull request", continue to 4b. **Do not push the tag yet** — the tagged commit isn't on `origin/main`.

### 4b — PR flow (when `main` is protected)

Local state at this point: local `main` has the release commit `<RELEASE_SHA>` ahead of `origin/main`, and the annotated tag `v<X.Y.Z>` points at `<RELEASE_SHA>`. Goal: land that exact commit on `origin/main` via a PR — *without* squash/rebase, which would orphan the tag.

1. **Move the release commit to a branch and reset local `main`:**

   ```bash
   git checkout -b release/v<X.Y.Z>          # branch now points at <RELEASE_SHA>
   git branch -f main origin/main             # local main back to origin/main
   git push -u origin release/v<X.Y.Z>
   ```

   The annotated tag stays attached to `<RELEASE_SHA>` regardless of which branch points where. `git branch -f main origin/main` is safe here because the only thing on local `main` that wasn't on `origin/main` was `<RELEASE_SHA>`, which is now preserved on `release/v<X.Y.Z>`.

2. **Open the PR. Merge instructions are load-bearing — call them out at the top of the body:**

   ```bash
   gh pr create --title "release: v<X.Y.Z>" --body "$(cat <<EOF
   ## Summary

   Cuts CHANGELOG \`[Unreleased]\` into \`## [X.Y.Z] - <today>\`, refreshes compare-link refs, and bumps \`VERSION=vX.Y.Z\` in the README cosign-verify snippet.

   ## ⚠️ Merge instructions

   **Use "Create a merge commit"** — NOT squash, NOT rebase.

   This branch contains commit \`<RELEASE_SHA>\` and the local annotated tag \`v<X.Y.Z>\` points at it. A squash/rebase merge would generate a new SHA on \`main\` and orphan the tag (it would point at a commit not on \`main\`, which the release flow forbids). A merge commit preserves \`<RELEASE_SHA>\`'s SHA on \`main\` so the tag stays valid.

   After merging with the merge-commit option, re-run \`/release\` and the skill will detect the pending tag and push it.

   ## Test plan

   - [ ] Merge with **"Create a merge commit"** (not squash, not rebase)
   - [ ] Re-run \`/release\` to push tag \`v<X.Y.Z>\` and trigger GoReleaser

   🤖 Generated with [Claude Code](https://claude.com/claude-code)
   EOF
   )"
   ```

3. **Tell the user and stop:**

   > Opened release PR #N. Merge it with **"Create a merge commit"** (not squash, not rebase), then re-run `/release` to push the tag.

   Do **not** push the tag. Stop here.

### 4c — Push the tag (after PR merges, or directly if 4a worked)

This step runs in two situations:
- Direct continuation from 4a after `git push origin main` succeeded.
- A subsequent `/release` invocation, where Step 1's "Pending tag push?" check found a local tag whose commit is now an ancestor of `origin/main`.

```bash
git checkout main
git pull --ff-only origin main
git merge-base --is-ancestor <RELEASE_SHA> origin/main   # must succeed
```

If the ancestor check fails, the PR was squash/rebase-merged despite the instructions — see "Failure modes" below. If it succeeds, **CONFIRM** with the user, then:

```bash
git push origin v<X.Y.Z>
```

### After publish

After the GoReleaser workflow completes, the GitHub draft release needs to be manually published — point the user at `docs/RELEASE.md`.

## Failure modes

- **Phase 1: open `release-prep/*` PR already exists** — never open a second one. Tell the user to merge or close the existing PR, then exit.
- **Phase 2: `[Unreleased]` empty** — the merged Phase 1 PR didn't add the bullets it should have, or someone reverted them. Re-run Phase 1 against the current state instead of bumping the version to "force" the script through.
- **Phase 2: tag already exists on origin** — someone else released this version first. Re-pick the next number with the user.
- **Working tree dirty when entering Phase 2** — commit or stash first. Doc fixes should have come through Phase 1's PR; ad-hoc doc commits on `main` defeat the review point.
- **Local `main` behind `origin/main`** — `git pull --ff-only origin main` and re-discover state. Don't tag against stale `main`.
- **Step 4b release PR was squash- or rebase-merged** — `<RELEASE_SHA>` is no longer reachable from `origin/main` and the local tag is orphaned. Do **not** push the orphaned tag. Recovery: delete the local tag (`git tag -d v<X.Y.Z>`), check out the squashed/rebased merge commit on `origin/main` that contains the release content, re-tag it (`git tag -a v<X.Y.Z> -m "Release v<X.Y.Z>"`), then push the tag. Confirm with the user before re-tagging — the merge commit's content must match what the original release commit had.
- **Step 4b release PR closed without merging** — release commit is on `origin/release/v<X.Y.Z>` but never landed on `main`. Either reopen and merge the PR (with merge-commit), or delete the local tag and start over. Don't leave a "ghost" local tag pointing at a commit that won't reach `main`.
