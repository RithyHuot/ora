#!/usr/bin/env bash
# scripts/release.sh — prepare a release commit + tag for ora.
#
# Usage:
#   scripts/release.sh vX.Y.Z [--yes]
#
# What it does:
#   1. Validates preflight (semver, branch, clean tree, sync, no dup tag,
#      [Unreleased] non-empty, lint+test pass).
#   2. Cuts CHANGELOG.md [Unreleased] into a dated ## [X.Y.Z] section and
#      refreshes the compare-link refs at the bottom.
#   3. Bumps VERSION=vX.Y.Z in README.md.
#   4. Shows the diff, asks for confirmation (skip with --yes or
#      RELEASE_YES=1), commits, and tags.
#   5. Stops before pushing — the tag push triggers GoReleaser, so it stays
#      manual.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

# --- args -------------------------------------------------------------------

VERSION=${1:-}
[[ -n "$VERSION" ]] || die "usage: $0 vX.Y.Z [--yes]"

ASSUME_YES=${RELEASE_YES:-0}
if [[ "${2:-}" == "--yes" ]]; then ASSUME_YES=1; fi

[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] \
  || die "VERSION must match vMAJOR.MINOR.PATCH (got: $VERSION)"

NUM=${VERSION#v}
TODAY=$(date +%Y-%m-%d)

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

# --- preflight --------------------------------------------------------------

BRANCH=$(git rev-parse --abbrev-ref HEAD)
[[ "$BRANCH" == "main" ]] || die "must be on main (currently on: $BRANCH)"

git diff-index --quiet HEAD -- \
  || die "working tree dirty; commit or stash first"

git fetch --quiet origin main
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)
[[ "$LOCAL" == "$REMOTE" ]] \
  || die "local main ($LOCAL) is not in sync with origin/main ($REMOTE)"

if git rev-parse --verify --quiet "refs/tags/$VERSION" >/dev/null; then
  die "tag $VERSION already exists locally"
fi
if git ls-remote --exit-code --tags origin "$VERSION" >/dev/null 2>&1; then
  die "tag $VERSION already exists on origin"
fi

if grep -qE "^## \[$NUM\] - " CHANGELOG.md; then
  die "CHANGELOG.md already has a [$NUM] section"
fi

# [Unreleased] must contain at least one bullet line. awk extracts the body
# between "## [Unreleased]" and the next "## [" heading.
UNRELEASED_BULLETS=$(awk '
  /^## \[Unreleased\]/ { p=1; next }
  /^## \[/ && p       { exit }
  p && /^- /          { print }
' CHANGELOG.md)
[[ -n "$UNRELEASED_BULLETS" ]] \
  || die "CHANGELOG.md [Unreleased] has no bullets — nothing to release"

echo "==> running lint"
make lint
echo "==> running tests"
make test

# --- CHANGELOG cut ----------------------------------------------------------

# Insert "## [X.Y.Z] - YYYY-MM-DD" right after the "## [Unreleased]" header
# and the blank line that follows it.
awk -v num="$NUM" -v date="$TODAY" '
  /^## \[Unreleased\]$/ && !done {
    print
    if ((getline next_line) > 0) print next_line
    print "## [" num "] - " date
    print ""
    done=1
    next
  }
  { print }
' CHANGELOG.md > CHANGELOG.md.tmp
mv CHANGELOG.md.tmp CHANGELOG.md

# Refresh compare-link refs at the bottom: rewrite [Unreleased] to compare
# against the new tag, and add a [X.Y.Z] tag link right after it.
OLD_UNRELEASED_LINE=$(grep -E '^\[Unreleased\]: ' CHANGELOG.md || true)
[[ -n "$OLD_UNRELEASED_LINE" ]] \
  || die "CHANGELOG.md is missing the [Unreleased] compare-link ref"

NEW_UNRELEASED_LINE="[Unreleased]: https://github.com/rithyhuot/ora/compare/${VERSION}...HEAD"
NEW_TAG_LINE="[$NUM]: https://github.com/rithyhuot/ora/releases/tag/$VERSION"

awk -v old="$OLD_UNRELEASED_LINE" -v new_unrel="$NEW_UNRELEASED_LINE" \
    -v new_tag="$NEW_TAG_LINE" '
  $0 == old {
    print new_unrel
    print new_tag
    next
  }
  { print }
' CHANGELOG.md > CHANGELOG.md.tmp
mv CHANGELOG.md.tmp CHANGELOG.md

# --- README VERSION bump ----------------------------------------------------

# BSD sed (macOS default) and GNU sed both accept this form.
sed -i.bak -E "s/VERSION=v[0-9]+\.[0-9]+\.[0-9]+/VERSION=$VERSION/g" README.md
rm -f README.md.bak

# --- review and confirm -----------------------------------------------------

echo
echo "==> diff"
git --no-pager diff -- CHANGELOG.md README.md

if [[ "$ASSUME_YES" != "1" ]]; then
  echo
  read -r -p "Commit and tag $VERSION? [y/N] " reply
  case "$reply" in
    [yY]|[yY][eE][sS]) ;;
    *)
      echo "aborted; CHANGELOG.md and README.md left modified for manual review"
      exit 1
      ;;
  esac
fi

# --- commit and tag ---------------------------------------------------------

git add CHANGELOG.md README.md
git commit -m "release: $VERSION"
git tag -a "$VERSION" -m "Release $VERSION"

cat <<MSG

Done. Local commit and tag created.

To publish (this triggers the release workflow):
  git push origin main
  git push origin $VERSION

To undo locally before pushing:
  git tag -d $VERSION
  git reset --hard HEAD~1
MSG
