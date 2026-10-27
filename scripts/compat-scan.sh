#!/usr/bin/env bash
# Discovery aid for compat.go's featureGates table — diffs Cilium's vendored
# pkg/policy/api between two versions and prints a report of things that
# might need a new gate: removed/added files, struct fields referenced in
# one version's generated deepcopy but not the other's (the technique that
# actually found the toPorts[].rules.l7/.kafka gates — see compat.go), and
# new/changed +kubebuilder:validation:MaxItems=0 ("Deprecated") markers.
#
# This is a report generator, not a code generator: it never edits
# compat.go. Every finding needs a human (or an agent under review) to read
# the real source, confirm it's a genuine silent-drop risk — not diff noise
# from an unrelated refactor — and write the "why" explanation compat.go's
# house style requires. Run manually (see mise.toml's "compat-scan" task),
# typically right before bumping go.mod's github.com/cilium/cilium version
# (see AGENTS.md's Cilium-version-bump checklist).
#
# Only ever downloads the two requested module versions via `go mod
# download` into the local module cache (GOMODCACHE) — never touches this
# project's own go.mod/go.sum.
set -euo pipefail
cd "$(dirname "$0")/.."

FROM="${1:-}"
TO="${2:-}"
if [[ -z "$FROM" || -z "$TO" ]]; then
	pinned=$(sed -n 's/.*pinnedCiliumVersion = "\(.*\)"/\1/p' globals.go)
	echo "Usage: $(basename "$0") <from-version> <to-version>" >&2
	echo "  e.g. $(basename "$0") v1.19.1 v${pinned}   (this project's current pin is ${pinned})" >&2
	exit 1
fi

echo "Downloading github.com/cilium/cilium@${FROM} and @${TO} (read-only, module cache only)..."
go mod download "github.com/cilium/cilium@${FROM}"
go mod download "github.com/cilium/cilium@${TO}"

MODCACHE=$(go env GOMODCACHE)
FROM_DIR="${MODCACHE}/github.com/cilium/cilium@${FROM}/pkg/policy/api"
TO_DIR="${MODCACHE}/github.com/cilium/cilium@${TO}/pkg/policy/api"

if [[ ! -d "$FROM_DIR" || ! -d "$TO_DIR" ]]; then
	echo "pkg/policy/api not found for one of these versions — check the version strings." >&2
	exit 1
fi

echo
echo "=== Non-test .go files only in ${FROM} (possibly removed by ${TO}) ==="
comm -23 \
	<(cd "$FROM_DIR" && ls -- *.go 2>/dev/null | grep -v _test.go | sort) \
	<(cd "$TO_DIR" && ls -- *.go 2>/dev/null | grep -v _test.go | sort) \
	| sed 's/^/  /' || true

echo
echo "=== Non-test .go files only in ${TO} (added since ${FROM}) ==="
comm -13 \
	<(cd "$FROM_DIR" && ls -- *.go 2>/dev/null | grep -v _test.go | sort) \
	<(cd "$TO_DIR" && ls -- *.go 2>/dev/null | grep -v _test.go | sort) \
	| sed 's/^/  /' || true

echo
echo "=== Struct fields referenced in ${FROM}'s generated deepcopy but not ${TO}'s (likely removed fields) ==="
FROM_FIELDS=$(mktemp)
TO_FIELDS=$(mktemp)
trap 'rm -f "$FROM_FIELDS" "$TO_FIELDS"' EXIT
grep -ohE '(in|out)\.[A-Za-z0-9_]+' "${FROM_DIR}"/zz_generated.deepcopy.go 2>/dev/null | sort -u > "$FROM_FIELDS"
grep -ohE '(in|out)\.[A-Za-z0-9_]+' "${TO_DIR}"/zz_generated.deepcopy.go 2>/dev/null | sort -u > "$TO_FIELDS"
comm -23 "$FROM_FIELDS" "$TO_FIELDS" | sed 's/^/  /'

echo
echo "=== +kubebuilder:validation:MaxItems=0 (\"Deprecated\") markers present in ${TO} ==="
grep -B2 "MaxItems=0" "${TO_DIR}"/*.go 2>/dev/null | grep -v _test.go || echo "  (none)"

echo
echo "=== compat.go's existing gates — cross-check findings above against these before filing anything ==="
grep -n '^\s*name:' "$(dirname "$0")/../compat.go" | sed 's/^/  /' || true

echo
echo "Read each finding against the real source before acting on it — this is diff"
echo "noise reduction, not a verdict. A genuine silent-drop risk gets a new"
echo "featureGates entry in compat.go, with a reason explaining why it matters,"
echo "same as the existing entries."
