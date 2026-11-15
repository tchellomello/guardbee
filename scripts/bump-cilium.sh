#!/usr/bin/env bash
# Mechanical half of a Cilium version bump: moves every hand-maintained pin
# (go.mod, globals.go's pinnedCiliumVersion, lab-up.sh's CILIUM_VERSION —
# the three pin_test.go's TestCiliumPinsAgree holds together), refreshes
# the flake's dependency hashes (scripts/nix-hashes.sh), prints the
# compat-scan report, then runs the full `mise run check`.
#
# Deliberately stops there. The two steps that actually make a bump safe
# stay manual, because they're judgment calls, not edits (see AGENTS.md's
# "Architecture principle that overrides convenience"):
#   - reading each compat-scan finding against the real Cilium source and
#     adding a featureGates entry, with a real "why", for anything genuine
#   - re-validating verdicts against your real cluster (--lab automates the
#     disposable-lab half of that via lab/scripts/lab-validate.sh)
# Prose/doc mentions of the old version are left alone too — most are
# illustrative, and sed-rewriting prose is how wrong docs get written; the
# script lists them instead.
set -euo pipefail
cd "$(dirname "$0")/.."

TO=""
LAB=false
for arg in "$@"; do
	case "$arg" in
	--lab) LAB=true ;;
	*) TO="$arg" ;;
	esac
done
OLD=$(sed -n 's/.*pinnedCiliumVersion = "\(.*\)"/\1/p' globals.go)
if [[ -z "$TO" ]]; then
	echo "Usage: $(basename "$0") <to-version> [--lab]   (e.g. v1.20.4; current pin is v${OLD})" >&2
	echo "  --lab  after check passes, run lab/scripts/lab-validate.sh (needs docker/kind/helm/kubectl, several minutes)" >&2
	echo "  available: $(go list -m -versions github.com/cilium/cilium | tr ' ' '\n' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | tail -5 | tr '\n' ' ')" >&2
	exit 1
fi
NEW="${TO#v}"
if [[ ! "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "error: '$TO' isn't a plain release version (vX.Y.Z) — pre-releases aren't something to pin the engine to" >&2
	exit 1
fi
if [[ "$NEW" == "$OLD" ]]; then
	echo "Already pinned to v${OLD}, nothing to do." >&2
	exit 0
fi
if [[ -n "$(git status --porcelain)" ]]; then
	echo "error: working tree isn't clean — commit or stash first, so the bump is reviewable as its own diff" >&2
	exit 1
fi

echo "=== compat-scan v${OLD} → v${NEW} (review this before trusting the bump) ==="
bash scripts/compat-scan.sh "v${OLD}" "v${NEW}"

echo
echo "=== Bumping pins v${OLD} → v${NEW} ==="
go get "github.com/cilium/cilium@v${NEW}"
go mod tidy
sed -i "s/^const pinnedCiliumVersion = \"${OLD}\"/const pinnedCiliumVersion = \"${NEW}\"/" globals.go
sed -i "s/^CILIUM_VERSION=\"${OLD}\"/CILIUM_VERSION=\"${NEW}\"/" lab/scripts/lab-up.sh
# go.sum just changed, so the flake's vendorHash did too.
bash scripts/nix-hashes.sh
git --no-pager diff --stat

echo
echo "=== mise run check ==="
mise run check

echo
echo "=== Remaining mentions of ${OLD} (docs/comments — update by hand where they mean \"the current pin\") ==="
grep -rnI --exclude-dir={node_modules,dist,.git} --exclude=go.sum -F "${OLD}" . || true

if $LAB; then
	echo
	echo "=== lab validation against Cilium ${NEW} ==="
	bash lab/scripts/lab-validate.sh
fi

echo
echo "Mechanical bump to v${NEW} done and \`mise run check\` passed. Still manual:"
echo "  1. Read the compat-scan findings above against the real source; add a"
echo "     compat.go featureGates entry (with its \"why\") for anything genuine."
if $LAB; then
	echo "  2. Lab verdicts matched. Run one verdict against your real cluster too."
else
	echo "  2. Live re-validation: mise run lab-validate (or re-run with --lab),"
	echo "     plus one verdict against your real cluster."
fi
