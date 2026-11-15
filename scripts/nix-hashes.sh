#!/usr/bin/env bash
# Recomputes nix/package.nix's two fixed-output hashes — npmDepsHash
# (ui/package-lock.json) and vendorHash (go.mod/go.sum) — and writes them in
# place. Run after any dependency change; `mise run bump-cilium` runs it for
# you. CI's "nix" job is the backstop: a stale hash fails the PR there
# instead of failing every user's `nixos-rebuild` after merge.
#
# Skips (exit 0) without Nix installed, so bump-cilium still works on a
# non-Nix machine — the CI job then reports which hash needs updating.
set -euo pipefail
cd "$(dirname "$0")/.."

PKG=nix/package.nix
if ! command -v nix >/dev/null 2>&1; then
	echo "nix-hashes: nix not installed — skipping; CI's \"nix\" job will flag a stale hash" >&2
	exit 0
fi
# Flakes only see git-tracked files.
git add --intent-to-add flake.nix "$PKG" 2>/dev/null || true

nixcmd=(nix --extra-experimental-features "nix-command flakes")

npm_hash=$("${nixcmd[@]}" run --inputs-from . nixpkgs#prefetch-npm-deps -- ui/package-lock.json 2>/dev/null | tail -1)
if [[ ! "$npm_hash" =~ ^sha256- ]]; then
	echo "nix-hashes: prefetch-npm-deps gave no hash (got: '$npm_hash')" >&2
	exit 1
fi
sed -i "s|npmDepsHash = \"sha256-[^\"]*\";|npmDepsHash = \"${npm_hash}\";|" "$PKG"

# vendorHash has no prefetch tool: build the vendor derivation against a
# known-wrong hash and read the real one out of Nix's mismatch error.
old_vendor=$(sed -n 's/.*vendorHash = "\(sha256-[^"]*\)";/\1/p' "$PKG")
sed -i 's|vendorHash = "sha256-[^"]*";|vendorHash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";|' "$PKG"
vendor_hash=$("${nixcmd[@]}" build .#guardbee.goModules --no-link 2>&1 | sed -n 's/.*got: *\(sha256-[^ ]*\).*/\1/p' | head -1 || true)
if [[ -z "$vendor_hash" ]]; then
	sed -i "s|vendorHash = \"sha256-[^\"]*\";|vendorHash = \"${old_vendor}\";|" "$PKG"
	echo "nix-hashes: couldn't derive vendorHash — restored the previous one; run: nix build .#guardbee.goModules" >&2
	exit 1
fi
sed -i "s|vendorHash = \"sha256-[^\"]*\";|vendorHash = \"${vendor_hash}\";|" "$PKG"

echo "nix-hashes: npmDepsHash=${npm_hash}"
echo "nix-hashes: vendorHash=${vendor_hash}"
