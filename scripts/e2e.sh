#!/usr/bin/env bash
# Runs the end-to-end suite (ui/e2e, Playwright) against the built binary.
# `mise run e2e` builds first; extra args go to `playwright test`, e.g.
#   mise run e2e -- flows        # only flows.e2e.ts
#   mise run e2e -- --headed     # watch it
#
# Browsers: Playwright's own downloads don't run on NixOS (they expect an
# FHS system), so there the browsers come from nixpkgs — through this
# repo's own flake.lock, whose playwright-driver must be the exact version
# ui/package.json pins @playwright/test to (Playwright refuses mismatched
# browsers). Elsewhere, including CI, `npx playwright install chromium`
# provides them as usual.
set -euo pipefail
cd "$(dirname "$0")/.."

name=$(sed -n 's/.*const binName = "\(.*\)"/\1/p' globals.go)
if [[ ! -x "./$name" ]]; then
	echo "e2e: ./$name not built — run \"mise run build\" first (mise run e2e does)" >&2
	exit 1
fi

if [[ -z "${PLAYWRIGHT_BROWSERS_PATH:-}" && -e /etc/NIXOS ]] && command -v nix >/dev/null 2>&1; then
	pinned=$(sed -n 's/.*"@playwright\/test": "\([^"]*\)".*/\1/p' ui/package.json)
	nixver=$(nix --extra-experimental-features "nix-command flakes" eval --raw --inputs-from . nixpkgs#playwright-driver.version)
	if [[ "$pinned" != "$nixver" ]]; then
		echo "e2e: ui/package.json pins @playwright/test $pinned but this flake's nixpkgs has playwright $nixver — align them (bump the pin, or nix flake update)" >&2
		exit 1
	fi
	PLAYWRIGHT_BROWSERS_PATH=$(nix --extra-experimental-features "nix-command flakes" build --no-link --print-out-paths --inputs-from . nixpkgs#playwright-driver.browsers)
	export PLAYWRIGHT_BROWSERS_PATH PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=true
fi

cd ui
exec npx playwright test "$@"
