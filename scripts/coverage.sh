#!/usr/bin/env bash
# Coverage ratchet: fails if Go or UI unit-test coverage drops below the
# recorded baseline (coverage-baseline.json), and raises the baseline when
# coverage goes up. A ratchet, not a target: the number only has to never
# go down. A fixed bar (say 80%) would mostly push tests into the code that
# talks to a live cluster, where they'd mock everything and assert little.
# Behavior in the browser is the e2e suite's job (mise run e2e); this catches
# the slow erosion of new code landing without unit tests.
#
#   mise run coverage            # check; CI runs this
#   mise run coverage -- --update  # record a higher baseline after adding tests
set -euo pipefail
cd "$(dirname "$0")/.."

BASELINE=coverage-baseline.json
# Wiggle room for rounding only: a real drop is a real drop.
TOLERANCE=0.1
update=false
[[ "${1:-}" == "--update" ]] && update=true

profile=$(mktemp)
trap 'rm -f "$profile"' EXIT
go test -count=1 -coverprofile="$profile" ./... >/dev/null
go_pct=$(go tool cover -func="$profile" | awk '/^total:/ {sub("%", "", $NF); print $NF}')

(cd ui && npx vitest run --coverage --coverage.reporter=json-summary >/dev/null)
ui_pct=$(node -e 'console.log(require("./ui/coverage/coverage-summary.json").total.lines.pct)')

read -r base_go base_ui < <(node -e '
  const b = require("./'"$BASELINE"'")
  console.log(b.go, b.ui)
')

echo "coverage: go ${go_pct}% (baseline ${base_go}%), ui lines ${ui_pct}% (baseline ${base_ui}%)"

below() { awk -v c="$1" -v b="$2" -v t="$TOLERANCE" 'BEGIN { exit !(c + t < b) }'; }
above() { awk -v c="$1" -v b="$2" 'BEGIN { exit !(c > b) }'; }

failed=false
if below "$go_pct" "$base_go"; then
	echo "coverage: Go dropped ${base_go}% -> ${go_pct}%. Add tests for the new code (go test -cover ./... shows where)." >&2
	failed=true
fi
if below "$ui_pct" "$base_ui"; then
	echo "coverage: UI dropped ${base_ui}% -> ${ui_pct}%. Add vitest tests for new logic in ui/src/shared/ (npm run coverage in ui/ shows where)." >&2
	failed=true
fi
$failed && exit 1

if above "$go_pct" "$base_go" || above "$ui_pct" "$base_ui"; then
	if $update; then
		new_go=$(awk -v c="$go_pct" -v b="$base_go" 'BEGIN { print (c > b ? c : b) }')
		new_ui=$(awk -v c="$ui_pct" -v b="$base_ui" 'BEGIN { print (c > b ? c : b) }')
		printf '{\n  "go": %s,\n  "ui": %s\n}\n' "$new_go" "$new_ui" >"$BASELINE"
		echo "coverage: baseline raised to go ${new_go}%, ui ${new_ui}% — commit ${BASELINE}"
	else
		echo "coverage: above baseline — run 'mise run coverage -- --update' and commit ${BASELINE} to lock it in"
	fi
fi
