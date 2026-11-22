#!/usr/bin/env bash
# End-to-end check of the built ./guardbee binary against a fresh lab
# cluster: lab-up → assert the lab scenario's known verdicts → lab-down.
# Used by `mise run bump-cilium <v> --lab` after a version bump, and
# runnable on its own via `mise run lab-validate`.
#
# Asserts on exit codes (docs/guide/commands.md's CI mode), not on flow
# counts — counts depend on what's in Hubble's buffer at run time (see
# docs/guide/lab.md). The two candidates are the lab guide's own:
#   looks-correct.yaml — must regress (exit 2, NEWLY_DROPPED present)
#   merge-ready.yaml   — must pass clean (exit 0)
# plus examples/postgres-metrics-http-only.yaml — the scrape newly behind an
# HTTP rule must be L7_CHANGED (exit 5 with --fail-on-l7)
# Then the connectivity tests, through the streaming endpoint the UI uses,
# once per built-in vetted probe image (probes/images.yaml), so "vetted" is
# re-proven against every pinned Cilium, not just claimed:
#   netshoot: webapp → postgres:5432     must be ALLOWED → ALLOWED
#   busybox:  prometheus → postgres:9187 must be ALLOWED → BLOCKED
# The lab is disposable, so the ephemeral containers these add go with it.
# Exit 3 (too few flows judged) means a freshly-created lab hasn't produced
# enough traffic yet, so that one result is retried, never treated as a
# pass.
#
# Refuses to reuse an existing lab cluster: lab-up.sh would reuse it, and
# this script deletes the cluster on exit, so it only ever tears down a
# cluster it created itself. The whole run — kind create/delete, lab-up's
# own "kubectl config use-context", every guardbee call — happens under a
# throwaway KUBECONFIG: the user's own kubeconfig is never written (run by
# hand, lab-up/lab-down leave its current-context pointing at a deleted
# cluster), and a context-switching tool reasserting a different context
# (see lab-up.sh) can't point a verdict at a real cluster.
set -euo pipefail
cd "$(dirname "$0")/../.."

CLUSTER_NAME="guardbee-lab"
NS="postgres"
MIN_FLOWS=10
RETRIES=6
RETRY_SLEEP=15
UI_ADDR="127.0.0.1:4799"

bin=$(sed -n 's/.*const binName = "\(.*\)"/\1/p' globals.go)
pinned=$(sed -n 's/.*pinnedCiliumVersion = "\(.*\)"/\1/p' globals.go)
if [[ ! -x "./$bin" ]]; then
	echo "lab-validate: ./$bin not built — run \"mise run build\" first" >&2
	exit 1
fi
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
	echo "lab-validate: kind cluster \"$CLUSTER_NAME\" already exists — run \"mise run lab-down\" first; this only validates against (and deletes) a lab it created itself" >&2
	exit 1
fi

kubeconfig=$(mktemp)
export KUBECONFIG="$kubeconfig"
ui_log=$(mktemp)
ui_pid=""
cleanup() {
	local rc=$?
	if [[ -n $ui_pid ]]; then
		kill "$ui_pid" 2>/dev/null || true
	fi
	if [[ $rc -ne 0 && -s $ui_log ]]; then
		echo "lab-validate: guardbee ui log:" >&2
		cat "$ui_log" >&2
	fi
	rm -f "$ui_log"
	# On failure, the lab is about to be deleted along with the only
	# evidence of why — in CI there's no way to go look afterwards.
	if [[ $rc -ne 0 ]]; then
		echo "lab-validate: failed (exit $rc) — pod state before teardown:" >&2
		kubectl get pods -A -o wide >&2 || true
	fi
	echo "lab-validate: tearing down the lab..."
	bash lab/scripts/lab-down.sh || true
	rm -f "$kubeconfig"
}
trap cleanup EXIT

bash lab/scripts/lab-up.sh

echo
echo "=== lab-validate: engine version ==="
# Captured, not piped into grep -q: grep exits on its first match, and
# under pipefail the SIGPIPE `version` then gets writing its later
# (cluster) line fails the whole check despite a correct engine line.
out=$("./$bin" version --kubeconfig "$kubeconfig")
echo "$out"
if ! grep -qF "cilium engine ${pinned} (pinned)" <<<"$out"; then
	echo "FAIL: binary doesn't report engine ${pinned} — stale build?" >&2
	exit 1
fi

# expect_verdict <candidate> <expected-exit> [extra verdict flags...]
expect_verdict() {
	local candidate=$1 want=$2 got attempt
	local extra=("${@:3}")
	for ((attempt = 1; attempt <= RETRIES; attempt++)); do
		got=0
		"./$bin" verdict --kubeconfig "$kubeconfig" -n "$NS" --last 50 \
			--fail-on-dropped --min-flows "$MIN_FLOWS" --format markdown "${extra[@]}" "$candidate" || got=$?
		if [[ $got -ne 3 ]]; then
			break
		fi
		echo "lab-validate: too few flows judged yet (attempt $attempt/$RETRIES), waiting ${RETRY_SLEEP}s for lab traffic..."
		sleep "$RETRY_SLEEP"
	done
	if [[ $got -ne $want ]]; then
		echo "FAIL: $candidate exited $got, expected $want" >&2
		return 1
	fi
	echo "PASS: $candidate exited $got as expected"
}

echo
echo "=== lab-validate: looks-correct.yaml must regress (exit 2) ==="
expect_verdict lab/candidates/looks-correct.yaml 2
echo
echo "=== lab-validate: merge-ready.yaml must pass clean (exit 0) ==="
expect_verdict lab/candidates/merge-ready.yaml 0
echo
echo "=== lab-validate: an HTTP rule on the Prometheus scrape is L7_CHANGED (exit 5) ==="
expect_verdict examples/postgres-metrics-http-only.yaml 5 --fail-on-l7

echo
echo "=== lab-validate: connectivity tests with the built-in probe images ==="
command -v jq >/dev/null || { echo "lab-validate: jq is required for the connectivity checks" >&2; exit 1; }
"./$bin" ui --kubeconfig "$kubeconfig" --addr "$UI_ADDR" --enable-probes >"$ui_log" 2>&1 &
ui_pid=$!
for ((i = 0; i < 30; i++)); do
	curl -sf "http://$UI_ADDR/api/probes/capabilities" >/dev/null && break
	sleep 1
done

# The same decision rule as the UI headline (ui/src/shared/connectivity.ts):
# any missing, partial or mixed evidence is INCONCLUSIVE, never a pass.
# shellcheck disable=SC2016
decision='def side(f): if (map(f) | all(. == true)) then "ALLOWED" elif (map(f) | all(. == false)) then "BLOCKED" else "INCONCLUSIVE" end;
	.result as $r | ($r.simulation // {}) as $s |
	if ($r.flows | length) == 0 or (($s.rows // []) | length) == 0 or (($s.skippedPolicies // []) | length) > 0 or ($s.counts.notSimulated // 1) > 0
	then "INCONCLUSIVE INCONCLUSIVE"
	else ($s.rows | side(.baselineAllowed)) + " " + ($s.rows | side(.candidateAllowed)) end'

# expect_probe <ns> <app> <host> <port> <image-id> <candidate> <want "BASELINE CANDIDATE">
expect_probe() {
	local ns=$1 app=$2 host=$3 port=$4 image=$5 candidate=$6 want=$7 pod uid body out got="" attempt
	for ((attempt = 1; attempt <= 3; attempt++)); do
		pod=$(kubectl -n "$ns" get pod -l "app=$app" -o jsonpath='{.items[0].metadata.name}')
		uid=$(kubectl -n "$ns" get pod "$pod" -o jsonpath='{.metadata.uid}')
		body=$(jq -n --arg ns "$ns" --arg pod "$pod" --arg uid "$uid" --arg host "$host" --argjson port "$port" \
			--arg image "$image" --rawfile candidate "$candidate" \
			'{namespace: $ns, pod: $pod, uid: $uid, host: $host, port: $port, protocol: "TCP", imageId: $image, candidateYAML: $candidate, candidateNamespace: "", replaceExisting: true}')
		out=$(curl -sN -X POST "http://$UI_ADDR/api/probes/connection/stream" \
			-H "Origin: http://$UI_ADDR" -H 'Content-Type: application/json' --data "$body")
		if ! grep -q '"stage":"inject"' <<<"$out" || ! tail -n1 <<<"$out" | jq -e '.result' >/dev/null; then
			echo "FAIL: $app → $host:$port ($image) did not stream stages and a result:" >&2
			echo "$out" >&2
			return 1
		fi
		got=$(tail -n1 <<<"$out" | jq -r "$decision")
		[[ $got != *INCONCLUSIVE* ]] && break
		echo "lab-validate: $app → $host:$port inconclusive (attempt $attempt/3): $(tail -n1 <<<"$out" | jq -c '.result.warnings')"
		sleep 5
	done
	if [[ $got != "$want" ]]; then
		echo "FAIL: $app → $host:$port with $image: baseline/candidate $got, expected $want" >&2
		return 1
	fi
	echo "PASS: $app → $host:$port with $image: $got"
}

expect_probe webapp webapp postgres.postgres.svc.cluster.local 5432 netshoot lab/candidates/looks-correct.yaml "ALLOWED ALLOWED"
expect_probe observability prometheus postgres.postgres.svc.cluster.local 9187 busybox lab/candidates/looks-correct.yaml "ALLOWED BLOCKED"

echo
echo "lab-validate: all lab verdicts and connectivity tests matched against Cilium ${pinned}."
