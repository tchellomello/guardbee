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
cleanup() {
	local rc=$?
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

# expect_verdict <candidate> <expected-exit>
expect_verdict() {
	local candidate=$1 want=$2 got attempt
	for ((attempt = 1; attempt <= RETRIES; attempt++)); do
		got=0
		"./$bin" verdict --kubeconfig "$kubeconfig" -n "$NS" --last 50 \
			--fail-on-dropped --min-flows "$MIN_FLOWS" --format markdown "$candidate" || got=$?
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
echo "lab-validate: all lab verdicts matched against Cilium ${pinned}."
