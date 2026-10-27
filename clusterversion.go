package main

// Phase 0 of GitHub issue #2: detect the Cilium version actually running on
// the cluster this invocation is pointed at, so the CLI/UI can warn when it
// drifts from pinnedCiliumVersion (Phase 1) and compat.go's feature gates
// can fall back to a real detected version instead of only ever assuming
// the pin (Phase 2). Reuses dialHubble's existing port-forward + gRPC dial —
// zero new RBAC, since GetNodes is served by the same hubble-relay
// ObserverClient flows.go already talks to.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/blang/semver/v4"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// clusterVersionState is what detectClusterCiliumVersion could actually
// determine. Kept as its own enum rather than a bare "skewed bool" because
// "we don't know" and "the nodes disagree with each other" are both real,
// distinct outcomes a caller needs to render differently — neither is a
// detected version standing in for the whole cluster.
type clusterVersionState int

const (
	// clusterVersionUnknown covers every case detection couldn't produce a
	// trustworthy answer: hubble-relay unreachable (port-forward/dial
	// failure — the same failure mode flows/verdict already tolerate), the
	// GetNodes call itself failing, or every node reporting an empty/
	// non-semver version string (an old relay/agent that predates this
	// field). Never fatal, never a false skew — "unknown" is the honest
	// answer and callers fall back to behaving exactly as they did before
	// this feature existed.
	clusterVersionUnknown clusterVersionState = iota
	// clusterVersionMatch: every node agreed on one real semver version,
	// and it's the same major.minor as pinnedCiliumVersion.
	clusterVersionMatch
	// clusterVersionSkewed: every node agreed on one real semver version,
	// but it differs from pinnedCiliumVersion at the major or minor level.
	// Patch-only differences are deliberately not "skew" — see
	// versionsSkewed.
	clusterVersionSkewed
	// clusterVersionNodeSkew: more than one distinct real semver version
	// was seen across nodes — a cluster mid rolling-upgrade. Reported as
	// its own state rather than silently picking one node's answer,
	// because which node's version "wins" would be an arbitrary guess.
	clusterVersionNodeSkew
)

// clusterVersionStatus is detectClusterCiliumVersion's result — the shared
// shape Phase 1's CLI warning, GET /api/version, and Phase 2's compat gate
// fallback all read, so none of them re-derive "is this skewed" on their
// own.
type clusterVersionStatus struct {
	state clusterVersionState
	// detected is the one agreed-on version string (e.g. "1.20.2"), set
	// only when state is clusterVersionMatch or clusterVersionSkewed.
	detected string
	// nodeVersions is every distinct real version string observed, in the
	// order first seen. Empty for clusterVersionUnknown; one entry for
	// Match/Skewed; two or more for NodeSkew (this is what a node-skew
	// warning message actually lists).
	nodeVersions []string
}

// detectClusterCiliumVersion best-effort-detects the Cilium version(s)
// actually running on the cluster via hubble-relay's GetNodes RPC (each
// node reports its own agent's version independently — see the vendored
// api/v1/observer/observer.proto's Node.version field). Always returns a
// usable status, never an error: every caller (CLI warning, UI endpoint,
// compat gate fallback) must tolerate hubble being unreachable exactly like
// fetchFlows/streamFlows already do, so detection failure degrades to
// clusterVersionUnknown rather than propagating up as something callers
// have to special-case.
func detectClusterCiliumVersion(ctx context.Context, core kubernetes.Interface, cfg *rest.Config) *clusterVersionStatus {
	client, closeFn, err := dialHubble(core, cfg)
	if err != nil {
		return &clusterVersionStatus{state: clusterVersionUnknown}
	}
	defer closeFn()

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := client.GetNodes(ctx, &observerpb.GetNodesRequest{})
	if err != nil {
		return &clusterVersionStatus{state: clusterVersionUnknown}
	}

	var distinct []string
	seen := map[string]bool{}
	for _, n := range resp.GetNodes() {
		v := leadingSemver(n.GetVersion())
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		distinct = append(distinct, v)
	}

	switch len(distinct) {
	case 0:
		return &clusterVersionStatus{state: clusterVersionUnknown}
	case 1:
		st := clusterVersionMatch
		if versionsSkewed(distinct[0], pinnedCiliumVersion) {
			st = clusterVersionSkewed
		}
		return &clusterVersionStatus{state: st, detected: distinct[0], nodeVersions: distinct}
	default:
		return &clusterVersionStatus{state: clusterVersionNodeSkew, nodeVersions: distinct}
	}
}

// leadingSemver extracts the real semver token off a raw Cilium version
// string and reports "" for anything that isn't one. Cilium's own
// pkg/version.Version formats as "1.20.2 <sha> <date> go version <gover>
// <os>/<arch>" (confirmed in the vendored pkg/version/version.go) — the
// semver is always the first space-separated field, but defending against
// an empty string or a future/older format that isn't real semver at all
// (rather than panicking or treating garbage as a version to compare
// against) is exactly the "don't false-positive a skew warning off
// garbage" case this project's issue called out.
func leadingSemver(raw string) string {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return ""
	}
	if _, err := semver.ParseTolerant(fields[0]); err != nil {
		return ""
	}
	return fields[0]
}

// versionsSkewed compares two version strings at the major.minor level
// only — a patch difference (e.g. 1.20.2 vs 1.20.5) is normal drift within
// a release series and shouldn't read as "incompatible," only a
// major/minor difference means the pkg/policy internals this tool embeds
// were built against a meaningfully different Cilium than what's actually
// running. Either side failing to parse is treated as "not skewed" rather
// than guessing — callers only ever pass leadingSemver's already-validated
// output or pinnedCiliumVersion (a hand-maintained constant), so a parse
// failure here would mean one of those invariants broke, not a real skew.
func versionsSkewed(detected, pinned string) bool {
	d, err := semver.ParseTolerant(detected)
	if err != nil {
		return false
	}
	p, err := semver.ParseTolerant(pinned)
	if err != nil {
		return false
	}
	return d.Major != p.Major || d.Minor != p.Minor
}

// warnOnVersionSkew is the Phase 1 CLI warning path shared by
// policies.go/flows.go/verdict.go's subcommand entry points: best-effort
// detection, printed as a single stderr line on confirmed skew (including
// node-skew), silent on clusterVersionUnknown/clusterVersionMatch so the
// common case (hubble unreachable from here, or a matching version)
// produces no new output at all.
func warnOnVersionSkew(core kubernetes.Interface, cfg *rest.Config) {
	status := detectClusterCiliumVersion(context.Background(), core, cfg)
	switch status.state {
	case clusterVersionSkewed:
		fmt.Fprintf(os.Stderr, binName+": cluster is running Cilium %s, this binary is pinned to %s — verdicts are computed with the pinned version's pkg/policy semantics, which may not exactly match what the cluster actually enforces\n",
			status.detected, pinnedCiliumVersion)
	case clusterVersionNodeSkew:
		fmt.Fprintf(os.Stderr, binName+": cluster nodes disagree on Cilium version (%s) — likely a rolling upgrade in progress; this binary is pinned to %s and verdicts may not match every node's actual enforcement\n",
			strings.Join(status.nodeVersions, ", "), pinnedCiliumVersion)
	}
}
