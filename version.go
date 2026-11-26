package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
)

// version is set at build time via -ldflags "-X main.version=...":
//   - mise.toml's "build" task sets it to "dev-<short-sha>" (plus "-dirty"
//     if the working tree has uncommitted changes), read from the local
//     git checkout at build time — never at runtime, so the binary itself
//     never needs git installed to report its own version.
//   - .github/workflows/release.yml sets it to the published release's own
//     tag instead (e.g. "v0.3.0").
// Plain `go build` (no ldflags) leaves it at this fallback, which is an
// honest answer for that case too: an ad-hoc build with no version wired in.
var version = "dev-unknown"

// versionClusterTimeout bounds the whole cluster round trip (API server
// list for the relay pod, port-forward, GetNodes). `version` is the one
// command people run to check their setup, often precisely when the
// cluster is unreachable — it must answer quickly either way, not hang on
// client-go's default of no timeout.
const versionClusterTimeout = 5 * time.Second

func runVersion(args []string) {
	fs := pflag.NewFlagSet("version", pflag.ExitOnError)
	registerDebugFlag(fs)
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig (default: KUBECONFIG env or ~/.kube/config)")
	clientOnly := fs.Bool("client", false, "only print this binary's own versions; don't contact the cluster")
	registerHubbleNamespaceFlag(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %[1]s version [--client] [--kubeconfig <path>]

Print the version this binary was built from and the Cilium version its
policy engine is pinned to. When a kubeconfig is available, also print the
Cilium version actually running on that cluster (read-only, via
hubble-relay — the same detection behind the version-skew warning).

Flags:
`, binName)
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	fmt.Printf("%s %s\n", binName, version)
	// Cilium engine version, not the binary's own — pinnedCiliumVersion
	// (globals.go) is a constant since go.mod's require line isn't
	// readable at runtime, so this needs no cluster call.
	fmt.Printf("cilium engine %s (pinned)\n", pinnedCiliumVersion)

	if *clientOnly {
		return
	}
	// No resolvable kubeconfig is the ordinary offline case (a CI runner,
	// a laptop with no cluster), not an error: print exactly what this
	// command printed before it knew about clusters at all.
	cfg, err := restConfig(*kubeconfig)
	if err != nil {
		return
	}
	cfg.Timeout = versionClusterTimeout
	target := resolveKubeTarget(*kubeconfig, cfg)
	core, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fmt.Println(clusterVersionLine(&clusterVersionStatus{state: clusterVersionUnknown}, target))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), versionClusterTimeout)
	defer cancel()
	fmt.Println(clusterVersionLine(detectClusterCiliumVersion(ctx, core, cfg), target))
}

// clusterVersionLine renders detectClusterCiliumVersion's result for
// `version`. Pure, so every state is unit-tested without a cluster. Names
// the context (or API server, for a context-less config) because "what
// version is the cluster running" is meaningless without "which cluster".
func clusterVersionLine(status *clusterVersionStatus, target kubeTarget) string {
	where := target.context
	if where == "" {
		where = target.apiServer
	}
	where = "(context: " + where + ")"
	switch status.state {
	case clusterVersionMatch:
		return fmt.Sprintf("cilium cluster %s %s", status.detected, where)
	case clusterVersionSkewed:
		return fmt.Sprintf("cilium cluster %s %s — differs from the pinned engine at major.minor; verdicts use %s semantics",
			status.detected, where, pinnedCiliumVersion)
	case clusterVersionNodeSkew:
		return fmt.Sprintf("cilium cluster %s %s — nodes disagree, likely a rolling upgrade",
			strings.Join(status.nodeVersions, ", "), where)
	default:
		return fmt.Sprintf("cilium cluster unknown %s — hubble-relay unreachable, or too old to report its version", where)
	}
}
