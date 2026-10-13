// Command-line entry point for GuardBee: a local CLI, no
// in-cluster agent, that answers whether a candidate CiliumNetworkPolicy
// would break or newly allow real cluster traffic. The binary's name is set
// in globals.go, not here.
//
// See the design doc: Obsidian projects/cilium-network-policy-editor/design-2026-10-11.md
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printHelp(os.Stderr)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "-h", "--help", "help":
		printHelp(os.Stdout)
		os.Exit(0)
	case "policies":
		runPolicies(os.Args[2:])
	case "flows":
		runFlows(os.Args[2:])
	case "verdict":
		runVerdict(os.Args[2:])
	case "ui":
		runUI(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown command %q\n\n", binName, os.Args[1])
		printHelp(os.Stderr)
		os.Exit(1)
	}
}

// printHelp is the top-level --help: every command, every flag, worked
// examples, and how to load shell completions. Run "<command> -h" for a
// command's own usage (same content, scoped to that command).
func printHelp(w *os.File) {
	fmt.Fprintf(w, `%[1]s — GuardBee: Cilium Policy Pre-Flight Simulator CLI

Diffs a candidate CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy against
real cluster traffic before you merge it: which flows would it newly block
or newly allow?

USAGE
  %[1]s <command> [flags]

COMMANDS
  policies    List live CiliumNetworkPolicy/CCNP state
  flows       Stream recent Hubble flows for a namespace
  verdict     Diff a candidate policy's verdicts against real recent flows
  ui          Start a local web UI for flows/verdict (milestone 1, read-only)

GLOBAL FLAGS (every command)
  --kubeconfig string     path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)
  --namespace, -n string  namespace to scope the query to; omit (or pass --all-namespaces)
                          to query cluster-wide
  --all-namespaces, -A    query cluster-wide instead of one namespace (same as omitting
                          --namespace) — needed to see a CiliumClusterwideNetworkPolicy's
                          full blast radius when it spans more than one namespace; a
                          plain CiliumNetworkPolicy should always get --namespace instead,
                          since it can only ever affect its own namespace

POLICIES
  %[1]s policies [-n <namespace>|-A]

  Example:
    %[1]s policies -n testing

FLOWS
  %[1]s flows [-n <namespace>|-A] [--last N] [-f]

  --last uint   number of recent flows to print (default 20) — a ceiling, not a
                guarantee; run "%[1]s flows -h" for why
  --follow, -f  keep streaming new flows until Ctrl+C instead of stopping after --last

  Examples:
    %[1]s flows -n testing --last 50
    %[1]s flows -n myapp --follow
    %[1]s flows --all-namespaces --last 100

VERDICT
  %[1]s verdict [-n <namespace>|-A] [--last N] [-f] <candidate.yaml>

  --last uint          number of recent flows to sample (default 50) — a ceiling, not a
                       guarantee; run "%[1]s verdict -h" for why
  --follow, -f         keep judging new flows until Ctrl+C instead of stopping after --last
  --show-unchanged     also print UNCHANGED rows (what's confirmed still working), not
                       just what changed — grouped after the regressions

  Examples:
    %[1]s verdict -n myapp examples/myapp-merge-ready.yaml
    %[1]s verdict -n myapp --last 200 examples/myapp-wrong-port.yaml
    %[1]s verdict -n myapp --follow examples/myapp-merge-ready.yaml
    %[1]s verdict --all-namespaces examples/ccnp-coredns-merge-ready.yaml
    %[1]s verdict -n myapp --show-unchanged examples/myapp-merge-ready.yaml

UI
  %[1]s ui [--addr host:port]

  --addr string   address to listen on (default 127.0.0.1:4747)

  Example:
    %[1]s ui

  Run "%[1]s <command> -h" for that command's usage on its own.

SHELL COMPLETIONS (bash/fish/zsh)
  Generated from globals.go into completions/ (regenerate with
  "mise run completions" after a rename or a flag/subcommand change):

    source completions/%[1]s.bash               # bash, in ~/.bashrc
    source completions/%[1]s.fish                # fish, or copy to ~/.config/fish/completions/
    cp completions/_%[1]s ~/.zsh/completions/    # zsh, anywhere on $fpath, then run compinit
`, binName)
}
