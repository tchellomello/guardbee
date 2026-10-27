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
	case "version":
		runVersion(os.Args[2:])
	case "compat":
		runCompat(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "%s: unknown command %q\n\n", binName, os.Args[1])
		printHelp(os.Stderr)
		os.Exit(1)
	}
}

// printHelp is the top-level --help: just the command list and the flags
// shared by all of them. Each subcommand owns its own full usage (flags,
// examples) via its fs.Usage — run "<command> --help" for that.
func printHelp(w *os.File) {
	fmt.Fprintf(w, `%[1]s — GuardBee: ship the policy. not the outage.

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
  version     Print the version this binary was built from
  compat      List version-gated policy constructs GuardBee knows about, and why

GLOBAL FLAGS (every command except ui)
  --kubeconfig string     path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)
  --namespace, -n string  namespace to scope the query to; omit (or pass --all-namespaces)
                          to query cluster-wide
  --all-namespaces, -A    query cluster-wide instead of one namespace (same as omitting
                          --namespace) — needed to see a CiliumClusterwideNetworkPolicy's
                          full blast radius when it spans more than one namespace; a
                          plain CiliumNetworkPolicy should always get --namespace instead,
                          since it can only ever affect its own namespace

Run "%[1]s <command> --help" for that command's flags and examples.

SHELL COMPLETIONS (bash/fish/zsh)
  Generated from globals.go into completions/ (regenerate with
  "mise run completions" after a rename or a flag/subcommand change):

    source completions/%[1]s.bash               # bash, in ~/.bashrc
    source completions/%[1]s.fish                # fish, or copy to ~/.config/fish/completions/
    cp completions/_%[1]s ~/.zsh/completions/    # zsh, anywhere on $fpath, then run compinit
`, binName)
}
