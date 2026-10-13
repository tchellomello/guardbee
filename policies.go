package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	ciliumclient "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// namespaceLabel renders a namespace for display: the real name, or
// "all namespaces" for the cluster-wide case (empty string).
func namespaceLabel(namespace string) string {
	if namespace == "" {
		return "all namespaces"
	}
	return namespace
}

// runPolicies lists the live CiliumNetworkPolicy state the candidate policy would
// be diffed against: CNPs in the given namespace (or every namespace), plus
// cluster-wide CCNPs. This is read-only reconnaissance — it proves the RBAC
// and clientset wiring work against the real cluster.
func runPolicies(args []string) {
	fs := pflag.NewFlagSet("policies", pflag.ExitOnError)
	flags := registerCommonFlags(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %[1]s policies [-n <namespace>|-A]

List live CiliumNetworkPolicy in that namespace (or every namespace, with
--all-namespaces or by omitting --namespace), plus cluster-wide
CiliumClusterwideNetworkPolicy, via the generated Cilium clientset.

Flags:
`, binName)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n  %[1]s policies -n testing\n  %[1]s policies --all-namespaces\n", binName)
	}
	_ = fs.Parse(args)
	namespace := flags.resolveNamespace()

	_, cilium, _, err := newClientsets(flags.kubeconfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" policies: building clients: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	cnps, err := cilium.CiliumV2().CiliumNetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" policies: listing CiliumNetworkPolicies in %s: %v\n", namespaceLabel(namespace), err)
		os.Exit(1)
	}
	fmt.Printf("CiliumNetworkPolicy (%s): %d found\n", namespaceLabel(namespace), len(cnps.Items))
	for _, p := range cnps.Items {
		if namespace == "" {
			fmt.Printf("  - %s/%s\n", p.Namespace, p.Name)
		} else {
			fmt.Printf("  - %s\n", p.Name)
		}
	}

	ccnps, err := cilium.CiliumV2().CiliumClusterwideNetworkPolicies().List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" policies: listing CiliumClusterwideNetworkPolicies: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("CiliumClusterwideNetworkPolicy (cluster-wide): %d found\n", len(ccnps.Items))
	for _, p := range ccnps.Items {
		fmt.Printf("  - %s\n", p.Name)
	}
}

// fetchBaselineRules lists the live CNPs (in the given namespace, or every
// namespace when namespace is "") and CCNPs (always cluster-wide — CCNPs
// aren't namespace-scoped to begin with) and converts each to Cilium's
// native api.Rules via the same Parse() method the real agent uses — this is
// what "today's policy" means for the verdict subcommand's baseline
// repository.
func fetchBaselineRules(logger *slog.Logger, cilium ciliumclient.Interface, namespace string) (api.Rules, error) {
	ctx := context.Background()
	var rules api.Rules

	cnps, err := cilium.CiliumV2().CiliumNetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing CiliumNetworkPolicies in %s: %w", namespaceLabel(namespace), err)
	}
	for i := range cnps.Items {
		parsed, err := cnps.Items[i].Parse(logger, "")
		if err != nil {
			return nil, fmt.Errorf("parsing CiliumNetworkPolicy %s: %w", cnps.Items[i].Name, err)
		}
		rules = append(rules, parsed...)
	}

	ccnps, err := cilium.CiliumV2().CiliumClusterwideNetworkPolicies().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing CiliumClusterwideNetworkPolicies: %w", err)
	}
	for i := range ccnps.Items {
		parsed, err := ccnps.Items[i].Parse(logger, "")
		if err != nil {
			return nil, fmt.Errorf("parsing CiliumClusterwideNetworkPolicy %s: %w", ccnps.Items[i].Name, err)
		}
		rules = append(rules, parsed...)
	}

	return rules, nil
}
