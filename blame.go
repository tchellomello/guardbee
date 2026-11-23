package main

// "blame" subcommand (issue #18): which live policy allowed or denied a
// workload's real traffic. Unlike "verdict", nothing here is simulated —
// the answer is the attribution Cilium's own agent attached to each
// policy-verdict event (pkg/policy/correlation: ingress/egress_allowed_by,
// ingress/egress_denied_by), read off Hubble the way
// `hubble observe --pod X --type policy-verdict -o json | jq` would. The
// same flowAttribution backs the UI's Flows tab (toFlowOut), so the CLI and
// the browser can't disagree on who to blame for a flow.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/spf13/pflag"
)

// policyRef is one policy Hubble attributed a verdict to (flowpb.Policy).
// Kind is Cilium's io.cilium.k8s.policy.derived-from label as-is:
// CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy, NetworkPolicy or
// ClusterNetworkPolicy — never guessed when Cilium left it empty.
type policyRef struct {
	Kind      string   `json:"kind,omitempty"`
	Namespace string   `json:"namespace,omitempty"`
	Name      string   `json:"name,omitempty"`
	Labels    []string `json:"labels,omitempty"`
	Revision  uint64   `json:"revision,omitempty"`
	// Display is String(), sent so the UI's badges read exactly like the CLI.
	Display string `json:"display"`
}

// String renders a ref compactly: "CNP:ns/name", "CCNP:name", or the kind
// spelled out for anything else ("NetworkPolicy:ns/name"). A rule with no
// name label (not one derived from a Kubernetes object) shows its labels
// instead, since that's all Cilium knows about it.
func (p policyRef) String() string {
	if p.Name == "" {
		if len(p.Labels) == 0 {
			return "(unnamed rule)"
		}
		return "rule{" + strings.Join(p.Labels, ",") + "}"
	}
	prefix := ""
	switch p.Kind {
	case "CiliumNetworkPolicy":
		prefix = "CNP:"
	case "CiliumClusterwideNetworkPolicy":
		prefix = "CCNP:"
	case "":
	default:
		prefix = p.Kind + ":"
	}
	if p.Namespace != "" {
		return prefix + p.Namespace + "/" + p.Name
	}
	return prefix + p.Name
}

func toPolicyRefs(in []*flowpb.Policy) []policyRef {
	var out []policyRef
	for _, p := range in {
		if p == nil || (p.GetName() == "" && len(p.GetLabels()) == 0) {
			continue
		}
		ref := policyRef{
			Kind:      p.GetKind(),
			Namespace: p.GetNamespace(),
			Name:      p.GetName(),
			Labels:    p.GetLabels(),
			Revision:  p.GetRevision(),
		}
		ref.Display = ref.String()
		out = append(out, ref)
	}
	return out
}

// Decisions flowAttribution reports. Only policy decisions get one — a drop
// for any other reason (CT, routing, …) isn't a policy's doing.
const (
	decisionAllowed     = "allowed"      // FORWARDED/REDIRECTED by policy
	decisionDenied      = "denied"       // DROPPED by an explicit deny rule (POLICY_DENY)
	decisionDefaultDeny = "default-deny" // DROPPED because no rule allows it (POLICY_DENIED)
	decisionAudit       = "audit"        // allowed only because of audit mode; would be denied
)

// attribution is why Cilium allowed or denied one flow.
type attribution struct {
	Decision  string      `json:"decision,omitempty"`
	AllowedBy []policyRef `json:"allowedBy,omitempty"`
	DeniedBy  []policyRef `json:"deniedBy,omitempty"`
	// DecidedBy is the one-line, human-readable answer, the same text the
	// CLI prints and the UI shows.
	DecidedBy string `json:"decidedBy,omitempty"`
}

// flowAttribution reads Cilium's own attribution off a flow, following
// exactly what pkg/policy/correlation.CorrelatePolicy (v1.20.4) does when it
// fills these fields in, so the reading can't claim more than Cilium said:
//
//   - Only policy-verdict events are correlated; any other event type gets
//     no attribution at all, never a guess.
//   - The agent fills only the field for the flow's own direction:
//     *_allowed_by on FORWARDED/REDIRECTED, *_denied_by on a POLICY_DENY/
//     POLICY_DENIED drop or an AUDIT. Ingress and egress are merged here,
//     since a flow carries one; the direction is its TrafficDirection.
//   - Correlation can fail silently (no port, endpoint gone, correlation
//     disabled with hubble-network-policy-correlation-enabled=false), so an
//     empty list proves nothing about *which* rule. The two drop reasons do:
//     POLICY_DENY (181) means an explicit deny rule matched, POLICY_DENIED
//     (133) means nothing allowed it (default deny). Only the latter is
//     reported as default-deny; an unattributed POLICY_DENY is still a
//     deny rule, and an unattributed allow is just that — not "no policy
//     selects the endpoint", which would be a guess.
func flowAttribution(f *flowpb.Flow) attribution {
	if f.GetEventType().GetType() != int32(monitorAPI.MessageTypePolicyVerdict) {
		return attribution{}
	}
	a := attribution{
		AllowedBy: toPolicyRefs(slices.Concat(f.GetIngressAllowedBy(), f.GetEgressAllowedBy())),
		DeniedBy:  toPolicyRefs(slices.Concat(f.GetIngressDeniedBy(), f.GetEgressDeniedBy())),
	}
	refs := func(rs []policyRef) string {
		names := make([]string, len(rs))
		for i, r := range rs {
			names[i] = r.String()
		}
		return strings.Join(names, ", ")
	}
	switch v := f.GetVerdict(); {
	case v == flowpb.Verdict_FORWARDED || v == flowpb.Verdict_REDIRECTED:
		a.Decision = decisionAllowed
		a.DecidedBy = "allowed, no policy attributed by Hubble"
		if len(a.AllowedBy) > 0 {
			a.DecidedBy = "allowed by " + refs(a.AllowedBy)
		}
	case v == flowpb.Verdict_AUDIT:
		a.Decision = decisionAudit
		a.DecidedBy = "audit: would be denied, no policy attributed by Hubble"
		if len(a.DeniedBy) > 0 {
			a.DecidedBy = "audit: would be denied by " + refs(a.DeniedBy)
		}
	case v == flowpb.Verdict_DROPPED && len(a.DeniedBy) > 0:
		a.Decision = decisionDenied
		a.DecidedBy = "denied by " + refs(a.DeniedBy)
	case v == flowpb.Verdict_DROPPED && f.GetDropReasonDesc() == flowpb.DropReason_POLICY_DENY:
		a.Decision = decisionDenied
		a.DecidedBy = "denied by a deny rule, not attributed by Hubble"
	case v == flowpb.Verdict_DROPPED && f.GetDropReasonDesc() == flowpb.DropReason_POLICY_DENIED:
		a.Decision = decisionDefaultDeny
		a.DecidedBy = "default deny: no policy rule allows it"
	}
	return a
}

// trafficDirection is the side the verdict was taken on (INGRESS/EGRESS),
// or "" when Hubble doesn't say.
func trafficDirection(f *flowpb.Flow) string {
	switch f.GetTrafficDirection() {
	case flowpb.TrafficDirection_INGRESS, flowpb.TrafficDirection_EGRESS:
		return f.GetTrafficDirection().String()
	}
	return ""
}

// flowOut is one observed flow as JSON: the UI's Flows tab rows (GET
// /api/flows and its stream) and `blame --format json` alike. This is
// Hubble's own already-happened verdict, straight off the datapath — not
// this tool's simulated one — so it's squarely in-bounds despite the
// simulator's own limits (see AGENTS.md's known v1 simplifications):
// nothing here is being guessed.
type flowOut struct {
	Time    string `json:"time"`
	Verdict string `json:"verdict"`
	// DropReason only on a dropped flow — DROP_REASON_UNKNOWN on every
	// forwarded one would just be noise.
	DropReason  string `json:"dropReason,omitempty"`
	Direction   string `json:"direction,omitempty"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	L4          string `json:"l4"`
	// The endpoints' security-identity labels as Hubble reports them
	// (k8s:app=web, reserved:world, …): what the filter fields' autocomplete
	// offers for --from-label/--to-label, so a label seen in real traffic can
	// be picked instead of typed.
	SourceLabels      []string `json:"sourceLabels,omitempty"`
	DestinationLabels []string `json:"destinationLabels,omitempty"`
	attribution
}

func toFlowOut(f *flowpb.Flow) flowOut {
	out := flowOut{
		Time:        f.GetTime().AsTime().Format(time.RFC3339),
		Verdict:     f.GetVerdict().String(),
		Direction:   trafficDirection(f),
		Source:      endpointString(f.GetSource()),
		Destination: endpointString(f.GetDestination()),
		L4:          l4String(f.GetL4()),

		SourceLabels:      f.GetSource().GetLabels(),
		DestinationLabels: f.GetDestination().GetLabels(),
		attribution:       flowAttribution(f),
	}
	if reason := f.GetDropReasonDesc(); reason != flowpb.DropReason_DROP_REASON_UNKNOWN {
		out.DropReason = reason.String()
	}
	return out
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// blameLine is one flow as a terminal line, with the attribution where the
// flows subcommand has none.
func blameLine(f flowOut) string {
	return fmt.Sprintf("%s  %s  %-7s  %s -> %s  %s  %s",
		f.Time,
		colorizePadded(flowVerdictColor(f.Verdict), f.Verdict, 9),
		dashIfEmpty(f.Direction),
		f.Source,
		f.Destination,
		f.L4,
		dashIfEmpty(f.DecidedBy),
	)
}

func writeBlameMarkdown(w io.Writer, namespace string, filter flowFilter, rows []flowOut) {
	fmt.Fprintf(w, "### %s blame — %s\n\n", binName, namespaceLabel(namespace))
	if s := filter.String(); s != "" {
		fmt.Fprintf(w, "Only flows matching `%s`.\n\n", s)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "_No matching flows in Hubble's buffer._")
		return
	}
	fmt.Fprintln(w, "| Time | Verdict | Direction | Source | Destination | L4 | Decided by | Drop reason |")
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|")
	for _, r := range rows {
		fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s | %s | %s |\n",
			r.Time, r.Verdict, dashIfEmpty(r.Direction), mdCell(r.Source), mdCell(r.Destination), r.L4,
			mdCell(dashIfEmpty(r.DecidedBy)), dashIfEmpty(r.DropReason))
	}
}

// blameScope turns blame's optional positional [namespace/]<pod> into a
// --pod value, and — when neither -n nor -A was given — scopes the run to
// that pod's namespace, so `blame myapp/api` reads like `hubble observe
// --pod myapp/api`.
func blameScope(positional []string, namespace string, allNamespaces bool, filter flowFilter) (string, flowFilter, error) {
	if len(positional) > 1 {
		return "", filter, fmt.Errorf("expected at most one [namespace/]<pod-name>, got %d", len(positional))
	}
	if len(positional) == 1 && strings.TrimSpace(positional[0]) != "" {
		pod := strings.TrimSpace(positional[0])
		filter.pods = append([]string{pod}, filter.pods...)
		if ns, _, ok := strings.Cut(pod, "/"); ok && ns != "" && namespace == "" && !allNamespaces {
			namespace = ns
		}
	}
	// policy-verdict is the only event Cilium attributes; --type overrides it.
	if len(filter.types) == 0 {
		filter.types = []string{monitorAPI.MessageTypeNamePolicyVerdict}
	}
	return namespace, filter, nil
}

func runBlame(args []string) {
	fs := pflag.NewFlagSet("blame", pflag.ExitOnError)
	flags := registerCommonFlags(fs)
	filterFlags := registerFlowFilterFlags(fs)
	registerHubbleAddrFlag(fs)
	var last uint64
	var follow bool
	var format string
	fs.Uint64Var(&last, "last", 20, "number of recent flows to print")
	fs.BoolVarP(&follow, "follow", "f", false, "keep streaming new flows until Ctrl+C, instead of stopping after --last")
	fs.StringVar(&format, "format", formatTable, "output format: table, json or markdown (markdown: one-shot only; json with --follow: one object per line)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %[1]s blame [[namespace/]<pod-name>] [-n <namespace>|-A] [--pod|--from-*|--to-*|--verdict|--type ...] [--last N] [-f]

Shows which live policy allowed or denied real traffic: for each Hubble
policy-verdict event, the CiliumNetworkPolicy / CiliumClusterwideNetworkPolicy
(or Kubernetes NetworkPolicy) Cilium's own agent attributed the verdict to,
and on which side (INGRESS/EGRESS) it was taken. A drop no rule allows is
reported as default deny — the fix there is an allow rule, not hunting for
a deny rule. Nothing is simulated: this is what the datapath decided.

The positional [namespace/]<pod-name> is --pod: flows where that pod (a
name prefix) is the source OR the destination, like hubble observe --pod.
Without -n/-A, its namespace becomes the scope. Only policy-verdict events
are fetched (hubble's --type policy-verdict) unless --type says otherwise;
other events carry no attribution. The rest of the filters are the same as
flows and verdict.

%[2]s

Flags:
`, binName, numberFlagHelp)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n  %[1]s blame myapp/api\n  %[1]s blame -n myapp api --verdict DROPPED\n  %[1]s blame myapp/netshoot --to-ip 169.254.169.254 --follow\n  %[1]s blame -n myapp --last 100 --format markdown\n  %[1]s blame -A --verdict DROPPED --drop-reason-desc POLICY_DENIED\n", binName)
	}
	_ = fs.Parse(args)
	checkHubbleAddr("blame")
	filter, err := filterFlags.parse()
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" blame: %v\n", err)
		os.Exit(1)
	}
	namespace, filter, err := blameScope(fs.Args(), flags.resolveNamespace(), flags.allNamespaces, filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" blame: %v\n", err)
		os.Exit(1)
	}
	if !validVerdictFormat(format) {
		fmt.Fprintf(os.Stderr, "%s blame: --format must be %s, %s or %s, got %q\n", binName, formatTable, formatJSON, formatMarkdown, format)
		os.Exit(1)
	}
	if follow && format == formatMarkdown {
		fmt.Fprintf(os.Stderr, "%s blame: --format markdown needs a one-shot run, not --follow\n", binName)
		os.Exit(1)
	}
	// Fail on a contradictory filter before touching the cluster.
	if _, err := flowWhitelist(namespace, filter); err != nil {
		fmt.Fprintf(os.Stderr, binName+" blame: %v\n", err)
		os.Exit(1)
	}

	core, _, cfg, err := newClientsets(flags.kubeconfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" blame: building clients: %v\n", err)
		os.Exit(1)
	}
	warnOnVersionSkew(core, cfg)

	if follow {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		enc := json.NewEncoder(os.Stdout)
		count, err := streamFlows(ctx, core, cfg, namespace, filter, last, func(f *flowpb.Flow) {
			if format == formatJSON {
				_ = enc.Encode(toFlowOut(f))
			} else {
				fmt.Println(blameLine(toFlowOut(f)))
			}
		})
		if format == formatTable {
			fmt.Printf("\n%d flows\n", count)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, binName+" blame: %v\n", err)
			os.Exit(1)
		}
		return
	}

	flows, err := fetchFlows(context.Background(), core, cfg, namespace, filter, last)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" blame: %v\n", err)
		os.Exit(1)
	}
	rows := make([]flowOut, len(flows))
	for i, f := range flows {
		rows[i] = toFlowOut(f)
	}
	switch format {
	case formatJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			fmt.Fprintf(os.Stderr, binName+" blame: writing JSON: %v\n", err)
			os.Exit(1)
		}
	case formatMarkdown:
		writeBlameMarkdown(os.Stdout, namespace, filter, rows)
	default:
		for _, r := range rows {
			fmt.Println(blameLine(r))
		}
		fmt.Printf("\n%d flows\n", len(rows))
	}
}
