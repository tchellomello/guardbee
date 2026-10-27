package main

// Phase 2 "Replay CLI" from the design doc: diff a candidate policy's
// verdicts against real recent flows. Every sampled flow is judged twice —
// once against today's live CNPs/CCNPs (baseline), once against baseline
// plus the candidate — and by default only the difference is reported,
// matching the design doc's SimulationResult model (newly dropped / newly
// allowed / unchanged); --show-unchanged also prints the UNCHANGED rows.
// --follow keeps judging new flows as they arrive until Ctrl+C, instead of
// stopping after --last.
//
// --namespace is optional: a CiliumNetworkPolicy is always namespace-scoped
// (its EndpointSelector can only ever match pods in its own namespace), so
// one namespace's flows are always the complete picture for one. A
// CiliumClusterwideNetworkPolicy is the opposite by design — it can select
// pods across several namespaces, or all of them — so testing one against
// flows from only one namespace can silently miss a real regression
// elsewhere the CCNP also touches. Omitting --namespace (or passing
// --all-namespaces) samples flows cluster-wide instead, matching hubble
// CLI's own convention for the same tradeoff.
//
// Known v1 simplifications (documented, not silent):
//   - Only ingress-at-destination is evaluated. A flow allowed purely by an
//     egress rule on the source with no ingress restriction on the
//     destination is treated the same as fully default-allow traffic; this
//     covers the common "does my new ingress-selecting CNP break anything"
//     case, not full bidirectional policy correctness.
//   - L7/FQDN-decided flows are flagged NOT_SIMULATED rather than guessed,
//     per the design doc's own stated limit — those verdicts live in Envoy
//     and the DNS proxy, not the policy map this engine computes.
//   - A flow's source/destination identity must already be a real,
//     currently-allocated identity (Hubble resolves these directly on every
//     flow). Candidate-policy labels with no matching live pod are simply
//     never exercised by any sampled flow — this tool never invents a fake
//     identity for them.
//   - Reply packets of an already-established connection (Hubble's
//     is_reply) are skipped entirely, not judged. Connection tracking always
//     allows them regardless of CNP ingress rules, which only gate new
//     connection establishment — judging replies would misreport normal
//     return traffic as NEWLY_DROPPED.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/spf13/pflag"
	"sigs.k8s.io/yaml"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumclient "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// verdictCounts tallies every flow judged in a run — shared between the
// one-shot and --follow code paths so both print the identical summary shape.
type verdictCounts struct {
	newlyDropped, newlyAllowed, unchanged, notSimulated, replySkipped, total int
}

func runVerdict(args []string) {
	fs := pflag.NewFlagSet("verdict", pflag.ExitOnError)
	flags := registerCommonFlags(fs)
	var last uint64
	var follow bool
	var showUnchanged bool
	fs.Uint64Var(&last, "last", 50, "number of recent flows to sample")
	fs.BoolVarP(&follow, "follow", "f", false, "keep judging new flows until Ctrl+C, instead of stopping after --last")
	fs.BoolVar(&showUnchanged, "show-unchanged", false, "also print UNCHANGED rows (deduplicated and grouped last), not just what changed")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %[1]s verdict [-n <namespace>|-A] [--last N] [-f] <candidate.yaml>

Diffs a candidate CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy against
today's live policy state, judging real recent Hubble flows against both.
Prints NEWLY_DROPPED/NEWLY_ALLOWED rows plus an UNCHANGED count, with a
legend explaining every category that occurred. --show-unchanged also
prints UNCHANGED rows (what's confirmed still working), grouped after the
regressions so those stay the first thing you see.

For a CiliumNetworkPolicy, always pass --namespace: that's the one namespace
whose traffic it can possibly affect. For a CiliumClusterwideNetworkPolicy,
omit --namespace (or pass --all-namespaces) so flows are sampled cluster-wide
— otherwise a regression in a namespace the CCNP also touches, but that you
didn't pass to --namespace, would go completely unsampled and unreported.

%[2]s

Flags:
`, binName, numberFlagHelp)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n  %[1]s verdict -n myapp examples/myapp-merge-ready.yaml\n  %[1]s verdict -n myapp --last 200 examples/myapp-wrong-port.yaml\n  %[1]s verdict -n myapp --follow examples/myapp-merge-ready.yaml\n  %[1]s verdict --all-namespaces examples/ccnp-coredns-merge-ready.yaml\n  %[1]s verdict -n myapp --show-unchanged examples/myapp-merge-ready.yaml\n", binName)
	}
	_ = fs.Parse(args)
	namespace := flags.resolveNamespace()
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, binName+" verdict: usage: "+binName+" verdict [-n <namespace>|-A] [--last N] [-f] <candidate.yaml>")
		os.Exit(1)
	}
	candidatePath := fs.Arg(0)

	logger := slog.Default()

	core, cilium, cfg, err := newClientsets(flags.kubeconfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" verdict: building clients: %v\n", err)
		os.Exit(1)
	}
	warnOnVersionSkew(core, cfg)

	candidateRules, err := parseCandidateFile(logger, candidatePath, namespace)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" verdict: parsing candidate %s: %v\n", candidatePath, err)
		os.Exit(1)
	}

	baselineRuleCount, baseline, candidate, err := buildVerdictEngines(logger, cilium, namespace, candidateRules)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" verdict: %v\n", err)
		os.Exit(1)
	}
	defer baseline.close(logger)
	defer candidate.close(logger)

	counts := &verdictCounts{}

	if follow {
		fmt.Printf("Judging %d candidate rule(s) from %s against %d live rule(s) already in %s — streaming flows live, Ctrl+C to stop.\n\n",
			len(candidateRules), candidatePath, baselineRuleCount, namespaceLabel(namespace))

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		total, err := streamFlows(ctx, core, cfg, namespace, last, func(f *flowpb.Flow) {
			if row := judgeFlow(logger, baseline, candidate, f, counts, showUnchanged); row != nil {
				fmt.Println(row.line(1))
			}
		})
		counts.total = total
		if err != nil {
			fmt.Fprintf(os.Stderr, binName+" verdict: %v\n", err)
			os.Exit(1)
		}
		printVerdictSummary(counts)
		return
	}

	comp, err := judgeFlowBatch(logger, baseline, candidate, core, cfg, namespace, last, showUnchanged)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" verdict: %v\n", err)
		os.Exit(1)
	}
	comp.candidateRuleCount = len(candidateRules)
	comp.baselineRuleCount = baselineRuleCount
	printVerdictComputation(comp, candidatePath)
}

// verdictComputation is the structured result of one one-shot verdict run —
// the single source of truth both the CLI's printed output and the "ui"
// subcommand's JSON API are built from (see printVerdictComputation and
// ui.go's handleVerdict), so the two can never compute a different answer,
// only present the same one differently.
type verdictComputation struct {
	namespace                             string
	candidateRuleCount, baselineRuleCount int
	flowsRequested                        uint64
	flowsSampled                          int
	counts                                *verdictCounts
	rows                                  []*verdictRow
	rowCounts                             []int // seen-Nx count, same index as rows
}

// computeVerdict is the full, self-contained one-shot verdict computation:
// fetches baseline policy, builds both engines, then delegates to
// judgeFlowBatch. The CLI's runVerdict builds its own engines inline instead
// (shared with the --follow path, which this function has no equivalent
// for) — this wrapper exists for callers that just want one answer with no
// engine lifecycle to manage themselves, namely the "ui" subcommand's HTTP
// API (see ui.go).
func computeVerdict(logger *slog.Logger, core kubernetes.Interface, cilium ciliumclient.Interface, cfg *rest.Config, namespace string, candidateRules api.Rules, last uint64, showUnchanged bool) (*verdictComputation, error) {
	baselineRuleCount, baseline, candidate, err := buildVerdictEngines(logger, cilium, namespace, candidateRules)
	if err != nil {
		return nil, err
	}
	defer baseline.close(logger)
	defer candidate.close(logger)

	comp, err := judgeFlowBatch(logger, baseline, candidate, core, cfg, namespace, last, showUnchanged)
	if err != nil {
		return nil, err
	}
	comp.candidateRuleCount = len(candidateRules)
	comp.baselineRuleCount = baselineRuleCount
	return comp, nil
}

// buildVerdictEngines fetches baseline policy and constructs both the
// baseline and baseline+candidate policy.Repository-backed engines — the
// setup step shared by computeVerdict (one-shot), runVerdict's own --follow
// path, and the "ui" subcommand's streaming handler (see ui.go's
// handleVerdictStream). Callers own closing both engines (defer
// baseline.close/candidate.close) once done with them. Both engines start
// with no known identities — every flow registers its own source/
// destination identity the first time it's judged (verdictEngine.
// addIdentities), rather than pre-seeding from a bounded batch — that's
// what lets --follow/streaming keep working correctly no matter how long it
// runs or how many new identities show up over time.
func buildVerdictEngines(logger *slog.Logger, cilium ciliumclient.Interface, namespace string, candidateRules api.Rules) (baselineRuleCount int, baseline, candidate *verdictEngine, err error) {
	baselineRules, err := fetchBaselineRules(logger, cilium, namespace)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("fetching baseline policy: %w", err)
	}

	baseline, err = newVerdictEngine(logger, baselineRules, identity.IdentityMap{})
	if err != nil {
		return 0, nil, nil, fmt.Errorf("building baseline engine: %w", err)
	}

	candidate, err = newVerdictEngine(logger, append(append(api.Rules{}, baselineRules...), candidateRules...), identity.IdentityMap{})
	if err != nil {
		baseline.close(logger)
		return 0, nil, nil, fmt.Errorf("building candidate engine: %w", err)
	}

	return len(baselineRules), baseline, candidate, nil
}

// judgeFlowBatch fetches flows for namespace and judges each one against the
// already-built baseline/candidate engines, deduplicating identical rows
// (see judgeFlow/verdictRow.key) and grouping them NEWLY_DROPPED, then
// NEWLY_ALLOWED, then UNCHANGED (only present with showUnchanged). This is
// the one-shot counterpart to runVerdict's --follow loop — same judging
// logic (judgeFlow), batched instead of streamed, and reusable by both the
// CLI and the "ui" subcommand's HTTP API.
func judgeFlowBatch(logger *slog.Logger, baseline, candidate *verdictEngine, core kubernetes.Interface, cfg *rest.Config, namespace string, last uint64, showUnchanged bool) (*verdictComputation, error) {
	flows, err := fetchFlows(core, cfg, namespace, last)
	if err != nil {
		return nil, fmt.Errorf("tapping flows: %w", err)
	}

	counts := &verdictCounts{}
	order := make([]string, 0, len(flows))
	rowsByKey := map[string]*verdictRow{}
	seen := map[string]int{}
	for _, f := range flows {
		row := judgeFlow(logger, baseline, candidate, f, counts, showUnchanged)
		if row == nil {
			continue
		}
		k := row.key()
		if _, ok := rowsByKey[k]; !ok {
			rowsByKey[k] = row
			order = append(order, k)
		}
		seen[k]++
	}
	counts.total = len(flows)

	comp := &verdictComputation{
		namespace:      namespace,
		flowsRequested: last,
		flowsSampled:   len(flows),
		counts:         counts,
	}
	for _, cat := range []string{"NEWLY_DROPPED", "NEWLY_ALLOWED", "UNCHANGED"} {
		for _, k := range order {
			if rowsByKey[k].change != cat {
				continue
			}
			comp.rows = append(comp.rows, rowsByKey[k])
			comp.rowCounts = append(comp.rowCounts, seen[k])
		}
	}
	return comp, nil
}

// printVerdictComputation renders a verdictComputation exactly as the CLI's
// one-shot verdict output always has.
func printVerdictComputation(comp *verdictComputation, candidatePath string) {
	if comp.flowsSampled == 0 {
		fmt.Println("no flows observed for " + namespaceLabel(comp.namespace) + " in Hubble's current buffer — nothing to simulate")
		return
	}

	if uint64(comp.flowsSampled) < comp.flowsRequested {
		fmt.Printf("Judging %d candidate rule(s) from %s against %d live rule(s) already in %s, using %d of up to %d requested flows — that's every flow Hubble's live buffer currently holds for this scope, not a shortfall in this tool; use --follow to keep sampling over time instead of raising --last.\n\n",
			comp.candidateRuleCount, candidatePath, comp.baselineRuleCount, namespaceLabel(comp.namespace), comp.flowsSampled, comp.flowsRequested)
	} else {
		fmt.Printf("Judging %d candidate rule(s) from %s against %d live rule(s) already in %s, using %d sampled flows.\n\n",
			comp.candidateRuleCount, candidatePath, comp.baselineRuleCount, namespaceLabel(comp.namespace), comp.flowsSampled)
	}

	for i, row := range comp.rows {
		fmt.Println(row.line(comp.rowCounts[i]))
	}
	printVerdictSummary(comp.counts)
}

// verdictRow is one reportable verdict change — NEWLY_DROPPED/NEWLY_ALLOWED
// always, UNCHANGED only when --show-unchanged is set — keyed so identical
// rows across multiple flows (e.g. a kubelet probe firing repeatedly) can be
// deduplicated and shown once with a count.
type verdictRow struct {
	change   string
	src, dst string
	proto    string
	port     uint16
}

func (r *verdictRow) key() string {
	return fmt.Sprintf("%s|%s|%s|%s:%d", r.change, r.src, r.dst, r.proto, r.port)
}

// line renders this row, appending a "(seen Nx in this sample)" suffix when
// count > 1 instead of printing the same row once per occurrence.
func (r *verdictRow) line(count int) string {
	suffix := ""
	if count > 1 {
		suffix = fmt.Sprintf("  (seen %dx in this sample)", count)
	}
	return fmt.Sprintf("%s  %s -> %s  %s:%d  %s%s",
		colorizePadded(changeColor(r.change), r.change, 13), r.src, r.dst, r.proto, r.port, changeExplanation(r.change), suffix)
}

// judgeFlow is the one piece of judging logic shared by the one-shot and
// --follow code paths: register this flow's identities with both engines,
// skip what can't be simulated, compute both verdicts, tally the result into
// counts, and return a *verdictRow for the caller to print or dedup — always
// for NEWLY_DROPPED/NEWLY_ALLOWED, for UNCHANGED only when showUnchanged is
// set, nil otherwise (skipped/not-simulated, or UNCHANGED without
// showUnchanged).
func judgeFlow(logger *slog.Logger, baseline, candidate *verdictEngine, f *flowpb.Flow, counts *verdictCounts, showUnchanged bool) *verdictRow {
	// Reply packets of an already-established connection are always allowed
	// by Cilium's connection tracking, regardless of CNP ingress rules —
	// those only gate new connection establishment. Judging replies against
	// the policy engine would misreport them as NEWLY_DROPPED.
	if f.GetIsReply().GetValue() {
		counts.replySkipped++
		return nil
	}

	src, dst := f.GetSource(), f.GetDestination()
	if src == nil || dst == nil || src.GetIdentity() == 0 || dst.GetIdentity() == 0 {
		counts.notSimulated++
		return nil
	}
	if f.GetL7() != nil {
		counts.notSimulated++
		return nil
	}

	newIDs := identitiesFromFlows([]*flowpb.Flow{f})
	baseline.addIdentities(logger, newIDs)
	candidate.addIdentities(logger, newIDs)

	var key policy.Key
	srcNID := identity.NumericIdentity(src.GetIdentity())
	dstNID := identity.NumericIdentity(dst.GetIdentity())
	l4 := f.GetL4()
	var proto string
	switch {
	case l4.GetTCP() != nil:
		proto = "TCP"
		port := uint16(l4.GetTCP().GetDestinationPort())
		// A flow with no concrete destination port can't be queried via
		// isAllowed/Lookup: mapState.lookup's own doc comment requires "a
		// non-wildcard port" in the query key, and WithTCPPort(0) builds
		// exactly that wildcard — querying it doesn't error, but Cilium's
		// own ancestor-LPM walk then only matches other full-wildcard-port
		// entries, silently missing any specific-port rule. Seen in
		// practice on real clusters for UDP flows Hubble reports with
		// DestinationPort 0.
		if port == 0 {
			counts.notSimulated++
			return nil
		}
		key = policy.IngressKey().WithIdentity(srcNID).WithTCPPort(port)
	case l4.GetUDP() != nil:
		proto = "UDP"
		port := uint16(l4.GetUDP().GetDestinationPort())
		if port == 0 {
			counts.notSimulated++
			return nil
		}
		key = policy.IngressKey().WithIdentity(srcNID).WithUDPPort(port)
	default:
		counts.notSimulated++
		return nil
	}

	baseEpp, err := baseline.distillFor(logger, dstNID)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" verdict: baseline: %v\n", err)
		counts.notSimulated++
		return nil
	}
	candEpp, err := candidate.distillFor(logger, dstNID)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" verdict: candidate: %v\n", err)
		counts.notSimulated++
		return nil
	}

	baseAllow := isAllowed(baseEpp, key)
	candAllow := isAllowed(candEpp, key)

	var change string
	switch {
	case baseAllow == candAllow:
		change = "UNCHANGED"
		counts.unchanged++
	case candAllow:
		change = "NEWLY_ALLOWED"
		counts.newlyAllowed++
	default:
		change = "NEWLY_DROPPED"
		counts.newlyDropped++
	}

	if change == "UNCHANGED" && !showUnchanged {
		return nil
	}
	return &verdictRow{change: change, src: endpointString(src), dst: endpointString(dst), proto: proto, port: key.DestPort}
}

// changeExplanation gives a one-line, non-jargon reason for a row, printed
// inline so a reader doesn't need the legend to understand a single row.
func changeExplanation(change string) string {
	switch change {
	case "NEWLY_DROPPED":
		return "(currently allowed; this candidate would start blocking it)"
	case "UNCHANGED":
		return "(same with or without this candidate)"
	case "NEWLY_ALLOWED":
		return "(currently blocked; this candidate would start allowing it)"
	default:
		return ""
	}
}

func printVerdictSummary(counts *verdictCounts) {
	fmt.Printf("\n%d flows sampled: %s unchanged, %s newly dropped, %s newly allowed, %s not simulated, %s reply (skipped)\n",
		counts.total,
		colorize(changeColor("UNCHANGED"), fmt.Sprintf("%d", counts.unchanged)),
		colorize(changeColor("NEWLY_DROPPED"), fmt.Sprintf("%d", counts.newlyDropped)),
		colorize(changeColor("NEWLY_ALLOWED"), fmt.Sprintf("%d", counts.newlyAllowed)),
		colorize(ansiGray, fmt.Sprintf("%d", counts.notSimulated)),
		colorize(ansiGray, fmt.Sprintf("%d", counts.replySkipped)),
	)

	if counts.newlyDropped > 0 {
		fmt.Printf("\n%s\n", colorize(ansiBold+ansiRed,
			fmt.Sprintf("%d real flow(s) would BREAK if this candidate merged as-is — review the NEWLY_DROPPED rows above before shipping it.", counts.newlyDropped)))
	}
	printVerdictLegend(counts)
}

// printVerdictLegend explains only the categories that actually showed up in
// counts this run — a clean pass with zero NEWLY_ALLOWED/not-simulated/reply
// rows doesn't need those three lines explained. UNCHANGED's line only
// appears if something besides UNCHANGED happened too, since an all-UNCHANGED
// run needs no legend at all.
func printVerdictLegend(counts *verdictCounts) {
	anyChange := counts.newlyDropped > 0 || counts.newlyAllowed > 0
	if !anyChange && counts.notSimulated == 0 && counts.replySkipped == 0 {
		return
	}

	fmt.Println("\nLegend:")
	if anyChange {
		fmt.Printf("  %s       verdict is the same with or without the candidate.\n", colorize(changeColor("UNCHANGED"), "UNCHANGED"))
	}
	if counts.newlyDropped > 0 {
		fmt.Printf("  %s   currently allowed, the candidate would block it — a regression to review before merging.\n", colorize(changeColor("NEWLY_DROPPED"), "NEWLY_DROPPED"))
	}
	if counts.newlyAllowed > 0 {
		fmt.Printf("  %s   currently blocked, the candidate would allow it — expected if that's the policy's purpose, worth a second look if not.\n", colorize(changeColor("NEWLY_ALLOWED"), "NEWLY_ALLOWED"))
	}
	if counts.notSimulated > 0 {
		fmt.Printf("  %s   L7/FQDN-decided or unresolved-identity flows; this engine doesn't judge those (see README).\n", colorize(ansiGray, "not simulated"))
	}
	if counts.replySkipped > 0 {
		fmt.Printf("  %s established-connection replies; connection tracking always allows these regardless of policy.\n", colorize(ansiGray, "reply (skipped)"))
	}
}

// identitiesFromFlows extracts every distinct (numeric identity, labels)
// pair Hubble has already resolved on the given flows. Real flows always
// carry real, currently-allocated identities, so this needs no separate
// CiliumIdentity lookup.
func identitiesFromFlows(flows []*flowpb.Flow) identity.IdentityMap {
	ids := identity.IdentityMap{}
	add := func(ep *flowpb.Endpoint) {
		if ep == nil || ep.GetIdentity() == 0 {
			return
		}
		ids[identity.NumericIdentity(ep.GetIdentity())] = labels.ParseLabelArray(ep.GetLabels()...)
	}
	for _, f := range flows {
		add(f.GetSource())
		add(f.GetDestination())
	}
	return ids
}

// parseCandidateFile reads a local CiliumNetworkPolicy or
// CiliumClusterwideNetworkPolicy YAML file and converts it to Cilium's
// native api.Rules via the same Parse() the real agent uses.
func parseCandidateFile(logger *slog.Logger, path, defaultNamespace string) (api.Rules, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCandidateYAML(logger, raw, defaultNamespace)
}

// parseCandidateYAML is parseCandidateFile's core: parses a
// CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy from in-memory YAML
// bytes via the same Parse() the real agent uses. Usable directly against
// pasted/uploaded YAML (the "ui" subcommand's web form, see ui.go) without
// needing a file on disk.
func parseCandidateYAML(logger *slog.Logger, raw []byte, defaultNamespace string) (api.Rules, error) {
	decoded, err := decodeCandidateYAML(raw, defaultNamespace)
	if err != nil {
		return nil, err
	}
	return decoded.parse(logger)
}

// decodedCandidate is the raw kind/name/namespace/rule-spec a candidate
// CNP/CCNP's YAML carries, before Cilium's own Parse() turns it into
// engine-ready api.Rules. Split out of parseCandidateYAML so a second
// caller (ui.go's handlePolicyParse, backing the Policy Editor's YAML
// import/hand-edit path) can get at kind/name/namespace/rule — which
// convertRuleToPolicyModel needs — without duplicating the
// CNP-vs-CCNP-vs-unknown-kind switch below a second time.
type decodedCandidate struct {
	kind      string
	name      string
	namespace string
	// rule is firstRuleSpec(spec, specs) — the same v1 simplification
	// handlePolicyForEdit already applies to a live policy's Spec/Specs
	// pair (policies.go), carried over here for a pasted/hand-edited
	// candidate's Spec/Specs pair too.
	rule *api.Rule
	// parse converts the full decoded CNP/CCNP (both Spec and Specs, not
	// just the first entry rule carries) into Cilium's own api.Rules via
	// its generated .Parse() — deferred to a closure rather than done
	// eagerly, since the /api/policy/validate path validates while
	// handlePolicyParse needs it, but handlePolicyForEdit's live-policy
	// analog never does.
	parse func(logger *slog.Logger) (api.Rules, error)
}

func decodeCandidateYAML(raw []byte, defaultNamespace string) (*decodedCandidate, error) {
	var kindOnly struct {
		Kind string `json:"kind"`
	}
	if err := yaml.Unmarshal(raw, &kindOnly); err != nil {
		return nil, fmt.Errorf("reading kind: %w", err)
	}

	switch kindOnly.Kind {
	case "CiliumNetworkPolicy":
		var cnp ciliumv2.CiliumNetworkPolicy
		if err := yaml.Unmarshal(raw, &cnp); err != nil {
			return nil, err
		}
		if cnp.ObjectMeta.Namespace == "" {
			// A CiliumNetworkPolicy is always namespace-scoped — it needs a
			// namespace from somewhere. defaultNamespace is "" whenever
			// --namespace was omitted or --all-namespaces was passed, which
			// only makes sense for a CiliumClusterwideNetworkPolicy
			// candidate; a namespaced CNP candidate must set its own
			// metadata.namespace in that case, or pass --namespace instead.
			if defaultNamespace == "" {
				return nil, fmt.Errorf("this CiliumNetworkPolicy candidate has no metadata.namespace, and no namespace was given to default it to — set metadata.namespace in the candidate, or pass --namespace <ns>")
			}
			cnp.ObjectMeta.Namespace = defaultNamespace
		}
		// Phase 2 adaptive gating (compat.go) runs here, on the raw
		// Spec/Specs, before anyone calls .Parse() — Parse() itself never
		// rejects a deprecated construct like FromRequires/ToRequires, it
		// silently drops it while building the real api.Rule (see
		// compat.go's doc comment), so checking Parse()'s own output
		// would always find an already-empty field and never catch
		// anything. Checked here (decode time) rather than only inside
		// the parse closure below so both callers — parseCandidateYAML's
		// wrapper and ui.go's handlePolicyParse, which calls
		// decoded.parse() directly — are covered by one check.
		if err := checkFeatureGates(rawRules(cnp.Spec, cnp.Specs), pinnedCiliumVersion); err != nil {
			return nil, err
		}
		return &decodedCandidate{
			kind:      kindOnly.Kind,
			name:      cnp.ObjectMeta.Name,
			namespace: cnp.ObjectMeta.Namespace,
			rule:      firstRuleSpec(cnp.Spec, cnp.Specs),
			parse:     func(logger *slog.Logger) (api.Rules, error) { return cnp.Parse(logger, "") },
		}, nil
	case "CiliumClusterwideNetworkPolicy":
		var ccnp ciliumv2.CiliumClusterwideNetworkPolicy
		if err := yaml.Unmarshal(raw, &ccnp); err != nil {
			return nil, err
		}
		if err := checkFeatureGates(rawRules(ccnp.Spec, ccnp.Specs), pinnedCiliumVersion); err != nil {
			return nil, err
		}
		return &decodedCandidate{
			kind:  kindOnly.Kind,
			name:  ccnp.ObjectMeta.Name,
			rule:  firstRuleSpec(ccnp.Spec, ccnp.Specs),
			parse: func(logger *slog.Logger) (api.Rules, error) { return ccnp.Parse(logger, "") },
		}, nil
	default:
		return nil, fmt.Errorf("unsupported kind %q (expected CiliumNetworkPolicy or CiliumClusterwideNetworkPolicy)", kindOnly.Kind)
	}
}

// isAllowed reports the verdict for key. Uses Lookup (not Get) because Get is
// an exact-match-only lookup and misses broader covering entries — e.g. a
// rule that allows a peer on every port (no ToPorts) produces a wildcard-port
// entry; Get wouldn't find it for a specific-port query, Lookup's LPM match
// does. Only a true miss (no covering entry at any specificity) falls back
// to the endpoint's own default mode (default-allow if no policy selects it,
// default-deny if one does) — most namespaces have no CNPs at all, and that
// must read as allow.
func isAllowed(epp *policy.EndpointPolicy, key policy.Key) bool {
	if entry, _, found := epp.Lookup(key); found {
		return entry.IsAllow()
	}
	return !epp.SelectorPolicy.IngressPolicyEnabled
}

// noopPolicyMetrics is a minimal types.PolicyMetrics implementation — this
// CLI has no Prometheus registry to report rule add/remove counts to.
type noopPolicyMetrics struct{}

func (noopPolicyMetrics) AddRule(policytypes.PolicyEntry) {}
func (noopPolicyMetrics) DelRule(policytypes.PolicyEntry) {}

// verdictOwner is a minimal policy.PolicyOwner stub — DistillPolicy needs an
// "endpoint" to distill for, but doesn't need a real one to compute verdicts.
type verdictOwner struct {
	id identity.NumericIdentity
}

func (o verdictOwner) GetID() uint64                                              { return uint64(o.id) }
func (verdictOwner) GetIngressNamedPort(name string, proto u8proto.U8proto) uint16 { return 0 }
func (verdictOwner) PolicyDebug(msg string, attrs ...any)                         {}
func (verdictOwner) IsHost() bool                                                  { return false }
func (verdictOwner) PreviousMapStateSizes() policy.MapStateSizes                   { return policy.MapStateSizes{} }
func (verdictOwner) RegenerateIfAlive(_ *regeneration.ExternalRegenerationMetadata) <-chan bool {
	return nil
}

// verdictEngine wraps a policy.Repository built from a fixed rule set, with
// identities registered incrementally as flows are judged (see
// addIdentities) rather than pre-seeded from a bounded batch — this is what
// lets --follow keep working correctly indefinitely. Distilled EndpointPolicy
// per destination identity is cached, since many flows share a destination.
type verdictEngine struct {
	repo       *policy.Repository
	identities identity.IdentityMap
	cache      map[identity.NumericIdentity]*policy.EndpointPolicy
}

func newVerdictEngine(logger *slog.Logger, rules api.Rules, identities identity.IdentityMap) (*verdictEngine, error) {
	idMgr := identitymanager.NewIDManager(logger)
	repo := policy.NewPolicyRepository(
		logger,
		nil,
		nil,
		envoypolicy.NewEnvoyL7RulesTranslator(logger, certificatemanager.NewMockSecretManagerInline()),
		idMgr,
		noopPolicyMetrics{},
	)

	wg := &sync.WaitGroup{}
	repo.GetSelectorCache().UpdateIdentities(identities, nil, wg)
	wg.Wait()
	// Separate from the peer selector cache above — ComputeSelectorPolicy
	// reads subject-matching (rule.EndpointSelector) state from here.
	repo.UpdateIdentities(identities, nil)

	repo.MustAddList(rules)

	engine := &verdictEngine{
		repo:       repo,
		identities: identity.IdentityMap{},
		cache:      map[identity.NumericIdentity]*policy.EndpointPolicy{},
	}
	for nid, lbls := range identities {
		engine.identities[nid] = lbls
	}
	return engine, nil
}

// addIdentities registers any newly-seen identities with the repository's
// selector caches (both the peer and subject ones — see newVerdictEngine's
// comment on why there are two). A new peer identity can change what any
// previously-distilled destination's policy allows (e.g. it might newly
// match a FromEndpoints selector), so the distill cache is invalidated
// whenever something new shows up, rather than risk a stale verdict.
func (e *verdictEngine) addIdentities(logger *slog.Logger, newIDs identity.IdentityMap) {
	added := identity.IdentityMap{}
	for nid, lbls := range newIDs {
		if _, known := e.identities[nid]; !known {
			added[nid] = lbls
			e.identities[nid] = lbls
		}
	}
	if len(added) == 0 {
		return
	}

	wg := &sync.WaitGroup{}
	e.repo.GetSelectorCache().UpdateIdentities(added, nil, wg)
	wg.Wait()
	e.repo.UpdateIdentities(added, nil)

	for nid, epp := range e.cache {
		epp.Detach(logger)
		delete(e.cache, nid)
	}
}

func (e *verdictEngine) distillFor(logger *slog.Logger, nid identity.NumericIdentity) (*policy.EndpointPolicy, error) {
	if epp, ok := e.cache[nid]; ok {
		return epp, nil
	}
	lbls, ok := e.identities[nid]
	if !ok {
		return nil, fmt.Errorf("identity %d not yet known to this engine", nid)
	}

	id := identity.NewIdentity(nid, lbls.Labels())
	sp, err := e.repo.ResolvePolicy(id)
	if err != nil {
		return nil, fmt.Errorf("resolving policy for identity %d: %w", nid, err)
	}
	epp := sp.DistillPolicy(logger, verdictOwner{id: nid}, map[string]uint16{})
	if epp == nil {
		return nil, fmt.Errorf("distilling policy for identity %d returned nil", nid)
	}
	epp.Ready()
	e.cache[nid] = epp
	return epp, nil
}

func (e *verdictEngine) close(logger *slog.Logger) {
	for _, epp := range e.cache {
		epp.Detach(logger)
	}
}
