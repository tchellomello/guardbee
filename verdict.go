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
//   - A flow must be allowed by BOTH the destination's ingress policy and
//     the source's egress policy (each side's own distilled policy, queried
//     for the other side as the peer). Only identity-based egress is judged
//     (endpoints, entities, CIDRs, ports); toFQDNs/L7 egress is
//     NOT_SIMULATED like any other L7 verdict, and a flow whose source is
//     outside the cluster has no egress policy to consult.
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
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
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
	dst := registerDestinationFlags(fs)
	var last uint64
	var follow bool
	var showUnchanged bool
	fs.Uint64Var(&last, "last", 50, "number of recent flows to sample")
	fs.BoolVarP(&follow, "follow", "f", false, "keep judging new flows until Ctrl+C, instead of stopping after --last")
	fs.BoolVar(&showUnchanged, "show-unchanged", false, "also print UNCHANGED rows (deduplicated and grouped last), not just what changed")
	var failOnDropped, replaceExisting bool
	var minFlows int
	var format string
	fs.BoolVar(&failOnDropped, "fail-on-dropped", false, fmt.Sprintf("exit %d if any sampled flow is NEWLY_DROPPED (for CI)", exitVerdictDropped))
	fs.IntVar(&minFlows, "min-flows", 0, fmt.Sprintf("exit %d if fewer than this many flows were actually judged (replies and not-simulated flows don't count); 0 disables", exitVerdictTooFewFlows))
	fs.StringVar(&format, "format", formatTable, "output format: table, json or markdown (json/markdown: one-shot only, not with --follow)")
	fs.BoolVar(&replaceExisting, "replace-existing", false, "judge the candidate as REPLACING any live policy with the same kind, namespace and name, instead of being added on top of it — use for edits to an existing policy")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %[1]s verdict [-n <namespace>|-A] [--to-pod|--to-service|--to-label|--to-port ...] [--last N] [-f] <candidate.yaml>

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

--to-pod/--to-service/--to-label/--to-port judge only flows going to that
destination (hubble observe's semantics, applied in Hubble's query, so all
--last flows are ones that go there). Anything the candidate does to other
destinations is then not sampled at all: narrow to investigate, not to
sign off on a policy.

By default a candidate is judged ON TOP of the live policy set, including a
live policy with the same name. --replace-existing drops that same-name live
policy first, which is what applying the candidate would really do; without
it, rules an edit removes or narrows still allow traffic and the regression
is not reported.

For CI: --fail-on-dropped exits %[3]d on any NEWLY_DROPPED flow, --min-flows N
exits %[4]d when fewer than N flows were judged (so an empty sample can't read
as a pass), and --format json|markdown prints a machine-readable result or a
PR-comment summary. Errors always exit 1; a dropped flow outranks a thin sample.

%[2]s

Flags:
`, binName, numberFlagHelp, exitVerdictDropped, exitVerdictTooFewFlows)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n  %[1]s verdict -n myapp examples/myapp-merge-ready.yaml\n  %[1]s verdict -n myapp --last 200 examples/myapp-wrong-port.yaml\n  %[1]s verdict -n myapp --follow examples/myapp-merge-ready.yaml\n  %[1]s verdict --all-namespaces examples/ccnp-coredns-merge-ready.yaml\n  %[1]s verdict -n myapp --show-unchanged examples/myapp-merge-ready.yaml\n  %[1]s verdict -n myapp --to-label reserved:kube-apiserver --to-port 443 examples/myapp-merge-ready.yaml\n  %[1]s verdict -n myapp --replace-existing --fail-on-dropped --min-flows 20 --format markdown examples/myapp-merge-ready.yaml\n", binName)
	}
	_ = fs.Parse(args)
	namespace := flags.resolveNamespace()
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, binName+" verdict: usage: "+binName+" verdict [-n <namespace>|-A] [--last N] [-f] <candidate.yaml>")
		os.Exit(1)
	}
	candidatePath := fs.Arg(0)
	if !validVerdictFormat(format) {
		fmt.Fprintf(os.Stderr, "%s verdict: --format must be %s, %s or %s, got %q\n", binName, formatTable, formatJSON, formatMarkdown, format)
		os.Exit(1)
	}
	if minFlows < 0 {
		fmt.Fprintf(os.Stderr, "%s verdict: --min-flows must be >= 0\n", binName)
		os.Exit(1)
	}
	if follow && (format != formatTable || failOnDropped || minFlows > 0) {
		fmt.Fprintf(os.Stderr, "%s verdict: --format json|markdown, --fail-on-dropped and --min-flows need a one-shot run, not --follow\n", binName)
		os.Exit(1)
	}

	// Wall clock for the whole run as the user experiences it — client
	// setup, baseline fetch, port-forward and flow sampling included, not
	// just the engine's judging loop, which is rarely the slow part.
	start := time.Now()
	logger := slog.Default()

	core, cilium, cfg, err := newClientsets(flags.kubeconfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" verdict: building clients: %v\n", err)
		os.Exit(1)
	}
	warnOnVersionSkew(core, cfg)
	target := resolveKubeTarget(flags.kubeconfig, cfg)

	candidateRules, err := parseCandidateFile(logger, candidatePath, namespace)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" verdict: parsing candidate %s: %v\n", candidatePath, err)
		os.Exit(1)
	}

	baselineRuleCount, skipped, replaced, baseline, candidate, err := buildVerdictEnginesWith(logger, cilium, namespace, candidateRules, replaceExisting)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" verdict: %v\n", err)
		os.Exit(1)
	}
	warnSkippedBaseline(skipped)
	defer baseline.close(logger)
	defer candidate.close(logger)
	if format == formatTable {
		for _, r := range replaced {
			fmt.Printf("Replacing live %s with the candidate (--replace-existing).\n", r)
		}
	}

	counts := &verdictCounts{}

	if follow {
		fmt.Printf("Judging %d candidate rule(s) from %s against %d live rule(s) already in %s%s%s — streaming flows live, Ctrl+C to stop.\n\n",
			len(candidateRules), candidatePath, baselineRuleCount, namespaceLabel(namespace), contextLabel(target), filterLabel(*dst))

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		total, err := streamFlows(ctx, core, cfg, namespace, *dst, last, func(f *flowpb.Flow) {
			if row := judgeFlow(logger, baseline, candidate, f, counts, showUnchanged); row != nil {
				fmt.Println(row.line(1))
			}
		})
		counts.total = total
		if err != nil {
			fmt.Fprintf(os.Stderr, binName+" verdict: %v\n", err)
			os.Exit(1)
		}
		printVerdictSummary(counts, time.Since(start))
		return
	}

	comp, err := judgeFlowBatch(logger, baseline, candidate, core, cfg, namespace, *dst, last, showUnchanged)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" verdict: %v\n", err)
		os.Exit(1)
	}
	comp.candidateRuleCount = len(candidateRules)
	comp.baselineRuleCount = baselineRuleCount
	comp.skippedPolicies = skipped
	comp.elapsed = time.Since(start)
	comp.target = target

	code := verdictExitCode(comp.counts, failOnDropped, minFlows)
	switch format {
	case formatJSON:
		if err := writeVerdictJSON(os.Stdout, comp, candidatePath, replaced, minFlows, code); err != nil {
			fmt.Fprintf(os.Stderr, binName+" verdict: writing JSON: %v\n", err)
			os.Exit(1)
		}
	case formatMarkdown:
		writeVerdictMarkdown(os.Stdout, comp, candidatePath, replaced, minFlows, code)
	default:
		printVerdictComputation(comp, candidatePath)
		if code == exitVerdictTooFewFlows {
			fmt.Printf("\nOnly %d flow(s) judged, fewer than --min-flows %d: not enough evidence to call this a pass.\n", judgedFlows(comp.counts), minFlows)
		}
	}
	if code != 0 {
		baseline.close(logger)
		candidate.close(logger)
		os.Exit(code)
	}
}

// verdictComputation is the structured result of one one-shot verdict run —
// the single source of truth both the CLI's printed output and the "ui"
// subcommand's JSON API are built from (see printVerdictComputation and
// ui.go's handleVerdict), so the two can never compute a different answer,
// only present the same one differently.
type verdictComputation struct {
	namespace                             string
	dst                                   destinationFilter // flows were narrowed to this destination, see destinationFilter
	candidateRuleCount, baselineRuleCount int
	flowsRequested                        uint64
	flowsSampled                          int
	counts                                *verdictCounts
	rows                                  []*verdictRow
	rowCounts                             []int // seen-Nx count, same index as rows
	skippedPolicies                       []string // live baseline policies the engine could not load, see fetchBaselineRules
	// CLI only: wall clock of the whole run, set by runVerdict (0 = not
	// measured). The UI times its runs browser-side instead, so its clock
	// also covers a --follow-style stream that has no server-side end.
	elapsed time.Duration
	// target is the cluster this run judged, set by the caller that owns the
	// clients (runVerdict, ui.go's handleVerdict) rather than computeVerdict,
	// which only ever sees already-built clients.
	target kubeTarget
}

// computeVerdict is the full, self-contained one-shot verdict computation:
// fetches baseline policy, builds both engines, then delegates to
// judgeFlowBatch. The CLI's runVerdict builds its own engines inline instead
// (shared with the --follow path, which this function has no equivalent
// for) — this wrapper exists for callers that just want one answer with no
// engine lifecycle to manage themselves, namely the "ui" subcommand's HTTP
// API (see ui.go).
func computeVerdict(logger *slog.Logger, core kubernetes.Interface, cilium ciliumclient.Interface, cfg *rest.Config, namespace string, dst destinationFilter, candidateRules api.Rules, last uint64, showUnchanged bool) (*verdictComputation, error) {
	baselineRuleCount, skipped, baseline, candidate, err := buildVerdictEngines(logger, cilium, namespace, candidateRules)
	if err != nil {
		return nil, err
	}
	defer baseline.close(logger)
	defer candidate.close(logger)

	comp, err := judgeFlowBatch(logger, baseline, candidate, core, cfg, namespace, dst, last, showUnchanged)
	if err != nil {
		return nil, err
	}
	comp.candidateRuleCount = len(candidateRules)
	comp.baselineRuleCount = baselineRuleCount
	comp.skippedPolicies = skipped
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
func buildVerdictEngines(logger *slog.Logger, cilium ciliumclient.Interface, namespace string, candidateRules api.Rules) (baselineRuleCount int, skipped []string, baseline, candidate *verdictEngine, err error) {
	baselineRuleCount, skipped, _, baseline, candidate, err = buildVerdictEnginesWith(logger, cilium, namespace, candidateRules, false)
	return baselineRuleCount, skipped, baseline, candidate, err
}

// buildVerdictEnginesWith is buildVerdictEngines plus --replace-existing:
// when replaceExisting is set, live rules from a policy the candidate also
// defines (same kind/namespace/name, see replaceSameNamePolicies) are left
// out of the baseline+candidate engine only — the baseline engine always
// keeps today's full live state. replaced names the policies dropped.
func buildVerdictEnginesWith(logger *slog.Logger, cilium ciliumclient.Interface, namespace string, candidateRules api.Rules, replaceExisting bool) (baselineRuleCount int, skipped, replaced []string, baseline, candidate *verdictEngine, err error) {
	baselineRules, skipped, err := fetchBaselineRules(logger, cilium, namespace)
	if err != nil {
		return 0, nil, nil, nil, nil, fmt.Errorf("fetching baseline policy: %w", err)
	}

	baseline, err = newVerdictEngine(logger, baselineRules, identity.IdentityMap{})
	if err != nil {
		return 0, nil, nil, nil, nil, fmt.Errorf("building baseline engine: %w", err)
	}

	candidateBase := baselineRules
	if replaceExisting {
		candidateBase, replaced = replaceSameNamePolicies(baselineRules, candidateRules)
	}
	candidate, err = newVerdictEngine(logger, append(append(api.Rules{}, candidateBase...), candidateRules...), identity.IdentityMap{})
	if err != nil {
		baseline.close(logger)
		return 0, nil, nil, nil, nil, fmt.Errorf("building candidate engine: %w", err)
	}

	return len(baselineRules), skipped, replaced, baseline, candidate, nil
}

// warnSkippedBaseline is the CLI's stderr counterpart to the UI's banner for
// baseline policies fetchBaselineRules skipped.
func warnSkippedBaseline(skipped []string) {
	for _, s := range skipped {
		fmt.Fprintf(os.Stderr, "warning: baseline policy skipped (uses fromNodes/toNodes, not simulated): %s\n", s)
	}
}

// judgeFlowBatch fetches flows for namespace and judges each one against the
// already-built baseline/candidate engines, deduplicating identical rows
// (see judgeFlow/verdictRow.key) and grouping them NEWLY_DROPPED, then
// NEWLY_ALLOWED, then UNCHANGED (only present with showUnchanged). This is
// the one-shot counterpart to runVerdict's --follow loop — same judging
// logic (judgeFlow), batched instead of streamed, and reusable by both the
// CLI and the "ui" subcommand's HTTP API.
func judgeFlowBatch(logger *slog.Logger, baseline, candidate *verdictEngine, core kubernetes.Interface, cfg *rest.Config, namespace string, dst destinationFilter, last uint64, showUnchanged bool) (*verdictComputation, error) {
	flows, err := fetchFlows(core, cfg, namespace, dst, last)
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
		dst:            dst,
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
		fmt.Println("no flows observed for " + namespaceLabel(comp.namespace) + filterLabel(comp.dst) + " in Hubble's current buffer — nothing to simulate")
		return
	}

	if uint64(comp.flowsSampled) < comp.flowsRequested {
		fmt.Printf("Judging %d candidate rule(s) from %s against %d live rule(s) already in %s%s%s, using %d of up to %d requested flows — that's every flow Hubble's live buffer currently holds for this scope, not a shortfall in this tool; use --follow to keep sampling over time instead of raising --last.\n\n",
			comp.candidateRuleCount, candidatePath, comp.baselineRuleCount, namespaceLabel(comp.namespace), contextLabel(comp.target), filterLabel(comp.dst), comp.flowsSampled, comp.flowsRequested)
	} else {
		fmt.Printf("Judging %d candidate rule(s) from %s against %d live rule(s) already in %s%s%s, using %d sampled flows.\n\n",
			comp.candidateRuleCount, candidatePath, comp.baselineRuleCount, namespaceLabel(comp.namespace), contextLabel(comp.target), filterLabel(comp.dst), comp.flowsSampled)
	}

	for i, row := range comp.rows {
		fmt.Println(row.line(comp.rowCounts[i]))
	}
	printVerdictSummary(comp.counts, comp.elapsed)
}

// contextLabel is the " on context x" fragment for the CLI's summary lines,
// or "" when the kubeconfig names no context.
func contextLabel(t kubeTarget) string {
	if t.context == "" {
		return ""
	}
	return " on context " + t.context
}

// filterLabel is the " (only flows --to-pod x …)" suffix for the CLI's
// summary lines, or "" when no destination filter is set.
func filterLabel(d destinationFilter) string {
	if d.empty() {
		return ""
	}
	return " (only flows " + d.String() + ")"
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
	// side says which half of the verdict actually flipped between
	// baseline and candidate: "ingress" (destination's policy), "egress"
	// (source's policy), "both", or "" for UNCHANGED. It's read straight off
	// the engine's own two isAllowed/isEgressAllowed answers, so the UI can
	// tell which workload a fix has to select without guessing from
	// namespaces. Not part of key(): it's fully determined by the same
	// identities/port the key already carries.
	side string
	// srcLabels/dstLabels are the flow endpoints' security-identity labels
	// exactly as Hubble reports them ("k8s:app=foo", "reserved:host", …) —
	// the same labels identitiesFromFlows feeds the engine, i.e. what a
	// selector really matches against. Not part of key() for the same reason
	// side isn't.
	srcLabels, dstLabels []string
	// dstService is the Kubernetes Service the flow was addressed to
	// ("ns/name", "" if none), as Hubble resolved it — what --to-service
	// matches, so the UI can offer it as a filter suggestion. Not part of
	// key(): one row's flows can reach the same pod with or without a
	// Service in front, and that doesn't change the verdict.
	dstService string
}

func serviceString(s *flowpb.Service) string {
	if s.GetName() == "" {
		return ""
	}
	if s.GetNamespace() == "" {
		return s.GetName()
	}
	return s.GetNamespace() + "/" + s.GetName()
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

	var key, egressKey policy.Key
	srcNID := engineNID(src)
	dstNID := engineNID(dst)
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
		egressKey = policy.EgressKey().WithIdentity(dstNID).WithTCPPort(port)
	case l4.GetUDP() != nil:
		proto = "UDP"
		port := uint16(l4.GetUDP().GetDestinationPort())
		if port == 0 {
			counts.notSimulated++
			return nil
		}
		key = policy.IngressKey().WithIdentity(srcNID).WithUDPPort(port)
		egressKey = policy.EgressKey().WithIdentity(dstNID).WithUDPPort(port)
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

	// A connection needs BOTH the destination's ingress policy and the
	// source's egress policy to allow it. Egress is queried on the source
	// identity's own distilled policy, keyed by the destination as the peer.
	baseSrcEpp, err := baseline.distillFor(logger, srcNID)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" verdict: baseline: %v\n", err)
		counts.notSimulated++
		return nil
	}
	candSrcEpp, err := candidate.distillFor(logger, srcNID)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" verdict: candidate: %v\n", err)
		counts.notSimulated++
		return nil
	}

	baseIn, baseEg := isAllowed(baseEpp, key), isEgressAllowed(baseSrcEpp, egressKey)
	candIn, candEg := isAllowed(candEpp, key), isEgressAllowed(candSrcEpp, egressKey)
	baseAllow := baseIn && baseEg
	candAllow := candIn && candEg

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
	var side string
	switch inFlipped, egFlipped := baseIn != candIn, baseEg != candEg; {
	case change == "UNCHANGED":
	case inFlipped && egFlipped:
		side = "both"
	case inFlipped:
		side = "ingress"
	case egFlipped:
		side = "egress"
	}
	return &verdictRow{
		change: change, src: endpointString(src), dst: endpointString(dst), proto: proto, port: key.DestPort,
		side: side, srcLabels: src.GetLabels(), dstLabels: dst.GetLabels(),
		dstService: serviceString(f.GetDestinationService()),
	}
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

func printVerdictSummary(counts *verdictCounts, elapsed time.Duration) {
	fmt.Printf("\n%d flows sampled: %s unchanged, %s newly dropped, %s newly allowed, %s not simulated, %s reply (skipped)\n",
		counts.total,
		colorize(changeColor("UNCHANGED"), fmt.Sprintf("%d", counts.unchanged)),
		colorize(changeColor("NEWLY_DROPPED"), fmt.Sprintf("%d", counts.newlyDropped)),
		colorize(changeColor("NEWLY_ALLOWED"), fmt.Sprintf("%d", counts.newlyAllowed)),
		colorize(ansiGray, fmt.Sprintf("%d", counts.notSimulated)),
		colorize(ansiGray, fmt.Sprintf("%d", counts.replySkipped)),
	)
	fmt.Println(colorize(ansiGray, "completed in "+formatElapsed(elapsed)))

	if counts.newlyDropped > 0 {
		fmt.Printf("\n%s\n", colorize(ansiBold+ansiRed,
			fmt.Sprintf("%d real flow(s) would BREAK if this candidate merged as-is — review the NEWLY_DROPPED rows above before shipping it.", counts.newlyDropped)))
	}
	printVerdictLegend(counts)
}

// formatElapsed rounds a run's duration to what a human cares about
// ("3.2s", "1m4.5s") instead of time.Duration's nanosecond default.
func formatElapsed(d time.Duration) string {
	return d.Round(100 * time.Millisecond).String()
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

// localIDs maps (scope, label set) to the engine-side numeric identity used
// for node-scoped identities — see engineNID.
var localIDs = struct {
	sync.Mutex
	byKey map[string]identity.NumericIdentity
	next  map[identity.NumericIdentity]uint32
}{byKey: map[string]identity.NumericIdentity{}, next: map[identity.NumericIdentity]uint32{}}

// engineNID returns the numeric identity this tool's engines use for a flow
// endpoint. Global and reserved identities are cluster-wide, so their real
// number is used unchanged. Local-scope (CIDR/world, 1<<24+) and
// remote-node-scope identities are allocated independently by EACH node's
// agent: the same number means different labels on different nodes, and
// hubble-relay merges every node's flows. Keying the engine by that number
// (first-seen labels winning) silently attached the wrong labels to later
// flows — seen live as a CCNP's toEntities: kube-apiserver deny landing on
// the wrong destination depending on which nodes' flows were sampled. So
// these get a synthetic number per distinct label set, scope bits kept
// because Cilium treats the scope itself as meaningful.
func engineNID(ep *flowpb.Endpoint) identity.NumericIdentity {
	nid := identity.NumericIdentity(ep.GetIdentity())
	scope := nid.Scope()
	if scope == identity.IdentityScopeGlobal {
		return nid
	}
	lbls := append([]string(nil), ep.GetLabels()...)
	sort.Strings(lbls)
	key := fmt.Sprintf("%d|%s", scope, strings.Join(lbls, ","))

	localIDs.Lock()
	defer localIDs.Unlock()
	if id, ok := localIDs.byKey[key]; ok {
		return id
	}
	localIDs.next[scope]++
	id := scope | identity.NumericIdentity(localIDs.next[scope])
	localIDs.byKey[key] = id
	return id
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
		ids[engineNID(ep)] = labels.ParseLabelArray(ep.GetLabels()...)
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
//
// raw may hold several "---"-separated documents, like a file passed to
// kubectl apply -f: each is decoded/gated/Parse()d on its own and their
// rules are judged together as one candidate. That's what lets a candidate
// ship alongside a narrow per-workload exception policy (the UI's verdict-row
// Allow/Deny button appends exactly that) and have Cilium's own engine
// combine them — allows union across policies, a deny beats any allow —
// rather than this tool merging them by hand.
func parseCandidateYAML(logger *slog.Logger, raw []byte, defaultNamespace string) (api.Rules, error) {
	docs, err := splitYAMLDocuments(raw)
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		// Nothing but whitespace/comments — let decodeCandidateYAML produce
		// the same "unsupported kind" error a single empty document always did.
		docs = [][]byte{raw}
	}
	var rules api.Rules
	for i, doc := range docs {
		decoded, err := decodeCandidateYAML(doc, defaultNamespace)
		if err == nil {
			var docRules api.Rules
			docRules, err = decoded.parse(logger)
			rules = append(rules, docRules...)
		}
		if err != nil {
			if len(docs) > 1 {
				return nil, fmt.Errorf("document %d: %w", i+1, err)
			}
			return nil, err
		}
	}
	return rules, nil
}

// splitYAMLDocuments splits a multi-document YAML stream on "---",
// dropping documents that are empty or comment-only.
func splitYAMLDocuments(raw []byte) ([][]byte, error) {
	reader := utilyaml.NewYAMLReader(bufio.NewReader(bytes.NewReader(raw)))
	var docs [][]byte
	for {
		doc, err := reader.Read()
		if err == io.EOF {
			return docs, nil
		}
		if err != nil {
			return nil, fmt.Errorf("splitting YAML documents: %w", err)
		}
		var content map[string]any
		if err := yaml.Unmarshal(doc, &content); err == nil && len(content) == 0 {
			continue
		}
		docs = append(docs, doc)
	}
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

	// checkRawFieldGates runs once here, kind-agnostically — a CNP and a
	// CCNP candidate share the same spec/specs shape, and this check (see
	// compat.go) operates on that raw shape directly, not on anything
	// CNP/CCNP-specific, so there's nothing to gain from duplicating it in
	// both branches below the way checkFeatureGates' typed check is.
	if err := checkRawFieldGates(raw, pinnedCiliumVersion); err != nil {
		return nil, err
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

// isEgressAllowed is isAllowed's egress twin: same Lookup, but a true miss
// falls back to the source endpoint's own egress default mode.
func isEgressAllowed(epp *policy.EndpointPolicy, key policy.Key) bool {
	if entry, _, found := epp.Lookup(key); found {
		return entry.IsAllow()
	}
	return !epp.SelectorPolicy.EgressPolicyEnabled
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
