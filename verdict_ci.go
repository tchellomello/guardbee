package main

// CI mode for the "verdict" subcommand (issue #10): what a pull-request check
// needs on top of the interactive output.
//
//   - Exit codes a pipeline can gate on: --fail-on-dropped exits
//     exitVerdictDropped when any sampled flow is NEWLY_DROPPED,
//     --fail-on-allowed exits exitVerdictAllowed on any NEWLY_ALLOWED,
//     --fail-on-l7 exits exitVerdictL7 on any L7_CHANGED, and
//     --min-flows exits exitVerdictTooFewFlows when too few flows were
//     actually judged — so "nothing was sampled" can never read as a pass.
//     Errors keep exiting 1.
//   - --format json|markdown: the same verdictComputation the table is
//     printed from, rendered as JSON (a superset of the "ui" subcommand's
//     /api/verdict response) or as a PR-comment-ready markdown summary.
//   - Several candidate files (or "-" for stdin), and --per-policy to judge
//     each CNP/CCNP document on its own: one section per policy, and an
//     overall exit code that is the worst of them (worstExitCode). Without
//     --per-policy every document is one merged candidate, as always.
//   - --replace-existing: drop a live policy of the same kind/namespace/name
//     as a candidate document from the baseline+candidate side, which is
//     what applying the candidate would actually do. Without it the
//     candidate is judged ON TOP of the live policy it replaces, so rules a
//     PR removes or narrows still allow traffic and NEWLY_DROPPED is
//     under-reported for edited policies.

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	ciliumclient "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	exitVerdictDropped     = 2
	exitVerdictTooFewFlows = 3
	exitVerdictAllowed     = 4
	exitVerdictL7          = 5
)

const (
	formatTable    = "table"
	formatJSON     = "json"
	formatMarkdown = "markdown"
)

func validVerdictFormat(f string) bool {
	return f == formatTable || f == formatJSON || f == formatMarkdown
}

// judgedFlows is how many sampled flows actually got a verdict — replies and
// not-simulated flows are counted in total but say nothing about the policy.
func judgedFlows(c *verdictCounts) int {
	return c.unchanged + c.newlyDropped + c.newlyAllowed + c.l7Changed
}

// verdictExitCode is the CI gate. A real finding outranks a thin sample:
// a NEWLY_DROPPED, NEWLY_ALLOWED or L7_CHANGED row is a finding even if few
// flows were judged. Dropped outranks allowed — breaking traffic is the
// worse news — and both outrank L7_CHANGED, which may or may not break
// anything (a connection-level flow, no request to judge).
func verdictExitCode(c *verdictCounts, failOnDropped, failOnAllowed, failOnL7 bool, minFlows int) int {
	if failOnDropped && c.newlyDropped > 0 {
		return exitVerdictDropped
	}
	if failOnAllowed && c.newlyAllowed > 0 {
		return exitVerdictAllowed
	}
	if failOnL7 && c.l7Changed > 0 {
		return exitVerdictL7
	}
	if minFlows > 0 && judgedFlows(c) < minFlows {
		return exitVerdictTooFewFlows
	}
	return 0
}

func verdictResult(code int) string {
	switch code {
	case exitVerdictDropped:
		return "dropped"
	case exitVerdictAllowed:
		return "allowed"
	case exitVerdictL7:
		return "l7-changed"
	case exitVerdictTooFewFlows:
		return "insufficient-flows"
	default:
		return "pass"
	}
}

// policyOf identifies the CNP/CCNP a parsed rule came from, read from the
// labels Cilium's own Parse() attaches to every rule it produces
// (pkg/k8s/apis/cilium.io/utils.GetPolicyLabels) — the same for a live
// policy (fetchBaselineRules) and a candidate (parseCandidateYAML), since both
// go through Parse(). ok is false for a rule without those labels.
func policyOf(r *api.Rule) (key, display string, ok bool) {
	get := func(k string) string { return r.Labels.Get(labels.LabelSourceK8s + ":" + k) }
	name := get(k8sConst.PolicyLabelName)
	if name == "" {
		return "", "", false
	}
	kind := get(k8sConst.PolicyLabelDerivedFrom)
	ns := get(k8sConst.PolicyLabelNamespace)
	display = kind + " " + name
	if ns != "" {
		display = kind + " " + ns + "/" + name
	}
	return kind + "|" + ns + "|" + name, display, true
}

// replaceSameNamePolicies returns baseline without the rules of any policy
// the candidate also defines (same kind, namespace and name), plus the
// sorted display names of the policies replaced. Rules the candidate does
// not name are kept untouched.
func replaceSameNamePolicies(baseline, candidate api.Rules) (kept api.Rules, replaced []string) {
	defined := map[string]bool{}
	for _, r := range candidate {
		if key, _, ok := policyOf(r); ok {
			defined[key] = true
		}
	}
	seen := map[string]bool{}
	for _, r := range baseline {
		key, display, ok := policyOf(r)
		if ok && defined[key] {
			if !seen[display] {
				seen[display] = true
				replaced = append(replaced, display)
			}
			continue
		}
		kept = append(kept, r)
	}
	sort.Strings(replaced)
	return kept, replaced
}

// toVerdictResponse is the JSON mirror of a verdictComputation, shared by
// the "ui" subcommand's /api/verdict and the CLI's --format json.
func toVerdictResponse(comp *verdictComputation) verdictResponse {
	resp := verdictResponse{
		Namespace:          comp.namespace,
		CandidateRuleCount: comp.candidateRuleCount,
		BaselineRuleCount:  comp.baselineRuleCount,
		FlowsRequested:     comp.flowsRequested,
		FlowsSampled:       comp.flowsSampled,
		Counts:             toCountsOut(comp.counts),
		Rows:               make([]verdictRowOut, len(comp.rows)),
		SkippedPolicies:    comp.skippedPolicies,
		Warnings:           comp.warnings,
		Context:            comp.target.context,
		APIServer:          comp.target.apiServer,
	}
	for i, row := range comp.rows {
		resp.Rows[i] = toRowOut(row, comp.rowCounts[i])
	}
	return resp
}

// cliVerdictOutput is --format json: the ui's verdictResponse plus what a
// CI job needs to decide and report without re-deriving anything.
type cliVerdictOutput struct {
	verdictResponse
	Candidate        string   `json:"candidate"`
	ReplacedPolicies []string `json:"replacedPolicies,omitempty"`
	JudgedFlows      int      `json:"judgedFlows"`
	MinFlows         int      `json:"minFlows,omitempty"`
	Result           string   `json:"result"`
	ExitCode         int      `json:"exitCode"`
	DurationMs       int64    `json:"durationMs"`
}

func newCLIVerdictOutput(comp *verdictComputation, candidatePath string, replaced []string, minFlows, code int) cliVerdictOutput {
	return cliVerdictOutput{
		verdictResponse:  toVerdictResponse(comp),
		Candidate:        candidatePath,
		ReplacedPolicies: replaced,
		JudgedFlows:      judgedFlows(comp.counts),
		MinFlows:         minFlows,
		Result:           verdictResult(code),
		ExitCode:         code,
		DurationMs:       comp.elapsed.Milliseconds(),
	}
}

func writeVerdictJSON(w io.Writer, comp *verdictComputation, candidatePath string, replaced []string, minFlows, code int) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(newCLIVerdictOutput(comp, candidatePath, replaced, minFlows, code))
}

// mdCell keeps a value from breaking a markdown table row.
func mdCell(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}

func writeVerdictMarkdown(w io.Writer, comp *verdictComputation, candidatePath string, replaced []string, minFlows, code int) {
	c := comp.counts
	var status string
	switch code {
	case exitVerdictDropped:
		status = fmt.Sprintf("**FAIL**: %d sampled flow(s) would break", c.newlyDropped)
	case exitVerdictAllowed:
		status = fmt.Sprintf("**FAIL**: %d sampled flow(s) would be newly allowed", c.newlyAllowed)
	case exitVerdictL7:
		status = fmt.Sprintf("**FAIL**: %d sampled flow(s) would get different L7 proxy rules", c.l7Changed)
	case exitVerdictTooFewFlows:
		status = fmt.Sprintf("**INCONCLUSIVE**: only %d flow(s) judged, %d required", judgedFlows(c), minFlows)
	default:
		if c.newlyDropped > 0 {
			status = fmt.Sprintf("**WARNING**: %d sampled flow(s) would break", c.newlyDropped)
		} else {
			status = "**PASS**: no sampled flow would break"
		}
	}
	fmt.Fprintf(w, "### GuardBee verdict: `%s`\n\n%s\n\n", candidatePath, status)
	if comp.target.context != "" {
		fmt.Fprintf(w, "- Context: `%s` (%s)\n", comp.target.context, comp.target.apiServer)
	}
	fmt.Fprintf(w, "- Scope: %s%s\n", namespaceLabel(comp.namespace), filterLabel(comp.filter))
	fmt.Fprintf(w, "- Flows: %d sampled, %d judged (%d unchanged, %d newly dropped, %d newly allowed, %d L7 changed), %d not simulated, %d replies skipped\n",
		c.total, judgedFlows(c), c.unchanged, c.newlyDropped, c.newlyAllowed, c.l7Changed, c.notSimulated, c.replySkipped)
	fmt.Fprintf(w, "- Rules: %d candidate vs %d live\n", comp.candidateRuleCount, comp.baselineRuleCount)
	if comp.elapsed > 0 {
		fmt.Fprintf(w, "- Duration: %s\n", formatElapsed(comp.elapsed))
	}
	for _, r := range replaced {
		fmt.Fprintf(w, "- Replaces live %s\n", r)
	}
	for _, msg := range comp.warnings {
		fmt.Fprintf(w, "- Warning: %s\n", msg)
	}
	for _, s := range comp.skippedPolicies {
		fmt.Fprintf(w, "- Live policy not simulated (fromNodes/toNodes): %s\n", s)
	}

	// The L7 column only appears when a row in the table has L7 rules, so a
	// PR comment for an L3/L4-only policy keeps its familiar shape.
	table := func(rows []int) {
		withL7 := false
		for _, i := range rows {
			withL7 = withL7 || comp.rows[i].l7Detail() != ""
		}
		if withL7 {
			fmt.Fprintln(w, "\n| Change | Source | Destination | Port | L7 | Seen |")
			fmt.Fprintln(w, "|---|---|---|---|---|---|")
		} else {
			fmt.Fprintln(w, "\n| Change | Source | Destination | Port | Seen |")
			fmt.Fprintln(w, "|---|---|---|---|---|")
		}
		for _, i := range rows {
			r := comp.rows[i]
			l7 := ""
			if withL7 {
				l7 = " " + mdCell(strings.TrimSpace(r.l7Detail())) + " |"
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s/%d |%s %d |\n", r.change, mdCell(r.src), mdCell(r.dst), r.proto, r.port, l7, comp.rowCounts[i])
		}
	}
	var changed, unchanged []int
	for i, r := range comp.rows {
		if r.change == "UNCHANGED" {
			unchanged = append(unchanged, i)
		} else {
			changed = append(changed, i)
		}
	}
	if len(changed) > 0 {
		table(changed)
	}
	if len(unchanged) > 0 {
		fmt.Fprintf(w, "\n<details><summary>%d unchanged flow(s)</summary>\n", len(unchanged))
		table(unchanged)
		fmt.Fprintln(w, "\n</details>")
	}
	fmt.Fprintln(w, "\n_Judged against the flows in Hubble's buffer at run time: a flow that did not occur recently is not covered._")
}

// worstExitCode is the overall result of several judged policies. Not a
// numeric max: a dropped flow (2) is worse than a newly allowed one (4),
// then an L7 rule change (5), and all outrank a thin sample (3), the same
// order verdictExitCode applies within one policy.
func worstExitCode(codes []int) int {
	rank := func(c int) int {
		switch c {
		case exitVerdictDropped:
			return 4
		case exitVerdictAllowed:
			return 3
		case exitVerdictL7:
			return 2
		case exitVerdictTooFewFlows:
			return 1
		}
		return 0
	}
	worst := 0
	for _, c := range codes {
		if rank(c) > rank(worst) {
			worst = c
		}
	}
	return worst
}

// candidateGroup is one candidate to judge: every rule that goes in together.
type candidateGroup struct {
	label string
	rules api.Rules
}

// loadCandidateDocs reads the verdict command's candidate arguments: file
// paths, or "-" for stdin. Documents of other kinds are skipped with a
// warning; a source that holds no policy at all is an error. Each doc is
// returned with the source it came from.
func loadCandidateDocs(logger *slog.Logger, args []string, stdin io.Reader, defaultNamespace string) (docs []candidateDoc, sources []string, err error) {
	for _, arg := range args {
		var raw []byte
		name := arg
		if arg == "-" {
			name = "stdin"
			raw, err = io.ReadAll(stdin)
		} else {
			raw, err = os.ReadFile(arg)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("reading candidate %s: %w", name, err)
		}
		// Only the CLI skips non-policy documents: a file here is often
		// rendered kustomize/helm output with Deployments and ConfigMaps next
		// to the policies. The UI's editor keeps rejecting an unsupported
		// kind, since there a non-policy document is a mistake, not a
		// bystander.
		parsed, skipped, err := parseCandidateDocs(logger, raw, defaultNamespace, true)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing candidate %s: %w", name, err)
		}
		for _, s := range skipped {
			fmt.Fprintf(os.Stderr, "%s verdict: skipping non-policy document in %s: %s\n", binName, name, s)
		}
		docs = append(docs, parsed...)
		sources = append(sources, name)
		for i := len(docs) - len(parsed); i < len(docs); i++ {
			docs[i].source = name
		}
	}
	return docs, sources, nil
}

// groupCandidates turns the parsed documents into what gets judged: one
// merged candidate (the default, so a candidate can ship with its exception
// policies and be combined by Cilium's own engine), or with perPolicy one
// candidate per document.
func groupCandidates(docs []candidateDoc, sources []string, perPolicy bool) []candidateGroup {
	if !perPolicy {
		return []candidateGroup{{label: strings.Join(sources, ", "), rules: flattenCandidateRules(docs)}}
	}
	groups := make([]candidateGroup, len(docs))
	for i, d := range docs {
		groups[i] = candidateGroup{label: fmt.Sprintf("%s (%s)", d.display(), d.source), rules: d.rules}
	}
	return groups
}

// groupRun is one candidate group's judged result.
type groupRun struct {
	label    string
	comp     *verdictComputation
	replaced []string
	code     int
}

// judgeCandidateGroups samples Hubble once and judges every group against
// the same flows, each with its own baseline+candidate engines.
func judgeCandidateGroups(logger *slog.Logger, cilium ciliumclient.Interface, core kubernetes.Interface, cfg *rest.Config, namespace string, filter flowFilter, last uint64, showUnchanged, replaceExisting bool, groups []candidateGroup, failOnDropped, failOnAllowed, failOnL7 bool, minFlows int, start time.Time, target kubeTarget) ([]groupRun, error) {
	flows, err := fetchFlows(core, cfg, namespace, filter, last)
	if err != nil {
		return nil, fmt.Errorf("tapping flows: %w", err)
	}
	var runs []groupRun
	for _, g := range groups {
		run, err := judgeGroup(logger, core, cilium, namespace, filter, last, showUnchanged, replaceExisting, g, flows, failOnDropped, failOnAllowed, failOnL7, minFlows, start, target)
		if err != nil {
			return nil, err
		}
		runs = append(runs, *run)
	}
	return runs, nil
}

func judgeGroup(logger *slog.Logger, core kubernetes.Interface, cilium ciliumclient.Interface, namespace string, filter flowFilter, last uint64, showUnchanged, replaceExisting bool, g candidateGroup, flows []*flowpb.Flow, failOnDropped, failOnAllowed, failOnL7 bool, minFlows int, start time.Time, target kubeTarget) (*groupRun, error) {
	baselineRuleCount, skipped, replaced, baseline, candidate, err := buildVerdictEnginesWith(logger, core, cilium, namespace, g.rules, replaceExisting)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", g.label, err)
	}
	defer baseline.close(logger)
	defer candidate.close(logger)
	warnSkippedBaseline(skipped)

	comp := judgeFetchedFlows(logger, baseline, candidate, flows, namespace, filter, last, showUnchanged)
	comp.candidateRuleCount = len(g.rules)
	comp.baselineRuleCount = baselineRuleCount
	comp.skippedPolicies = skipped
	comp.warnings = candidateWarnings(g.rules)
	comp.elapsed = time.Since(start)
	comp.target = target
	return &groupRun{label: g.label, comp: comp, replaced: replaced, code: verdictExitCode(comp.counts, failOnDropped, failOnAllowed, failOnL7, minFlows)}, nil
}

// cliMultiOutput is --format json when more than one policy was judged.
type cliMultiOutput struct {
	Policies []cliVerdictOutput `json:"policies"`
	Result   string             `json:"result"`
	ExitCode int                `json:"exitCode"`
}

func writeMultiVerdictJSON(w io.Writer, runs []groupRun, minFlows, overall int) error {
	out := cliMultiOutput{Result: verdictResult(overall), ExitCode: overall}
	for _, r := range runs {
		out.Policies = append(out.Policies, newCLIVerdictOutput(r.comp, r.label, r.replaced, minFlows, r.code))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func writeMultiVerdictMarkdown(w io.Writer, runs []groupRun, minFlows, overall int) {
	fmt.Fprintf(w, "## GuardBee verdict: %d policies, overall **%s**\n\n", len(runs), strings.ToUpper(verdictResult(overall)))
	for i, r := range runs {
		if i > 0 {
			fmt.Fprintln(w)
		}
		writeVerdictMarkdown(w, r.comp, r.label, r.replaced, minFlows, r.code)
	}
}
