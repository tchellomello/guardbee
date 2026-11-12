package main

// CI mode for the "verdict" subcommand (issue #10): what a pull-request check
// needs on top of the interactive output.
//
//   - Exit codes a pipeline can gate on: --fail-on-dropped exits
//     exitVerdictDropped when any sampled flow is NEWLY_DROPPED, and
//     --min-flows exits exitVerdictTooFewFlows when too few flows were
//     actually judged — so "nothing was sampled" can never read as a pass.
//     Errors keep exiting 1.
//   - --format json|markdown: the same verdictComputation the table is
//     printed from, rendered as JSON (a superset of the "ui" subcommand's
//     /api/verdict response) or as a PR-comment-ready markdown summary.
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
	"sort"
	"strings"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

const (
	exitVerdictDropped     = 2
	exitVerdictTooFewFlows = 3
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
	return c.unchanged + c.newlyDropped + c.newlyAllowed
}

// verdictExitCode is the CI gate. A real regression outranks a thin sample:
// a NEWLY_DROPPED row is a finding even if few flows were judged.
func verdictExitCode(c *verdictCounts, failOnDropped bool, minFlows int) int {
	if failOnDropped && c.newlyDropped > 0 {
		return exitVerdictDropped
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

func writeVerdictJSON(w io.Writer, comp *verdictComputation, candidatePath string, replaced []string, minFlows, code int) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(cliVerdictOutput{
		verdictResponse:  toVerdictResponse(comp),
		Candidate:        candidatePath,
		ReplacedPolicies: replaced,
		JudgedFlows:      judgedFlows(comp.counts),
		MinFlows:         minFlows,
		Result:           verdictResult(code),
		ExitCode:         code,
		DurationMs:       comp.elapsed.Milliseconds(),
	})
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
	fmt.Fprintf(w, "- Scope: %s%s\n", namespaceLabel(comp.namespace), filterLabel(comp.dst))
	fmt.Fprintf(w, "- Flows: %d sampled, %d judged (%d unchanged, %d newly dropped, %d newly allowed), %d not simulated, %d replies skipped\n",
		c.total, judgedFlows(c), c.unchanged, c.newlyDropped, c.newlyAllowed, c.notSimulated, c.replySkipped)
	fmt.Fprintf(w, "- Rules: %d candidate vs %d live\n", comp.candidateRuleCount, comp.baselineRuleCount)
	if comp.elapsed > 0 {
		fmt.Fprintf(w, "- Duration: %s\n", formatElapsed(comp.elapsed))
	}
	for _, r := range replaced {
		fmt.Fprintf(w, "- Replaces live %s\n", r)
	}
	for _, s := range comp.skippedPolicies {
		fmt.Fprintf(w, "- Live policy not simulated (fromNodes/toNodes): %s\n", s)
	}

	table := func(rows []int) {
		fmt.Fprintln(w, "\n| Change | Source | Destination | Port | Seen |")
		fmt.Fprintln(w, "|---|---|---|---|---|")
		for _, i := range rows {
			r := comp.rows[i]
			fmt.Fprintf(w, "| %s | %s | %s | %s/%d | %d |\n", r.change, mdCell(r.src), mdCell(r.dst), r.proto, r.port, comp.rowCounts[i])
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
