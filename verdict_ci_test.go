package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/policy/api"
	"sigs.k8s.io/yaml"
)

// A live "web" policy allows client->web on 80 and 81; the candidate edit
// of the SAME policy narrows it to 80. Added on top of the live policy (the
// default), 81 stays allowed by the old rule and the regression is
// invisible. With --replace-existing the live "web" is dropped from the
// candidate side, so 81 must come back NEWLY_DROPPED — while an unrelated
// live policy in the namespace stays in force on both sides.
const liveWebPolicy = `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: web
  namespace: alpha
spec:
  endpointSelector:
    matchLabels:
      app: web
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: client
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
            - port: "81"
              protocol: TCP
`

const liveOtherPolicy = `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: other
  namespace: alpha
spec:
  endpointSelector:
    matchLabels:
      app: db
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: web
`

const narrowedWebCandidate = `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: web
  namespace: alpha
spec:
  endpointSelector:
    matchLabels:
      app: web
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: client
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
`

func liveCNP(t *testing.T, raw string) *cilium_v2.CiliumNetworkPolicy {
	t.Helper()
	var cnp cilium_v2.CiliumNetworkPolicy
	if err := yaml.Unmarshal([]byte(raw), &cnp); err != nil {
		t.Fatalf("unmarshal live CNP: %v", err)
	}
	return &cnp
}

func TestReplaceExistingDetectsNarrowedPolicy(t *testing.T) {
	logger := slog.Default()
	cs := fake.NewSimpleClientset(liveCNP(t, liveWebPolicy), liveCNP(t, liveOtherPolicy))

	candidateRules, err := parseCandidateYAML(logger, []byte(narrowedWebCandidate), "alpha")
	if err != nil {
		t.Fatalf("parseCandidateYAML: %v", err)
	}

	ep := func(id uint32, pod, app string) *flowpb.Endpoint {
		return &flowpb.Endpoint{Identity: id, PodName: pod, Namespace: "alpha",
			Labels: []string{"k8s:app=" + app, "k8s:io.kubernetes.pod.namespace=alpha"}}
	}
	client, web, db := ep(1100, "client-1", "client"), ep(1200, "web-1", "web"), ep(1300, "db-1", "db")
	tcp := func(src, dst *flowpb.Endpoint, port uint32) *flowpb.Flow {
		return &flowpb.Flow{Source: src, Destination: dst, L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: port}},
		}}
	}

	judge := func(replace bool, f *flowpb.Flow) (string, []string) {
		t.Helper()
		_, _, replaced, baseline, candidate, err := buildVerdictEnginesWith(logger, nil, cs, "alpha", candidateRules, replace)
		if err != nil {
			t.Fatalf("buildVerdictEnginesWith(replace=%v): %v", replace, err)
		}
		defer baseline.close(logger)
		defer candidate.close(logger)
		return judgeFlow(logger, baseline, candidate, f, &verdictCounts{}, true).change, replaced
	}

	if got, replaced := judge(false, tcp(client, web, 81)); got != "UNCHANGED" || len(replaced) != 0 {
		t.Fatalf("additive (default): want UNCHANGED and nothing replaced, got %s replaced=%v", got, replaced)
	}

	got, replaced := judge(true, tcp(client, web, 81))
	if got != "NEWLY_DROPPED" {
		t.Fatalf("replace-existing: port 81 removed by the edit, want NEWLY_DROPPED, got %s", got)
	}
	if len(replaced) != 1 || replaced[0] != "CiliumNetworkPolicy alpha/web" {
		t.Fatalf("replace-existing: want [CiliumNetworkPolicy alpha/web] replaced, got %v", replaced)
	}
	if got, _ := judge(true, tcp(client, web, 80)); got != "UNCHANGED" {
		t.Errorf("replace-existing: port 80 kept by the edit, want UNCHANGED, got %s", got)
	}
	// The unrelated live policy still selects db on both sides: web->db is
	// allowed by it before and after, client->db denied before and after.
	if got, _ := judge(true, tcp(web, db, 5432)); got != "UNCHANGED" {
		t.Errorf("replace-existing must keep unrelated live policy: web->db want UNCHANGED, got %s", got)
	}
}

func TestReplaceSameNamePoliciesMatchesKindNamespaceAndName(t *testing.T) {
	logger := slog.Default()
	live, err := parseCandidateYAML(logger, []byte(liveWebPolicy+"---\n"+liveOtherPolicy), "")
	if err != nil {
		t.Fatalf("parse live: %v", err)
	}
	sameNameOtherNS, err := parseCandidateYAML(logger, []byte(strings.Replace(narrowedWebCandidate, "namespace: alpha", "namespace: beta", 1)), "")
	if err != nil {
		t.Fatalf("parse candidate: %v", err)
	}
	kept, replaced := replaceSameNamePolicies(live, sameNameOtherNS)
	if len(replaced) != 0 || len(kept) != len(live) {
		t.Fatalf("a same-name policy in another namespace must not replace anything: replaced=%v kept=%d/%d", replaced, len(kept), len(live))
	}
}

func TestVerdictExitCode(t *testing.T) {
	cases := []struct {
		name          string
		counts        verdictCounts
		failOnDropped bool
		failOnAllowed bool
		failOnL7      bool
		minFlows      int
		want          int
	}{
		{"plain run never fails", verdictCounts{newlyDropped: 3}, false, false, false, 0, 0},
		{"dropped with gate", verdictCounts{newlyDropped: 1, unchanged: 40}, true, false, false, 0, exitVerdictDropped},
		{"clean with gate", verdictCounts{unchanged: 40}, true, false, false, 0, 0},
		{"too few judged", verdictCounts{unchanged: 3, replySkipped: 50}, false, false, false, 10, exitVerdictTooFewFlows},
		{"replies and not-simulated don't count", verdictCounts{unchanged: 9, replySkipped: 30, notSimulated: 30}, true, false, false, 10, exitVerdictTooFewFlows},
		{"enough judged", verdictCounts{unchanged: 8, newlyAllowed: 2}, true, false, false, 10, 0},
		{"dropped outranks thin sample", verdictCounts{newlyDropped: 1}, true, false, false, 10, exitVerdictDropped},
		{"allowed with gate", verdictCounts{newlyAllowed: 1, unchanged: 40}, false, true, false, 0, exitVerdictAllowed},
		{"allowed without gate", verdictCounts{newlyAllowed: 1, unchanged: 40}, true, false, false, 0, 0},
		{"dropped outranks allowed", verdictCounts{newlyDropped: 1, newlyAllowed: 1}, true, true, false, 0, exitVerdictDropped},
		{"allowed outranks thin sample", verdictCounts{newlyAllowed: 1}, false, true, false, 10, exitVerdictAllowed},
		{"l7 with gate", verdictCounts{l7Changed: 1, unchanged: 40}, false, false, true, 0, exitVerdictL7},
		{"l7 without gate", verdictCounts{l7Changed: 1, unchanged: 40}, true, true, false, 0, 0},
		{"allowed outranks l7", verdictCounts{newlyAllowed: 1, l7Changed: 1}, false, true, true, 0, exitVerdictAllowed},
		{"l7 outranks thin sample", verdictCounts{l7Changed: 1}, false, false, true, 10, exitVerdictL7},
		{"l7 rows count as judged", verdictCounts{l7Changed: 10}, false, false, false, 10, 0},
	}
	for _, c := range cases {
		if got := verdictExitCode(&c.counts, c.failOnDropped, c.failOnAllowed, c.failOnL7, c.minFlows); got != c.want {
			t.Errorf("%s: want %d, got %d", c.name, c.want, got)
		}
	}
}

func sampleComputation() *verdictComputation {
	return &verdictComputation{
		namespace:          "alpha",
		candidateRuleCount: 1,
		baselineRuleCount:  2,
		flowsRequested:     50,
		flowsSampled:       12,
		counts:             &verdictCounts{newlyDropped: 1, unchanged: 5, replySkipped: 6, total: 12},
		rows: []*verdictRow{
			{change: "NEWLY_DROPPED", src: "alpha/client-1", dst: "alpha/web-1", proto: "TCP", port: 81},
			{change: "UNCHANGED", src: "alpha/client-1", dst: "alpha/web-1", proto: "TCP", port: 80},
		},
		rowCounts: []int{1, 5},
		target:    kubeTarget{context: "kind-lab", apiServer: "https://127.0.0.1:6443"},
		elapsed:   3200 * time.Millisecond,
	}
}

func TestWriteVerdictJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := writeVerdictJSON(&buf, sampleComputation(), "web.yaml", []string{"CiliumNetworkPolicy alpha/web"}, 10, exitVerdictDropped); err != nil {
		t.Fatalf("writeVerdictJSON: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, buf.String())
	}
	if out["result"] != "dropped" || out["exitCode"].(float64) != exitVerdictDropped {
		t.Errorf("result/exitCode wrong: %v/%v", out["result"], out["exitCode"])
	}
	if out["judgedFlows"].(float64) != 6 || out["candidate"] != "web.yaml" || out["namespace"] != "alpha" {
		t.Errorf("summary fields wrong: %v", out)
	}
	if counts := out["counts"].(map[string]any); counts["newlyDropped"].(float64) != 1 {
		t.Errorf("counts not embedded from the ui response shape: %v", counts)
	}
	if rows := out["rows"].([]any); len(rows) != 2 {
		t.Errorf("want 2 rows, got %d", len(rows))
	}
	if r := out["replacedPolicies"].([]any); len(r) != 1 {
		t.Errorf("replacedPolicies missing: %v", out["replacedPolicies"])
	}
	if out["context"] != "kind-lab" || out["apiServer"] != "https://127.0.0.1:6443" {
		t.Errorf("context/apiServer wrong: %v/%v", out["context"], out["apiServer"])
	}
	if out["durationMs"].(float64) != 3200 {
		t.Errorf("durationMs wrong: %v", out["durationMs"])
	}
}

func TestWriteVerdictMarkdown(t *testing.T) {
	var buf bytes.Buffer
	writeVerdictMarkdown(&buf, sampleComputation(), "web.yaml", []string{"CiliumNetworkPolicy alpha/web"}, 0, exitVerdictDropped)
	md := buf.String()
	for _, want := range []string{
		"### GuardBee verdict: `web.yaml`",
		"**FAIL**: 1 sampled flow(s) would break",
		"| NEWLY_DROPPED | `alpha/client-1` | `alpha/web-1` | TCP/81 | 1 |",
		"<details><summary>1 unchanged flow(s)</summary>",
		"Replaces live `CiliumNetworkPolicy alpha/web`",
		"- Context: `kind-lab` (https://127.0.0.1:6443)",
		"- Duration: 3.2s",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "\x1b[") {
		t.Error("markdown must not contain ANSI color codes")
	}

	buf.Reset()
	comp := sampleComputation()
	comp.counts = &verdictCounts{unchanged: 2, total: 2}
	comp.rows, comp.rowCounts = nil, nil
	writeVerdictMarkdown(&buf, comp, "web.yaml", nil, 10, exitVerdictTooFewFlows)
	if !strings.Contains(buf.String(), "**INCONCLUSIVE**: only 2 flow(s) judged, 10 required") {
		t.Errorf("insufficient-flows status missing:\n%s", buf.String())
	}
}

const unrelatedConfigMap = `apiVersion: v1
kind: ConfigMap
metadata:
  name: settings
data:
  key: value
`

// A rendered kustomize file has bystander documents next to the policies:
// the CLI skips them and judges the policies, while the shared parser (the
// UI's path) still rejects an unsupported kind.
func TestParseCandidateDocsSkipsNonPolicyDocuments(t *testing.T) {
	logger := slog.Default()
	raw := []byte(liveWebPolicy + "---\n" + unrelatedConfigMap + "---\n" + liveOtherPolicy)

	docs, skipped, err := parseCandidateDocs(logger, raw, "", true)
	if err != nil {
		t.Fatalf("parseCandidateDocs: %v", err)
	}
	rules := flattenCandidateRules(docs)
	if len(docs) != 2 || docs[0].display() != "CiliumNetworkPolicy alpha/web" {
		t.Errorf("want the two policies in file order, got %d docs, first %q", len(docs), docs[0].display())
	}
	want, err := parseCandidateYAML(logger, []byte(liveWebPolicy+"---\n"+liveOtherPolicy), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != len(want) || len(rules) == 0 {
		t.Errorf("want the %d rules of the two policies, got %d", len(want), len(rules))
	}
	if len(skipped) != 1 || skipped[0] != "ConfigMap settings" {
		t.Errorf("skipped = %v, want [ConfigMap settings]", skipped)
	}

	if _, err := parseCandidateYAML(logger, raw, ""); err == nil {
		t.Error("parseCandidateYAML must keep rejecting an unsupported kind (the UI's behaviour)")
	}
}

func TestParseCandidateDocsNoPolicyIsAnError(t *testing.T) {
	_, _, err := parseCandidateDocs(slog.Default(), []byte(unrelatedConfigMap), "", true)
	if err == nil || !strings.Contains(err.Error(), "no CiliumNetworkPolicy") {
		t.Errorf("a file without any policy must fail, not read as an empty pass: %v", err)
	}
}

// A document that IS a policy but is malformed must fail the run: skipping
// is for bystanders, never for a policy the author meant to ship.
func TestParseCandidateDocsStillRejectsBrokenPolicy(t *testing.T) {
	raw := unrelatedConfigMap + "---\nkind: CiliumNetworkPolicy\nspec: [not, a, map]\n"
	if _, _, err := parseCandidateDocs(slog.Default(), []byte(raw), "alpha", true); err == nil {
		t.Error("a malformed CiliumNetworkPolicy document must fail the run, not be skipped")
	}
}

func TestWorstExitCode(t *testing.T) {
	cases := []struct {
		name  string
		codes []int
		want  int
	}{
		{"none", nil, 0},
		{"all pass", []int{0, 0}, 0},
		{"dropped outranks allowed even though 4 > 2", []int{exitVerdictAllowed, exitVerdictDropped}, exitVerdictDropped},
		{"allowed outranks thin sample", []int{exitVerdictTooFewFlows, exitVerdictAllowed, 0}, exitVerdictAllowed},
		{"allowed outranks l7", []int{exitVerdictL7, exitVerdictAllowed}, exitVerdictAllowed},
		{"l7 outranks thin sample", []int{exitVerdictTooFewFlows, exitVerdictL7}, exitVerdictL7},
		{"thin sample outranks pass", []int{0, exitVerdictTooFewFlows}, exitVerdictTooFewFlows},
	}
	for _, c := range cases {
		if got := worstExitCode(c.codes); got != c.want {
			t.Errorf("%s: want %d, got %d", c.name, c.want, got)
		}
	}
}

const secondCandidatePolicy = `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: cache
  namespace: alpha
spec:
  endpointSelector:
    matchLabels:
      app: cache
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: client
      toPorts:
        - ports:
            - port: "6379"
              protocol: TCP
`

// Two policies and one unrelated document, spread over a file and stdin,
// come out as two policies; the loader reports every source and skips the
// bystander.
func TestLoadCandidateDocsFilesAndStdin(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "rendered.yaml")
	if err := os.WriteFile(file, []byte(narrowedWebCandidate+"---\n"+unrelatedConfigMap), 0o600); err != nil {
		t.Fatal(err)
	}
	docs, sources, err := loadCandidateDocs(slog.Default(), []string{file, "-"}, strings.NewReader(secondCandidatePolicy), "alpha")
	if err != nil {
		t.Fatalf("loadCandidateDocs: %v", err)
	}
	if len(docs) != 2 || docs[0].display() != "CiliumNetworkPolicy alpha/web" || docs[1].display() != "CiliumNetworkPolicy alpha/cache" {
		t.Fatalf("want web then cache, got %+v", docs)
	}
	if docs[0].source != file || docs[1].source != "stdin" || len(sources) != 2 {
		t.Errorf("sources wrong: %q %q %v", docs[0].source, docs[1].source, sources)
	}

	merged := groupCandidates(docs, sources, false)
	if len(merged) != 1 || len(merged[0].rules) != len(flattenCandidateRules(docs)) {
		t.Errorf("default must stay one merged candidate, got %d groups", len(merged))
	}
	per := groupCandidates(docs, sources, true)
	if len(per) != 2 || per[0].label != "CiliumNetworkPolicy alpha/web ("+file+")" || per[1].label != "CiliumNetworkPolicy alpha/cache (stdin)" {
		t.Errorf("per-policy groups wrong: %+v", per)
	}

	if _, _, err := loadCandidateDocs(slog.Default(), []string{filepath.Join(dir, "missing.yaml")}, strings.NewReader(""), ""); err == nil {
		t.Error("a missing file must be an error")
	}
}

// The acceptance case: a file with two policies and one unrelated document
// judged per policy gives one result each, and the overall code is the worst.
// Here the narrowed "web" edit drops a sampled flow while "cache" changes
// nothing that was sampled.
func TestJudgeGroupPerPolicyWorstExitCode(t *testing.T) {
	logger := slog.Default()
	cs := fake.NewSimpleClientset(liveCNP(t, liveWebPolicy), liveCNP(t, liveOtherPolicy))

	docs, _, err := parseCandidateDocs(logger, []byte(narrowedWebCandidate+"---\n"+unrelatedConfigMap+"---\n"+secondCandidatePolicy), "alpha", true)
	if err != nil {
		t.Fatal(err)
	}
	for i := range docs {
		docs[i].source = "rendered.yaml"
	}
	groups := groupCandidates(docs, []string{"rendered.yaml"}, true)
	if len(groups) != 2 {
		t.Fatalf("want 2 policies (ConfigMap skipped), got %d", len(groups))
	}

	ep := func(id uint32, pod, app string) *flowpb.Endpoint {
		return &flowpb.Endpoint{Identity: id, PodName: pod, Namespace: "alpha",
			Labels: []string{"k8s:app=" + app, "k8s:io.kubernetes.pod.namespace=alpha"}}
	}
	client, web := ep(1100, "client-1", "client"), ep(1200, "web-1", "web")
	flows := []*flowpb.Flow{{Source: client, Destination: web, L4: &flowpb.Layer4{
		Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 81}},
	}}}

	baselineRules, skipped, err := fetchBaselineRules(logger, cs, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	var runs []groupRun
	for _, g := range groups {
		run, err := judgeGroup(logger, baselineRules, skipped, nil, "alpha", flowFilter{}, 50, false, true, g, flows, true, false, false, 0, time.Now(), kubeTarget{})
		if err != nil {
			t.Fatalf("judgeGroup(%s): %v", g.label, err)
		}
		runs = append(runs, *run)
	}
	if runs[0].code != exitVerdictDropped || runs[0].comp.counts.newlyDropped != 1 {
		t.Errorf("web edit: want exit %d with 1 newly dropped, got exit %d counts %+v", exitVerdictDropped, runs[0].code, runs[0].comp.counts)
	}
	if runs[1].code != 0 {
		t.Errorf("cache policy changes nothing sampled: want exit 0, got %d", runs[1].code)
	}
	if got := worstExitCode([]int{runs[0].code, runs[1].code}); got != exitVerdictDropped {
		t.Errorf("overall: want %d, got %d", exitVerdictDropped, got)
	}

	var jsonBuf, mdBuf bytes.Buffer
	if err := writeMultiVerdictJSON(&jsonBuf, runs, 0, exitVerdictDropped); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Policies []map[string]any `json:"policies"`
		Result   string           `json:"result"`
		ExitCode int              `json:"exitCode"`
	}
	if err := json.Unmarshal(jsonBuf.Bytes(), &out); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, jsonBuf.String())
	}
	if len(out.Policies) != 2 || out.Result != "dropped" || out.ExitCode != exitVerdictDropped || out.Policies[1]["exitCode"].(float64) != 0 {
		t.Errorf("multi JSON wrong: %+v", out)
	}
	writeMultiVerdictMarkdown(&mdBuf, runs, 0, exitVerdictDropped)
	for _, want := range []string{"## GuardBee verdict: 2 policies, overall **DROPPED**", "### GuardBee verdict: `CiliumNetworkPolicy alpha/web (rendered.yaml)`", "### GuardBee verdict: `CiliumNetworkPolicy alpha/cache (rendered.yaml)`"} {
		if !strings.Contains(mdBuf.String(), want) {
			t.Errorf("multi markdown missing %q:\n%s", want, mdBuf.String())
		}
	}
}

func TestMdCell(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", ""},
		{"alpha/web-1", "`alpha/web-1`"},
		{"a|b", "`a\\|b`"},
		{"a\nb\r\nc", "`a b  c`"},
		{"a`b", "``a`b``"},
		{"a``b`c", "```a``b`c```"},
		{"`x`", "`` `x` ``"},
		{"x`", "`` x` ``"},
	} {
		if got := mdCell(c.in); got != c.want {
			t.Errorf("mdCell(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Any HTTP client of a workload behind an L7 rule picks the request path a
// verdict row names; in the CI comment it must stay text, not become a link,
// an @mention or bold.
func TestWriteVerdictMarkdownL7RequestIsInert(t *testing.T) {
	live := api.Rules{backendHTTPRule(t, api.PortRuleHTTP{Method: "GET", Path: "/api/.*"})}
	cand := api.Rules{backendHTTPRule(t, api.PortRuleHTTP{Method: "GET", Path: "/api/v2/.*"})}
	base, candE := l7Engines(t, live, cand)
	f := httpFlow("GET", "http://backend/api/v1/@octocat/[click](https://evil.example)/**b**?q=`x`")
	row := judgeFlow(slog.Default(), base, candE, f, &verdictCounts{}, false)
	if row == nil || row.change != "NEWLY_DROPPED" {
		t.Fatalf("want a NEWLY_DROPPED row, got %+v", row)
	}
	var buf bytes.Buffer
	comp := &verdictComputation{counts: &verdictCounts{newlyDropped: 1, total: 1}, rows: []*verdictRow{row}, rowCounts: []int{1}}
	writeVerdictMarkdown(&buf, comp, "c.yaml", nil, 0, exitVerdictDropped)

	var line string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(l, "| NEWLY_DROPPED |") {
			line = l
		}
	}
	start := strings.Index(line, "/80 | ")
	end := strings.LastIndex(line, " | ")
	if start < 0 || end <= start {
		t.Fatalf("no L7 cell in:\n%s", buf.String())
	}
	cell := line[start+len("/80 | ") : end]
	inner, ok := strings.CutPrefix(cell, "``")
	if ok {
		inner, ok = strings.CutSuffix(inner, "``")
	}
	if !ok || strings.Contains(inner, "``") {
		t.Fatalf("L7 cell must be one code span fenced by two backticks: %q", cell)
	}
	for _, want := range []string{"[click](https://evil.example)", "@octocat", "**b**", "`x`"} {
		if !strings.Contains(inner, want) {
			t.Errorf("L7 cell lost %q: %q", want, cell)
		}
	}
}
