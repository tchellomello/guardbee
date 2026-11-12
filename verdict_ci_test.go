package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
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
		_, _, replaced, baseline, candidate, err := buildVerdictEnginesWith(logger, cs, "alpha", candidateRules, replace)
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
		minFlows      int
		want          int
	}{
		{"plain run never fails", verdictCounts{newlyDropped: 3}, false, 0, 0},
		{"dropped with gate", verdictCounts{newlyDropped: 1, unchanged: 40}, true, 0, exitVerdictDropped},
		{"clean with gate", verdictCounts{unchanged: 40}, true, 0, 0},
		{"too few judged", verdictCounts{unchanged: 3, replySkipped: 50}, false, 10, exitVerdictTooFewFlows},
		{"replies and not-simulated don't count", verdictCounts{unchanged: 9, replySkipped: 30, notSimulated: 30}, true, 10, exitVerdictTooFewFlows},
		{"enough judged", verdictCounts{unchanged: 8, newlyAllowed: 2}, true, 10, 0},
		{"dropped outranks thin sample", verdictCounts{newlyDropped: 1}, true, 10, exitVerdictDropped},
	}
	for _, c := range cases {
		if got := verdictExitCode(&c.counts, c.failOnDropped, c.minFlows); got != c.want {
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
}

func TestWriteVerdictMarkdown(t *testing.T) {
	var buf bytes.Buffer
	writeVerdictMarkdown(&buf, sampleComputation(), "web.yaml", []string{"CiliumNetworkPolicy alpha/web"}, 0, exitVerdictDropped)
	md := buf.String()
	for _, want := range []string{
		"### GuardBee verdict: `web.yaml`",
		"**FAIL**: 1 sampled flow(s) would break",
		"| NEWLY_DROPPED | alpha/client-1 | alpha/web-1 | TCP/81 | 1 |",
		"<details><summary>1 unchanged flow(s)</summary>",
		"Replaces live CiliumNetworkPolicy alpha/web",
		"- Context: `kind-lab` (https://127.0.0.1:6443)",
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
