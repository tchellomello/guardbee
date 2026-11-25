package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	"sigs.k8s.io/yaml"
)

// A deny-all for the "web" pods: wrapped in a List next to a benign policy,
// it is the policy a gate that skipped Lists let through unjudged.
const denyAllWebPolicy = `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: deny-web
  namespace: alpha
spec:
  endpointSelector:
    matchLabels:
      app: web
  ingressDeny:
    - fromEntities:
        - all
`

const kubernetesNetworkPolicy = `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: lockdown
  namespace: alpha
spec:
  podSelector: {}
  policyTypes: [Ingress]
`

// listOf wraps items in a list document of the given apiVersion/kind. With
// bare, each item's own apiVersion/kind is dropped, so it has to inherit
// them from the list the way kubectl infers them.
func listOf(t *testing.T, apiVersion, kind string, bare bool, items ...string) string {
	t.Helper()
	var objs []map[string]any
	for _, it := range items {
		var m map[string]any
		if err := yaml.Unmarshal([]byte(it), &m); err != nil {
			t.Fatal(err)
		}
		if bare {
			delete(m, "apiVersion")
			delete(m, "kind")
		}
		objs = append(objs, m)
	}
	out, err := yaml.Marshal(map[string]any{"apiVersion": apiVersion, "kind": kind, "items": objs})
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// kubectl apply applies the items of a List; so must the gate judge them.
// Before, every wrapper below was skipped as a non-policy "List" document
// and only the benign policy was judged.
func TestParseCandidateDocsExpandsLists(t *testing.T) {
	cases := map[string]string{
		"v1 List":                       listOf(t, "v1", "List", false, denyAllWebPolicy),
		"CiliumNetworkPolicyList":       listOf(t, "cilium.io/v2", "CiliumNetworkPolicyList", false, denyAllWebPolicy),
		"CiliumNetworkPolicyList, bare": listOf(t, "cilium.io/v2", "CiliumNetworkPolicyList", true, denyAllWebPolicy),
		"nested List":                   listOf(t, "v1", "List", false, listOf(t, "v1", "List", false, denyAllWebPolicy)),
	}
	for name, wrapped := range cases {
		raw := []byte(secondCandidatePolicy + "---\n" + wrapped)
		for _, skip := range []bool{true, false} { // the CLI's path and the UI's
			docs, skipped, err := parseCandidateDocs(slog.Default(), raw, "alpha", skip)
			if err != nil {
				t.Errorf("%s (skip=%v): %v", name, skip, err)
				continue
			}
			if len(docs) != 2 || docs[1].display() != "CiliumNetworkPolicy alpha/deny-web" || len(docs[1].rules) == 0 {
				t.Errorf("%s (skip=%v): want cache and the wrapped deny-web judged, got %d docs %+v", name, skip, len(docs), docs)
			}
			if len(skipped) != 0 {
				t.Errorf("%s (skip=%v): nothing should be skipped, got %v", name, skip, skipped)
			}
		}
	}
}

// A List's items go through the same checks as top-level documents: a
// bystander inside is skipped and reported, a broken policy inside fails.
func TestParseCandidateDocsListItemsLikeDocuments(t *testing.T) {
	raw := []byte(listOf(t, "v1", "List", false, unrelatedConfigMap, denyAllWebPolicy))
	docs, skipped, err := parseCandidateDocs(slog.Default(), raw, "alpha", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 || len(skipped) != 1 || skipped[0] != "ConfigMap settings" {
		t.Errorf("want deny-web judged and the ConfigMap skipped, got %d docs, skipped %v", len(docs), skipped)
	}

	broken := strings.Replace(denyAllWebPolicy, "ingressDeny:", "ingressDeny: 7\n  x:", 1)
	_, _, err = parseCandidateDocs(slog.Default(), []byte(listOf(t, "v1", "List", false, broken)), "alpha", true)
	if err == nil || !strings.Contains(err.Error(), "item 1") {
		t.Errorf("a broken policy inside a List must fail and say where: %v", err)
	}

	if _, _, err := parseCandidateDocs(slog.Default(), []byte("apiVersion: v1\nkind: List\nitems: []\n"), "alpha", false); err == nil {
		t.Error("an empty List must not read as an empty candidate on the UI path")
	}
}

// The gate itself: a benign policy plus a List-wrapped deny-all that breaks a
// sampled flow must exit exitVerdictDropped under --fail-on-dropped.
func TestJudgeGroupListWrappedDenyFailsOnDropped(t *testing.T) {
	logger := slog.Default()
	cs := fake.NewSimpleClientset(liveCNP(t, liveWebPolicy), liveCNP(t, liveOtherPolicy))
	raw := secondCandidatePolicy + "---\n" + listOf(t, "cilium.io/v2", "CiliumNetworkPolicyList", false, denyAllWebPolicy)
	docs, _, err := parseCandidateDocs(logger, []byte(raw), "alpha", true)
	if err != nil {
		t.Fatal(err)
	}
	g := groupCandidates(docs, []string{"pr.yaml"}, false)[0]

	ep := func(id uint32, pod, app string) *flowpb.Endpoint {
		return &flowpb.Endpoint{Identity: id, PodName: pod, Namespace: "alpha",
			Labels: []string{"k8s:app=" + app, "k8s:io.kubernetes.pod.namespace=alpha"}}
	}
	flows := []*flowpb.Flow{{Source: ep(1100, "client-1", "client"), Destination: ep(1200, "web-1", "web"), L4: &flowpb.Layer4{
		Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 80}},
	}}}
	baselineRules, skipped, err := fetchBaselineRules(logger, cs, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	run, err := judgeGroup(logger, baselineRules, skipped, nil, "alpha", flowFilter{}, 50, false, false, g, flows, true, false, false, 0, time.Now(), kubeTarget{})
	if err != nil {
		t.Fatal(err)
	}
	if run.code != exitVerdictDropped || run.comp.counts.newlyDropped != 1 {
		t.Errorf("want exit %d with 1 newly dropped, got exit %d counts %+v", exitVerdictDropped, run.code, run.comp.counts)
	}
}

// What the gate did not judge is in the outputs a reviewer reads, not only
// on stderr; a NetworkPolicy, which Cilium enforces, is named apart.
func TestSkippedDocumentsInOutputs(t *testing.T) {
	_, _, skipped, err := loadCandidateDocs(slog.Default(), []string{"-"},
		strings.NewReader(kubernetesNetworkPolicy+"---\n"+narrowedWebCandidate+"---\n"+unrelatedConfigMap), "alpha")
	if err != nil {
		t.Fatal(err)
	}
	comp := sampleComputation()
	comp.skippedDocuments = skipped

	var md bytes.Buffer
	writeVerdictMarkdown(&md, comp, "web.yaml", nil, 0, exitVerdictDropped)
	for _, want := range []string{
		"- Not judged (Kubernetes NetworkPolicy: Cilium enforces it, GuardBee does not simulate it): `NetworkPolicy lockdown (stdin)`",
		"- Not judged (not a Cilium policy): `ConfigMap settings (stdin)`",
	} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("markdown missing %q:\n%s", want, md.String())
		}
	}

	var js bytes.Buffer
	if err := writeVerdictJSON(&js, comp, "web.yaml", nil, 0, exitVerdictDropped); err != nil {
		t.Fatal(err)
	}
	var out struct {
		SkippedDocuments []string `json:"skippedDocuments"`
	}
	if err := json.Unmarshal(js.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.SkippedDocuments) != 2 || out.SkippedDocuments[0] != "NetworkPolicy lockdown (stdin)" {
		t.Errorf("skippedDocuments = %v", out.SkippedDocuments)
	}
}
