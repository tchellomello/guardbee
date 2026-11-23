package main

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/api"
)

// toFQDNs regression suite: a candidate's selector is matched against the
// names Hubble attached to the flow (fqdnverdict.go), not only against fqdn:
// labels already on the destination identity.

const fqdnWebappEgress = `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: webapp-egress
  namespace: webapp
spec:
  endpointSelector:
    matchLabels:
      app: webapp
  egress:
    - toFQDNs:
        - %s
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
`

func fqdnPolicy(selector string) string {
	return fmt.Sprintf(fqdnWebappEgress, selector)
}

// fqdnFlow is webapp opening TCP/443 to an external IP. dstID/dstLabels are
// what Hubble reports for the destination; names its destination_names.
func fqdnFlow(dstID uint32, dstLabels []string, names ...string) *flowpb.Flow {
	return &flowpb.Flow{
		Source: &flowpb.Endpoint{
			Identity:  1000,
			Namespace: "webapp",
			Labels:    []string{"k8s:app=webapp", "k8s:io.kubernetes.pod.namespace=webapp"},
		},
		Destination:      &flowpb.Endpoint{Identity: dstID, Labels: dstLabels},
		DestinationNames: names,
		L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
	}
}

func worldFlow(names ...string) *flowpb.Flow {
	return fqdnFlow(uint32(identity.ReservedIdentityWorld), []string{"reserved:world"}, names...)
}

type fqdnJudge struct {
	t                   *testing.T
	baseline, candidate *verdictEngine
	counts              verdictCounts
}

func newFQDNJudge(t *testing.T, baselineYAML, candidateYAML string) *fqdnJudge {
	t.Helper()
	logger := slog.Default()
	engine := func(yaml string) *verdictEngine {
		var rules api.Rules
		if yaml != "" {
			r, err := parseCandidateYAML(logger, []byte(yaml), "")
			if err != nil {
				t.Fatalf("parseCandidateYAML: %v", err)
			}
			rules = r
		}
		e, err := newVerdictEngine(logger, rules, identity.IdentityMap{})
		if err != nil {
			t.Fatalf("newVerdictEngine: %v", err)
		}
		t.Cleanup(func() { e.close(logger) })
		return e
	}
	return &fqdnJudge{t: t, baseline: engine(baselineYAML), candidate: engine(candidateYAML)}
}

// change judges f and returns its category, "" when not simulated.
func (j *fqdnJudge) change(f *flowpb.Flow) string {
	j.t.Helper()
	row := judgeFlow(slog.Default(), j.baseline, j.candidate, f, &j.counts, true)
	if row == nil {
		return ""
	}
	return row.change
}

func TestFQDNNewSelectorMatchesHubbleName(t *testing.T) {
	// No live policy: webapp egress is default-allow. Before Phase 4 the new
	// selector had no fqdn: label to match, so this was a false NEWLY_DROPPED.
	j := newFQDNJudge(t, "", fqdnPolicy("matchName: api.github.com"))
	if got := j.change(worldFlow("api.github.com")); got != "UNCHANGED" {
		t.Errorf("api.github.com under its own toFQDNs: got %q, want UNCHANGED", got)
	}
	// Hubble's names are lowercase without the trailing dot, but don't
	// depend on it.
	if got := j.change(worldFlow("API.GitHub.com.")); got != "UNCHANGED" {
		t.Errorf("mixed case with trailing dot: got %q, want UNCHANGED", got)
	}
	if got := j.change(worldFlow("evil.example.com")); got != "NEWLY_DROPPED" {
		t.Errorf("a name no selector matches: got %q, want NEWLY_DROPPED", got)
	}
}

func TestFQDNMatchPatternFollowsCilium(t *testing.T) {
	j := newFQDNJudge(t, "", fqdnPolicy(`matchPattern: "*.github.com"`))
	for name, want := range map[string]string{
		"api.github.com":   "UNCHANGED",
		"github.com":       "NEWLY_DROPPED", // "*." needs a label in front
		"a.b.github.com":   "NEWLY_DROPPED", // "*" is one DNS label
		"api.github.com.x": "NEWLY_DROPPED",
	} {
		if got := j.change(worldFlow(name)); got != want {
			t.Errorf("%s under *.github.com: got %q, want %q", name, got, want)
		}
	}
}

func TestFQDNAnyNameOfTheIPMatches(t *testing.T) {
	// One IP behind several names (a CDN): the name manager labels the IP
	// for every name, so one matching name is enough.
	j := newFQDNJudge(t, "", fqdnPolicy("matchName: api.github.com"))
	if got := j.change(worldFlow("cdn.example.net", "api.github.com")); got != "UNCHANGED" {
		t.Errorf("IP with a matching second name: got %q, want UNCHANGED", got)
	}
}

func TestFQDNNamesBehindWorldDoNotShareAnIdentity(t *testing.T) {
	// Both flows are reserved:world (2) on Hubble's side. If the labelled
	// copy kept number 2, whichever name came first would decide the other.
	j := newFQDNJudge(t, "", fqdnPolicy("matchName: api.github.com"))
	for i, c := range []struct{ name, want string }{
		{"api.github.com", "UNCHANGED"},
		{"evil.example.com", "NEWLY_DROPPED"},
		{"api.github.com", "UNCHANGED"},
	} {
		if got := j.change(worldFlow(c.name)); got != c.want {
			t.Errorf("flow %d (%s): got %q, want %q", i, c.name, got, c.want)
		}
	}
}

func TestFQDNReplacedLiveSelectorDrops(t *testing.T) {
	// The live policy allows api.github.com, so Hubble already reports the
	// IP's local identity with its fqdn: label (the case that worked before
	// Phase 4). The candidate replaces it with a selector for another name.
	live := fqdnPolicy("matchName: api.github.com")
	j := newFQDNJudge(t, live, fqdnPolicy("matchName: other.example.com"))
	f := fqdnFlow(uint32(identity.IdentityScopeLocal|1), []string{"reserved:world", "fqdn:api.github.com"}, "api.github.com")
	if got := j.change(f); got != "NEWLY_DROPPED" {
		t.Errorf("api.github.com after its selector is replaced: got %q, want NEWLY_DROPPED", got)
	}

	// Same live state, candidate unchanged: still allowed.
	j = newFQDNJudge(t, live, live)
	if got := j.change(f); got != "UNCHANGED" {
		t.Errorf("api.github.com under the same live selector: got %q, want UNCHANGED", got)
	}
}

func TestFQDNWithoutNamesIsNotSimulated(t *testing.T) {
	// No destination_names: the source's DNS bypasses the DNS proxy, so
	// nothing says whether the selector would match. Withheld, not dropped.
	j := newFQDNJudge(t, "", fqdnPolicy("matchName: api.github.com"))
	if got := j.change(worldFlow()); got != "" {
		t.Fatalf("world flow without names: got %q, want not simulated", got)
	}
	if j.counts.notSimulated != 1 || j.counts.newlyDropped != 0 {
		t.Fatalf("counts: notSimulated=%d newlyDropped=%d, want 1 and 0", j.counts.notSimulated, j.counts.newlyDropped)
	}

	// A pod destination is never selected by toFQDNs: its drop stays a drop.
	pod := fqdnFlow(2000, []string{"k8s:app=postgres", "k8s:io.kubernetes.pod.namespace=postgres"})
	if got := j.change(pod); got != "NEWLY_DROPPED" {
		t.Errorf("pod destination: got %q, want NEWLY_DROPPED", got)
	}
}

func TestFQDNRowNamesTheDestination(t *testing.T) {
	// "reserved:world" alone doesn't say which site a toFQDNs verdict is
	// about: the row carries the names, and each name is its own row.
	j := newFQDNJudge(t, "", fqdnPolicy("matchName: api.github.com"))
	logger := slog.Default()
	allowed := judgeFlow(logger, j.baseline, j.candidate, worldFlow("api.github.com"), &j.counts, true)
	dropped := judgeFlow(logger, j.baseline, j.candidate, worldFlow("evil.example.com"), &j.counts, true)
	if allowed == nil || dropped == nil {
		t.Fatal("want a row for each flow")
	}
	if got := toRowOut(dropped, 1).DestinationNames; len(got) != 1 || got[0] != "evil.example.com" {
		t.Errorf("JSON destinationNames: got %v, want [evil.example.com]", got)
	}
	if got := dropped.line(1); !strings.Contains(got, "reserved:world (evil.example.com)") {
		t.Errorf("CLI line doesn't name the destination: %s", got)
	}
	other := judgeFlow(logger, j.baseline, j.candidate, worldFlow("other.example.com"), &j.counts, true)
	if other.key() == dropped.key() {
		t.Error("drops to two different names must not merge into one row")
	}

	// A pod's names (its Service's DNS name) add nothing: not shown.
	pod := fqdnFlow(2000, []string{"k8s:app=postgres", "k8s:io.kubernetes.pod.namespace=postgres"}, "postgres.postgres.svc.cluster.local")
	if row := judgeFlow(logger, j.baseline, j.candidate, pod, &j.counts, true); row == nil || row.dstNames != nil {
		t.Errorf("pod destination: want a row without names, got %+v", row)
	}
}
