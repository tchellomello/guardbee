package main

// Regression tests for Phase 2's adaptive gating (see compat.go): both the
// pure version-range check (gateApplies) and the real rejection path
// (checkFeatureGates / parseCandidateYAML) against synthetic version
// strings and hand-built candidates — no live cluster needed, matching
// this project's existing engine_spike_test.go/verdict_test.go style of
// exercising the real logic standalone.

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/policy/api"
)

func TestGateApplies(t *testing.T) {
	gate := featureGate{name: "test-gate", minVersion: "1.20"}

	cases := []struct {
		name    string
		version string
		want    bool
	}{
		{"exact floor version", "1.20.0", true},
		{"patch above floor", "1.20.5", true},
		{"minor above floor", "1.21.0", true},
		{"major above floor", "2.0.0", true},
		{"below floor minor", "1.19.9", false},
		{"below floor major", "0.9.0", false},
		{"unparseable version is conservative (applies)", "garbage", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := gateApplies(c.version, gate); got != c.want {
				t.Errorf("gateApplies(%q, %+v) = %v, want %v", c.version, gate, got, c.want)
			}
		})
	}
}

func TestGateAppliesRespectsMaxVersion(t *testing.T) {
	gate := featureGate{name: "bounded-gate", minVersion: "1.15", maxVersion: "1.18"}

	if gateApplies("1.19.0", gate) {
		t.Error("expected gate not to apply above maxVersion")
	}
	if !gateApplies("1.16.0", gate) {
		t.Error("expected gate to apply inside [minVersion, maxVersion]")
	}
}

// candidateWithFromRequires builds a minimal api.Rule with a non-empty
// FromRequires, the one real gated construct featureGates currently knows
// about (see compat.go's doc comment for why: Parse() silently drops it
// rather than rejecting it, which is the actual bug this gate exists to
// close).
func candidateWithFromRequires() api.Rules {
	return api.Rules{
		&api.Rule{
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromRequires: []string{"k8s:io.kubernetes.pod.namespace=default"},
					},
				},
			},
		},
	}
}

func TestCheckFeatureGatesRejectsFromRequiresOnGatedVersion(t *testing.T) {
	err := checkFeatureGates(candidateWithFromRequires(), "1.20.2")
	if err == nil {
		t.Fatal("expected a gate rejection error, got nil")
	}
	if !strings.Contains(err.Error(), "fromRequires/toRequires") {
		t.Errorf("error %q does not name the gate", err.Error())
	}
}

func TestCheckFeatureGatesAllowsFromRequiresBelowGateFloor(t *testing.T) {
	// A version older than the gate's minVersion ("1.20") has no confirmed
	// gate data (see compat.go's doc comment on why this entry is floored
	// at 1.20 rather than unconditional) — must pass through unchanged,
	// exactly like before this feature existed, not newly rejected on a
	// version this gate was never verified against.
	err := checkFeatureGates(candidateWithFromRequires(), "1.15.0")
	if err != nil {
		t.Errorf("expected no rejection below the gate's floor, got: %v", err)
	}
}

func TestCheckFeatureGatesAllowsOrdinaryCandidate(t *testing.T) {
	ordinary := api.Rules{
		&api.Rule{
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(),
						},
					},
				},
			},
		},
	}
	if err := checkFeatureGates(ordinary, pinnedCiliumVersion); err != nil {
		t.Errorf("expected no rejection for a candidate with no gated construct, got: %v", err)
	}
}

// TestParseCandidateYAMLRejectsFromRequires exercises the real,
// end-to-end call site (verdict.go's parseCandidateYAML) rather than only
// the pure checkFeatureGates helper — this is the actual decision point
// the "verdict"/"ui" subcommands hit, and the concrete behavior this
// feature changes: before this gate existed, parseCandidateYAML called
// cnp.Parse() directly and it succeeded silently (confirmed by hand before
// writing this gate — see compat.go's doc comment), discarding
// FromRequires without a trace. Now it's rejected before Parse() ever
// runs.
func TestParseCandidateYAMLRejectsFromRequires(t *testing.T) {
	yamlDoc := []byte(`
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: probe
  namespace: default
spec:
  endpointSelector: {}
  ingress:
  - fromRequires:
    - "k8s:io.kubernetes.pod.namespace=default"
    fromEndpoints:
    - matchLabels:
        role: frontend
`)
	_, err := parseCandidateYAML(slog.Default(), yamlDoc, "")
	if err == nil {
		t.Fatal("expected parseCandidateYAML to reject a candidate with fromRequires, got nil error")
	}
	if !strings.Contains(err.Error(), "fromRequires/toRequires") {
		t.Errorf("error %q does not name the gate", err.Error())
	}
}

func TestParseCandidateYAMLAllowsOrdinaryCandidate(t *testing.T) {
	yamlDoc := []byte(`
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: probe2
  namespace: default
spec:
  endpointSelector: {}
  ingress:
  - fromEndpoints:
    - matchLabels:
        role: frontend
`)
	rules, err := parseCandidateYAML(slog.Default(), yamlDoc, "")
	if err != nil {
		t.Fatalf("unexpected rejection of an ordinary candidate: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("expected 1 parsed rule, got %d", len(rules))
	}
}
