package main

// Exercises the actual verdictEngine/isAllowed code used by the "verdict"
// subcommand (not a reimplementation) against a hand-built scenario, without
// needing a live cluster or Hubble: baseline has no CNPs at all (true
// default-allow), candidate adds one rule selecting "backend" that only
// allows "frontend" on TCP/80. This is exactly the case the tool exists to
// catch: adding an ingress-selecting policy silently flips every other port
// on that workload from default-allow to default-deny.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestVerdictEngineNewlyDroppedOnDefaultDenyFlip(t *testing.T) {
	logger := slog.Default()

	const (
		frontendNID identity.NumericIdentity = 1000
		backendNID  identity.NumericIdentity = 2000
	)

	identities := identity.IdentityMap{
		frontendNID: labels.ParseLabelArray("role=frontend"),
		backendNID:  labels.ParseLabelArray("role=backend"),
	}

	var baselineRules api.Rules // no CNPs exist yet

	candidateRules := api.Rules{
		&api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("role=backend")),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(labels.ParseSelectLabel("role=frontend")),
						},
					},
					ToPorts: api.PortRules{
						{Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}}},
					},
				},
			},
		},
	}

	baseline, err := newVerdictEngine(logger, baselineRules, identities)
	if err != nil {
		t.Fatalf("newVerdictEngine(baseline): %v", err)
	}
	defer baseline.close(logger)

	candidate, err := newVerdictEngine(logger, candidateRules, identities)
	if err != nil {
		t.Fatalf("newVerdictEngine(candidate): %v", err)
	}
	defer candidate.close(logger)

	baseEpp, err := baseline.distillFor(logger, backendNID)
	if err != nil {
		t.Fatalf("baseline.distillFor: %v", err)
	}
	candEpp, err := candidate.distillFor(logger, backendNID)
	if err != nil {
		t.Fatalf("candidate.distillFor: %v", err)
	}

	port80 := policy.IngressKey().WithIdentity(frontendNID).WithTCPPort(80)
	port81 := policy.IngressKey().WithIdentity(frontendNID).WithTCPPort(81)

	// Port 80: explicitly allowed by the candidate rule — should read as
	// allowed under both baseline (default-allow, no policy at all) and
	// candidate (explicit allow) -> UNCHANGED.
	if !isAllowed(baseEpp, port80) {
		t.Fatal("expected baseline to default-allow port 80 (no CNPs exist)")
	}
	if !isAllowed(candEpp, port80) {
		t.Fatal("expected candidate to explicitly allow port 80")
	}

	// Port 81: never mentioned by the candidate rule. Baseline still
	// default-allows it (no policy selects backend at all). Candidate now
	// selects backend, so unmentioned ports flip to deny -> NEWLY_DROPPED.
	if !isAllowed(baseEpp, port81) {
		t.Fatal("expected baseline to default-allow port 81 (no CNPs exist)")
	}
	if isAllowed(candEpp, port81) {
		t.Fatal("expected candidate to deny port 81 (backend is now policy-selected, 81 isn't explicitly allowed)")
	}

	t.Log("verdict engine PASS: port 80 UNCHANGED (allow->allow), port 81 correctly classified NEWLY_DROPPED (allow->deny)")
}

// Regression test for the Get-vs-Lookup fix: a rule with a broad covering
// peer selector (frontend, no port restriction -> wildcard-port allow) and a
// separate narrower rule for a different peer must not hide each other. Get
// is exact-match only and would miss the frontend's wildcard-port entry when
// looking up a specific port for it; Lookup correctly finds the covering
// entry via LPM.
func TestVerdictEngineLookupFindsWildcardPortCoveringEntry(t *testing.T) {
	logger := slog.Default()

	const (
		frontendNID identity.NumericIdentity = 1000
		backendNID  identity.NumericIdentity = 2000
	)
	identities := identity.IdentityMap{
		frontendNID: labels.ParseLabelArray("role=frontend"),
		backendNID:  labels.ParseLabelArray("role=backend"),
	}

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("role=backend")),
			Ingress: []api.IngressRule{
				{
					// No ToPorts at all -> allow frontend on every port.
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(labels.ParseSelectLabel("role=frontend")),
						},
					},
				},
			},
		},
	}

	engine, err := newVerdictEngine(logger, rules, identities)
	if err != nil {
		t.Fatalf("newVerdictEngine: %v", err)
	}
	defer engine.close(logger)

	epp, err := engine.distillFor(logger, backendNID)
	if err != nil {
		t.Fatalf("distillFor: %v", err)
	}

	// No entry exists for this exact port — only the wildcard-port entry for
	// frontend does. Get would miss it; Lookup must find it via LPM.
	key := policy.IngressKey().WithIdentity(frontendNID).WithTCPPort(12345)
	if !isAllowed(epp, key) {
		t.Fatal("expected frontend's wildcard-port allow rule to cover an unlisted specific port via Lookup's LPM match")
	}
}

// Regression test for -follow: an engine built with NO known identities
// (exactly what verdict -follow does, since it can't pre-seed from an
// unbounded live stream) must still compute the correct verdict once
// addIdentities registers an identity discovered mid-stream, for both the
// peer selector cache and the subject selector cache.
func TestVerdictEngineIncrementalIdentityDiscovery(t *testing.T) {
	logger := slog.Default()

	const (
		frontendNID identity.NumericIdentity = 1000
		backendNID  identity.NumericIdentity = 2000
	)

	rules := api.Rules{
		&api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("role=backend")),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(labels.ParseSelectLabel("role=frontend")),
						},
					},
					ToPorts: api.PortRules{
						{Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}}},
					},
				},
			},
		},
	}

	// Start with nothing known — this is the -follow starting state.
	engine, err := newVerdictEngine(logger, rules, identity.IdentityMap{})
	if err != nil {
		t.Fatalf("newVerdictEngine: %v", err)
	}
	defer engine.close(logger)

	// Simulate a flow arriving mid-stream: its identities weren't known at
	// construction time, so they must be registered now.
	engine.addIdentities(logger, identity.IdentityMap{
		frontendNID: labels.ParseLabelArray("role=frontend"),
		backendNID:  labels.ParseLabelArray("role=backend"),
	})

	epp, err := engine.distillFor(logger, backendNID)
	if err != nil {
		t.Fatalf("distillFor after addIdentities: %v", err)
	}

	port80 := policy.IngressKey().WithIdentity(frontendNID).WithTCPPort(80)
	if !isAllowed(epp, port80) {
		t.Fatal("expected frontend->backend:80 to be allowed after identities discovered mid-stream via addIdentities")
	}

	// A second, later-arriving identity must also invalidate the cache for
	// destinations already distilled, not just extend it going forward.
	const laterNID identity.NumericIdentity = 3000
	engine.addIdentities(logger, identity.IdentityMap{
		laterNID: labels.ParseLabelArray("role=frontend"),
	})
	epp2, err := engine.distillFor(logger, backendNID)
	if err != nil {
		t.Fatalf("distillFor after second addIdentities: %v", err)
	}
	laterKey := policy.IngressKey().WithIdentity(laterNID).WithTCPPort(80)
	if !isAllowed(epp2, laterKey) {
		t.Fatal("expected a second, later-discovered frontend identity to also be allowed on port 80")
	}
}

// Regression test for the one-shot output dedup: a repeating peer (e.g. a
// kubelet probe firing every ~10s) must key identically across occurrences
// so the caller's dedup map collapses it to one row, while a genuinely
// different row (different change, peer, protocol, or port) must not
// collide with it.
func TestVerdictRowKeyDedupsIdenticalRowsOnly(t *testing.T) {
	probe := &verdictRow{change: "NEWLY_DROPPED", src: "reserved:host", dst: "homeassistant/homeassistant-0", proto: "TCP", port: 8123}
	probeAgain := &verdictRow{change: "NEWLY_DROPPED", src: "reserved:host", dst: "homeassistant/homeassistant-0", proto: "TCP", port: 8123}
	if probe.key() != probeAgain.key() {
		t.Fatalf("expected identical rows to share a dedup key, got %q vs %q", probe.key(), probeAgain.key())
	}

	differentPeer := &verdictRow{change: "NEWLY_DROPPED", src: "private-gateway/private-xkt22", dst: "homeassistant/homeassistant-0", proto: "TCP", port: 8123}
	differentPort := &verdictRow{change: "NEWLY_DROPPED", src: "reserved:host", dst: "homeassistant/homeassistant-0", proto: "TCP", port: 80}
	differentChange := &verdictRow{change: "NEWLY_ALLOWED", src: "reserved:host", dst: "homeassistant/homeassistant-0", proto: "TCP", port: 8123}
	for _, other := range []*verdictRow{differentPeer, differentPort, differentChange} {
		if probe.key() == other.key() {
			t.Fatalf("expected a genuinely different row not to share probe's dedup key %q", probe.key())
		}
	}

	if got := probe.line(1); strings.Contains(got, "seen") {
		t.Fatalf("expected no 'seen Nx' suffix for a count of 1, got %q", got)
	}
	if got := probe.line(8); !strings.Contains(got, "seen 8x") {
		t.Fatalf("expected a 'seen 8x' suffix for a count of 8, got %q", got)
	}
}

// Regression test for --show-unchanged: judgeFlow must return nil for an
// UNCHANGED verdict by default (today's behavior, matching the user's own
// prior ask to not print one row per unchanged flow), but return a real
// *verdictRow for it when showUnchanged is true, so the caller can dedup and
// print it like any other row.
func TestJudgeFlowShowUnchanged(t *testing.T) {
	logger := slog.Default()

	const (
		frontendNID identity.NumericIdentity = 1000
		backendNID  identity.NumericIdentity = 2000
	)
	identities := identity.IdentityMap{
		frontendNID: labels.ParseLabelArray("role=frontend"),
		backendNID:  labels.ParseLabelArray("role=backend"),
	}

	// No CNPs on either side -> both default-allow -> every flow is UNCHANGED.
	baseline, err := newVerdictEngine(logger, nil, identities)
	if err != nil {
		t.Fatalf("newVerdictEngine(baseline): %v", err)
	}
	defer baseline.close(logger)
	candidate, err := newVerdictEngine(logger, nil, identities)
	if err != nil {
		t.Fatalf("newVerdictEngine(candidate): %v", err)
	}
	defer candidate.close(logger)

	flow := &flowpb.Flow{
		Source:      &flowpb.Endpoint{Identity: uint32(frontendNID)},
		Destination: &flowpb.Endpoint{Identity: uint32(backendNID)},
		L4: &flowpb.Layer4{
			Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 80}},
		},
	}

	counts := &verdictCounts{}
	if row := judgeFlow(logger, baseline, candidate, flow, counts, false); row != nil {
		t.Fatalf("expected judgeFlow to return nil for UNCHANGED with showUnchanged=false, got %+v", row)
	}
	if counts.unchanged != 1 {
		t.Fatalf("expected the UNCHANGED tally to still increment regardless of showUnchanged, got %d", counts.unchanged)
	}

	row := judgeFlow(logger, baseline, candidate, flow, counts, true)
	if row == nil {
		t.Fatal("expected judgeFlow to return a row for UNCHANGED with showUnchanged=true")
	}
	if row.change != "UNCHANGED" {
		t.Fatalf("expected change=UNCHANGED, got %q", row.change)
	}
	if counts.unchanged != 2 {
		t.Fatalf("expected the UNCHANGED tally to increment again on the second call, got %d", counts.unchanged)
	}
}

func TestPolicyValidateEndpoint(t *testing.T) {
	srv := &uiServer{logger: slog.Default()}

	validYAML := `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: test-valid
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: test
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: client
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
`

	// 1. Valid case
	reqBody, _ := json.Marshal(policyValidateRequest{
		Namespace:     "default",
		CandidateYAML: validYAML,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/policy/validate", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	srv.handlePolicyValidate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp policyValidateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshaling response: %v", err)
	}
	if !resp.Valid || resp.RuleCount == 0 {
		t.Fatalf("expected valid policy with rules, got %+v", resp)
	}

	// 2. Invalid case: combining ToEndpoints and ToEntities in same rule item
	invalidYAML := `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: test-invalid
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: test
  egress:
    - toEndpoints:
        - matchLabels:
            app: backend
      toEntities:
        - world
`
	reqBody, _ = json.Marshal(policyValidateRequest{
		Namespace:     "default",
		CandidateYAML: invalidYAML,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/policy/validate", bytes.NewReader(reqBody))
	w = httptest.NewRecorder()
	srv.handlePolicyValidate(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var invalidResp policyValidateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &invalidResp); err != nil {
		t.Fatalf("unmarshaling response: %v", err)
	}
	if invalidResp.Valid {
		t.Fatalf("expected invalid policy, got %+v", invalidResp)
	}
	// Cilium's own IngressCommonRule/EgressCommonRule.sanitize() (vendored
	// pkg/policy/api/rule_validation.go) builds this message from a
	// map[string]int of field names and a nested `for range` over it — Go
	// deliberately randomizes map iteration order per process, so which
	// field name comes first in the sentence ("combining ToEndpoints and
	// ToEntities..." vs "combining ToEntities and ToEndpoints...") varies
	// run to run. Asserting on one fixed order was flaky by construction;
	// checking both names plus the stable suffix is order-independent.
	if !strings.Contains(invalidResp.Error, "ToEndpoints") ||
		!strings.Contains(invalidResp.Error, "ToEntities") ||
		!strings.Contains(invalidResp.Error, "is not supported yet") {
		t.Fatalf("expected error mentioning combining ToEndpoints/ToEntities, got %q", invalidResp.Error)
	}
}

// TestPolicyParseEndpoint covers POST /api/policy/parse (the Policy
// Editor's YAML import/hand-edit path, see ui.go's handlePolicyParse): a
// valid CNP round-trips to a correct templatePolicyModel, a valid CCNP's
// namespace comes back via its io.kubernetes.pod.namespace target label
// (same convention convertRuleToPolicyModel already uses for the live-
// policy "Edit in Policy Editor" path), and invalid YAML returns a clean
// {valid:false, error} response rather than panicking.
func TestPolicyParseEndpoint(t *testing.T) {
	srv := &uiServer{logger: slog.Default()}

	postParse := func(t *testing.T, namespace, candidateYAML string) policyParseResponse {
		t.Helper()
		reqBody, _ := json.Marshal(policyValidateRequest{Namespace: namespace, CandidateYAML: candidateYAML})
		req := httptest.NewRequest(http.MethodPost, "/api/policy/parse", bytes.NewReader(reqBody))
		w := httptest.NewRecorder()
		srv.handlePolicyParse(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status 200, got %d", w.Code)
		}
		var resp policyParseResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshaling response: %v", err)
		}
		return resp
	}

	t.Run("valid CNP", func(t *testing.T) {
		resp := postParse(t, "default", `
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: test-parse-cnp
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: test
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: client
      toPorts:
        - ports:
            - port: "80"
              protocol: TCP
`)
		if !resp.Valid || resp.Policy == nil {
			t.Fatalf("expected a valid parsed policy, got %+v", resp)
		}
		if resp.Policy.Kind != "CiliumNetworkPolicy" || resp.Policy.Name != "test-parse-cnp" || resp.Policy.Namespace != "default" {
			t.Fatalf("expected kind/name/namespace to round-trip, got %+v", resp.Policy)
		}
		if len(resp.Policy.IngressRules) != 1 || len(resp.Policy.IngressRules[0].ToPorts) != 1 {
			t.Fatalf("expected one ingress rule with one port rule, got %+v", resp.Policy.IngressRules)
		}
	})

	t.Run("valid CCNP carries its namespace via the target label", func(t *testing.T) {
		resp := postParse(t, "", `
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: test-parse-ccnp
spec:
  endpointSelector:
    matchLabels:
      io.kubernetes.pod.namespace: "payments"
  ingress:
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: "payments"
`)
		if !resp.Valid || resp.Policy == nil {
			t.Fatalf("expected a valid parsed policy, got %+v", resp)
		}
		if resp.Policy.Kind != "CiliumClusterwideNetworkPolicy" || resp.Policy.Namespace != "payments" {
			t.Fatalf("expected the CCNP's io.kubernetes.pod.namespace target label to surface as Namespace, got %+v", resp.Policy)
		}
	})

	t.Run("invalid YAML returns a clean error, not a panic", func(t *testing.T) {
		resp := postParse(t, "default", "not: [valid, cilium, policy")
		if resp.Valid {
			t.Fatalf("expected an invalid response, got %+v", resp)
		}
		if resp.Error == "" {
			t.Fatal("expected a non-empty error message")
		}
	})

	t.Run("unsupported kind returns a clean error, not a panic", func(t *testing.T) {
		resp := postParse(t, "default", `
apiVersion: v1
kind: ConfigMap
metadata:
  name: not-a-policy
`)
		if resp.Valid {
			t.Fatalf("expected an invalid response, got %+v", resp)
		}
		if !strings.Contains(resp.Error, "unsupported kind") {
			t.Fatalf("expected an unsupported-kind error, got %q", resp.Error)
		}
	})
}

// TestCompatEndpoint covers GET /api/compat (ui.go's handleCompat) — the
// UI's/CLI's shared view of compat.go's featureGates table, so "why was my
// candidate rejected" has a page to check rather than only the rejection
// error text. Asserts the response mirrors featureGates directly, not a
// hardcoded count, so this doesn't need updating every time a new gate is
// added.
func TestCompatEndpoint(t *testing.T) {
	srv := &uiServer{logger: slog.Default()}

	req := httptest.NewRequest(http.MethodGet, "/api/compat", nil)
	w := httptest.NewRecorder()
	srv.handleCompat(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}
	var resp compatResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshaling response: %v", err)
	}
	if resp.Pinned != pinnedCiliumVersion {
		t.Errorf("expected pinned %q, got %q", pinnedCiliumVersion, resp.Pinned)
	}
	if len(resp.Gates) != len(featureGates) {
		t.Fatalf("expected %d gates (one per featureGates entry), got %d", len(featureGates), len(resp.Gates))
	}
	for i, g := range featureGates {
		if resp.Gates[i].Name != g.name || resp.Gates[i].Reason != g.reason {
			t.Errorf("gate %d: expected name/reason %q/%q, got %q/%q", i, g.name, g.reason, resp.Gates[i].Name, resp.Gates[i].Reason)
		}
	}
}

