package main

// Regression suite for L7-ruled ports. Before the fix, distillFor passed an
// empty redirects map to DistillPolicy, which made Cilium omit the MapState
// entry for any port carrying L7 rules (no proxy port to redirect to), so
// isAllowed fell back to default-deny and real traffic to an HTTP- or
// DNS-ruled port read as NEWLY_DROPPED.

import (
	"log/slog"
	"strings"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

const (
	l7FrontendNID identity.NumericIdentity = 1000
	l7BackendNID  identity.NumericIdentity = 2000
	l7OtherNID    identity.NumericIdentity = 3000
)

var l7Identities = identity.IdentityMap{
	l7FrontendNID: labels.ParseLabelArray("role=frontend"),
	l7BackendNID:  labels.ParseLabelArray("role=backend"),
	l7OtherNID:    labels.ParseLabelArray("role=other"),
}

// backendHTTPRule selects role=backend, allowing role=frontend on TCP/80,
// with the given HTTP rules (nil = plain L4 allow).
func backendHTTPRule(t *testing.T, http ...api.PortRuleHTTP) *api.Rule {
	t.Helper()
	pr := api.PortRule{Ports: []api.PortProtocol{{Port: "80", Protocol: api.ProtoTCP}}}
	if http != nil {
		pr.Rules = &api.L7Rules{HTTP: http}
	}
	r := &api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("role=backend")),
		Ingress: []api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.ParseSelectLabel("role=frontend"))},
			},
			ToPorts: api.PortRules{pr},
		}},
	}
	if err := r.Sanitize(); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	return r
}

func l7Engines(t *testing.T, baseRules, candRules api.Rules) (*verdictEngine, *verdictEngine) {
	t.Helper()
	logger := slog.Default()
	base, err := newVerdictEngine(logger, baseRules, l7Identities)
	if err != nil {
		t.Fatalf("baseline engine: %v", err)
	}
	t.Cleanup(func() { base.close(logger) })
	cand, err := newVerdictEngine(logger, candRules, l7Identities)
	if err != nil {
		t.Fatalf("candidate engine: %v", err)
	}
	t.Cleanup(func() { cand.close(logger) })
	return base, cand
}

func tcp80Flow(src identity.NumericIdentity) *flowpb.Flow {
	return &flowpb.Flow{
		Source:      &flowpb.Endpoint{Identity: uint32(src)},
		Destination: &flowpb.Endpoint{Identity: uint32(l7BackendNID)},
		L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 80}}},
	}
}

func TestJudgeFlowL7RulesAreNotADrop(t *testing.T) {
	healthz := api.PortRuleHTTP{Method: "GET", Path: "/healthz"}
	base, cand := l7Engines(t, nil, api.Rules{backendHTTPRule(t, healthz)})

	counts := &verdictCounts{}
	row := judgeFlow(slog.Default(), base, cand, tcp80Flow(l7FrontendNID), counts, false)
	if row == nil {
		t.Fatalf("want an L7_CHANGED row, got nil (counts %+v)", counts)
	}
	if row.change != "L7_CHANGED" {
		t.Fatalf("frontend->backend:80 now behind HTTP rules: want L7_CHANGED, got %s", row.change)
	}
	if counts.l7Changed != 1 || counts.newlyDropped != 0 {
		t.Fatalf("counts: %+v", counts)
	}
	if row.side != "ingress" || row.l7Baseline != "" || !strings.Contains(row.l7Candidate, "GET /healthz") {
		t.Fatalf("row must name the ingress L7 rules the proxy applies: side=%q base=%q cand=%q", row.side, row.l7Baseline, row.l7Candidate)
	}

	// The L4 half still bites: a peer the rule does not select is denied.
	row = judgeFlow(slog.Default(), base, cand, tcp80Flow(l7OtherNID), counts, false)
	if row == nil || row.change != "NEWLY_DROPPED" {
		t.Fatalf("other->backend:80 is not selected by the rule: want NEWLY_DROPPED, got %+v", row)
	}
}

func TestJudgeFlowSameL7RulesUnchanged(t *testing.T) {
	healthz := api.PortRuleHTTP{Method: "GET", Path: "/healthz"}
	live := api.Rules{backendHTTPRule(t, healthz)}
	base, cand := l7Engines(t, live, live)

	counts := &verdictCounts{}
	if row := judgeFlow(slog.Default(), base, cand, tcp80Flow(l7FrontendNID), counts, false); row != nil {
		t.Fatalf("identical L7 rules on both sides: want UNCHANGED (no row), got %+v", row)
	}
	if counts.unchanged != 1 {
		t.Fatalf("counts: %+v", counts)
	}
}

func TestJudgeFlowChangedL7Rules(t *testing.T) {
	base, cand := l7Engines(t,
		api.Rules{backendHTTPRule(t, api.PortRuleHTTP{Method: "GET", Path: "/healthz"})},
		api.Rules{backendHTTPRule(t, api.PortRuleHTTP{Method: "GET", Path: "/api/.*"})})

	row := judgeFlow(slog.Default(), base, cand, tcp80Flow(l7FrontendNID), &verdictCounts{}, false)
	if row == nil || row.change != "L7_CHANGED" {
		t.Fatalf("HTTP rules changed for the same peer/port: want L7_CHANGED, got %+v", row)
	}
	if !strings.Contains(row.l7Baseline, "/healthz") || !strings.Contains(row.l7Candidate, "/api/.*") {
		t.Fatalf("want both rule sets named: base=%q cand=%q", row.l7Baseline, row.l7Candidate)
	}
}

func TestJudgeFlowHubbleL7Records(t *testing.T) {
	healthz := api.PortRuleHTTP{Method: "GET", Path: "/healthz"}
	live := api.Rules{backendHTTPRule(t, healthz)}
	base, cand := l7Engines(t, live, nil)

	req := tcp80Flow(l7FrontendNID)
	req.L7 = &flowpb.Layer7{Type: flowpb.L7FlowType_REQUEST, Record: &flowpb.Layer7_Http{Http: &flowpb.HTTP{Method: "GET", Url: "http://backend/healthz"}}}
	resp := tcp80Flow(l7FrontendNID)
	resp.L7 = &flowpb.Layer7{Type: flowpb.L7FlowType_RESPONSE, Record: &flowpb.Layer7_Http{Http: &flowpb.HTTP{Code: 200}}}

	counts := &verdictCounts{}
	// Candidate drops the live L7 policy entirely: no CNP left -> default allow.
	row := judgeFlow(slog.Default(), base, cand, req, counts, false)
	if row == nil || row.change != "L7_CHANGED" {
		t.Fatalf("L7 request record must be judged on its L4 tuple: want L7_CHANGED, got %+v (counts %+v)", row, counts)
	}
	if row := judgeFlow(slog.Default(), base, cand, resp, counts, false); row != nil {
		t.Fatalf("L7 response record: want skipped, got %+v", row)
	}
	if counts.replySkipped != 1 || counts.notSimulated != 0 {
		t.Fatalf("response must count as a reply, not as not-simulated: %+v", counts)
	}
}

// The common real-world L7 policy: egress DNS through the DNS proxy. Same
// rules on both sides must stay UNCHANGED; narrowing them is L7_CHANGED on
// the egress side, named with the DNS patterns.
func TestJudgeFlowEgressDNSRules(t *testing.T) {
	dnsRule := func(pattern string) *api.Rule {
		r := &api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("role=frontend")),
			Egress: []api.EgressRule{{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.ParseSelectLabel("role=backend"))},
				},
				ToPorts: api.PortRules{{
					Ports: []api.PortProtocol{{Port: "53", Protocol: api.ProtoUDP}},
					Rules: &api.L7Rules{DNS: []api.PortRuleDNS{{MatchPattern: pattern}}},
				}},
			}},
		}
		if err := r.Sanitize(); err != nil {
			t.Fatalf("Sanitize: %v", err)
		}
		return r
	}
	dnsFlow := &flowpb.Flow{
		Source:      &flowpb.Endpoint{Identity: uint32(l7FrontendNID)},
		Destination: &flowpb.Endpoint{Identity: uint32(l7BackendNID)},
		L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 53}}},
	}

	live := api.Rules{dnsRule("*")}
	base, cand := l7Engines(t, live, live)
	if row := judgeFlow(slog.Default(), base, cand, dnsFlow, &verdictCounts{}, false); row != nil {
		t.Fatalf("unchanged DNS rules: want UNCHANGED, got %+v", row)
	}

	base, cand = l7Engines(t, live, api.Rules{dnsRule("*.example.com")})
	row := judgeFlow(slog.Default(), base, cand, dnsFlow, &verdictCounts{}, false)
	if row == nil || row.change != "L7_CHANGED" || row.side != "egress" {
		t.Fatalf("narrowed DNS rules: want egress L7_CHANGED, got %+v", row)
	}
	if !strings.Contains(row.l7Candidate, "egress: DNS *.example.com") {
		t.Fatalf("candidate rules not named: %q", row.l7Candidate)
	}
}
