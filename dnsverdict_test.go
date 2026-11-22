package main

import (
	"log/slog"
	"strings"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

// frontendDNSRule selects role=frontend, allowing DNS to role=backend on
// UDP/53 through the DNS proxy with the given matchPatterns.
func frontendDNSRule(t *testing.T, patterns ...string) *api.Rule {
	t.Helper()
	var rules []api.PortRuleDNS
	for _, p := range patterns {
		rules = append(rules, api.PortRuleDNS{MatchPattern: p})
	}
	r := &api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("role=frontend")),
		Egress: []api.EgressRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.ParseSelectLabel("role=backend"))},
			},
			ToPorts: api.PortRules{{
				Ports: []api.PortProtocol{{Port: "53", Protocol: api.ProtoUDP}},
				Rules: &api.L7Rules{DNS: rules},
			}},
		}},
	}
	if err := r.Sanitize(); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	return r
}

func dnsQueryFlow(query string) *flowpb.Flow {
	return &flowpb.Flow{
		Source:      &flowpb.Endpoint{Identity: uint32(l7FrontendNID)},
		Destination: &flowpb.Endpoint{Identity: uint32(l7BackendNID)},
		L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 53}}},
		L7:          &flowpb.Layer7{Type: flowpb.L7FlowType_REQUEST, Record: &flowpb.Layer7_Dns{Dns: &flowpb.DNS{Query: query}}},
	}
}

func TestJudgeFlowDNSQueryNarrowed(t *testing.T) {
	base, cand := l7Engines(t,
		api.Rules{frontendDNSRule(t, "*")},
		api.Rules{frontendDNSRule(t, "*.example.com")})

	counts := &verdictCounts{}
	row := judgeFlow(slog.Default(), base, cand, dnsQueryFlow("api.github.com."), counts, false)
	if row == nil || row.change != "NEWLY_DROPPED" || row.side != "egress" {
		t.Fatalf("query outside the narrowed rules: want egress NEWLY_DROPPED, got %+v", row)
	}
	if row.l7Request != "DNS api.github.com." {
		t.Fatalf("row must name the query: %q", row.l7Request)
	}
	if !strings.Contains(row.l7Detail(), "DNS api.github.com.; ") {
		t.Fatalf("CLI detail must lead with the query: %q", row.l7Detail())
	}

	// Still matched by the narrowed rules: the rule change doesn't affect it.
	if row := judgeFlow(slog.Default(), base, cand, dnsQueryFlow("www.example.com."), counts, false); row != nil {
		t.Fatalf("query still allowed: want UNCHANGED, got %+v", row)
	}
	// Case and a missing trailing dot don't matter to the DNS proxy.
	if row := judgeFlow(slog.Default(), base, cand, dnsQueryFlow("WWW.Example.COM"), counts, false); row != nil {
		t.Fatalf("query matching modulo case/FQDN: want UNCHANGED, got %+v", row)
	}
	if counts.newlyDropped != 1 || counts.unchanged != 2 || counts.l7Changed != 0 {
		t.Fatalf("counts: %+v", counts)
	}
}

func TestJudgeFlowDNSQueryNewlyFiltered(t *testing.T) {
	// No policy today; the candidate puts DNS rules in front of port 53.
	// "**." spans several labels; a plain "*" is one label only (below).
	base, cand := l7Engines(t, nil, api.Rules{frontendDNSRule(t, "**.cluster.local")})

	row := judgeFlow(slog.Default(), base, cand, dnsQueryFlow("postgres.postgres.svc.cluster.local."), &verdictCounts{}, true)
	if row == nil || row.change != "UNCHANGED" || row.l7Request == "" {
		t.Fatalf("matching query: want UNCHANGED naming the query, got %+v", row)
	}
	row = judgeFlow(slog.Default(), base, cand, dnsQueryFlow("example.org."), &verdictCounts{}, false)
	if row == nil || row.change != "NEWLY_DROPPED" {
		t.Fatalf("non-matching query: want NEWLY_DROPPED, got %+v", row)
	}
	// The classic mistake: "*.cluster.local" matches one label, so a
	// Service name (<svc>.<ns>.svc.cluster.local) is refused. Cilium's own
	// matchpattern semantics, not a GuardBee rule.
	_, single := l7Engines(t, nil, api.Rules{frontendDNSRule(t, "*.cluster.local")})
	row = judgeFlow(slog.Default(), base, single, dnsQueryFlow("postgres.postgres.svc.cluster.local."), &verdictCounts{}, false)
	if row == nil || row.change != "NEWLY_DROPPED" {
		t.Fatalf(`"*.cluster.local" must not match a multi-label Service name: want NEWLY_DROPPED, got %+v`, row)
	}
	// Without a query (an L4 trace of the same connection) it stays an L7
	// rule change, as before.
	plain := dnsQueryFlow("")
	plain.L7 = nil
	row = judgeFlow(slog.Default(), base, cand, plain, &verdictCounts{}, false)
	if row == nil || row.change != "L7_CHANGED" {
		t.Fatalf("connection-level flow: want L7_CHANGED, got %+v", row)
	}
}

func TestJudgeFlowDNSQueryWithoutProxy(t *testing.T) {
	// Neither side sends port 53 through the DNS proxy: the query record is
	// judged on L4 only and gets no per-query row.
	base, cand := l7Engines(t, nil, nil)
	row := judgeFlow(slog.Default(), base, cand, dnsQueryFlow("example.org."), &verdictCounts{}, true)
	if row == nil || row.change != "UNCHANGED" || row.l7Request != "" {
		t.Fatalf("want an UNCHANGED connection-level row, got %+v", row)
	}
}

func TestDNSGeneratePattern(t *testing.T) {
	// A few fixed expectations; dnsverdict_conformance_test.go compares the
	// port against Cilium's own GeneratePattern on Linux.
	cases := []struct {
		rules []api.PortRuleDNS
		want  string
	}{
		{nil, "(?:)"},
		{[]api.PortRuleDNS{{MatchPattern: "*"}}, "(?:)"},
		{[]api.PortRuleDNS{{MatchName: "Example.COM"}}, `^(?:example[.]com[.])$`},
	}
	for _, c := range cases {
		if got := dnsGeneratePattern(&policy.PerSelectorPolicy{L7Rules: api.L7Rules{DNS: c.rules}}); got != c.want {
			t.Errorf("%+v: want %q, got %q", c.rules, c.want, got)
		}
	}
}

func TestCandidateWarningsFQDNWithoutDNS(t *testing.T) {
	fqdnOnly := &api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("role=frontend")),
		Egress:           []api.EgressRule{{ToFQDNs: api.FQDNSelectorSlice{{MatchName: "api.github.com"}}}},
	}
	got := candidateWarnings(api.Rules{fqdnOnly})
	if len(got) != 1 || !strings.Contains(got[0], "toFQDNs") || !strings.Contains(got[0], "rules.dns") {
		t.Fatalf("toFQDNs without a DNS rule: want one warning, got %v", got)
	}
	// The same candidate carrying its DNS rule: nothing to warn about.
	if got := candidateWarnings(api.Rules{fqdnOnly, frontendDNSRule(t, "*")}); len(got) != 0 {
		t.Fatalf("with a DNS rule: want no warning, got %v", got)
	}
	// No toFQDNs at all: nothing to warn about.
	if got := candidateWarnings(api.Rules{backendHTTPRule(t, api.PortRuleHTTP{Path: "/"})}); len(got) != 0 {
		t.Fatalf("no toFQDNs: want no warning, got %v", got)
	}

	var md strings.Builder
	comp := &verdictComputation{counts: &verdictCounts{}, warnings: candidateWarnings(api.Rules{fqdnOnly})}
	writeVerdictMarkdown(&md, comp, "c.yaml", nil, 0, 0)
	if !strings.Contains(md.String(), "- Warning: ") {
		t.Fatalf("markdown must carry the warning:\n%s", md.String())
	}
}
