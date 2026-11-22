package main

import (
	"log/slog"
	"strings"
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_type_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/policy/api"
)

func regexHeader(name, re string) *envoy_config_route.HeaderMatcher {
	return &envoy_config_route.HeaderMatcher{Name: name, HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
		StringMatch: &envoy_type_matcher.StringMatcher{MatchPattern: &envoy_type_matcher.StringMatcher_SafeRegex{
			SafeRegex: &envoy_type_matcher.RegexMatcher{Regex: re}}}}}
}

func exactHeader(name, v string) *envoy_config_route.HeaderMatcher {
	return &envoy_config_route.HeaderMatcher{Name: name, HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_StringMatch{
		StringMatch: &envoy_type_matcher.StringMatcher{MatchPattern: &envoy_type_matcher.StringMatcher_Exact{Exact: v}}}}
}

func presentHeader(name string, present bool) *envoy_config_route.HeaderMatcher {
	return &envoy_config_route.HeaderMatcher{Name: name, HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_PresentMatch{PresentMatch: present}}
}

func inverted(hm *envoy_config_route.HeaderMatcher) *envoy_config_route.HeaderMatcher {
	hm.InvertMatch = true
	return hm
}

func hubbleHTTP(method, rawURL string, headers ...string) *httpRequest {
	h := &flowpb.HTTP{Method: method, Url: rawURL}
	for i := 0; i+1 < len(headers); i += 2 {
		h.Headers = append(h.Headers, &flowpb.HTTPHeader{Key: headers[i], Value: headers[i+1]})
	}
	r, err := httpRequestFromHubble(h)
	if err != nil {
		panic(err)
	}
	return r
}

// Envoy v1.37.5 source/common/http/header_utility.h semantics, and the
// header-level cases of cilium/proxy's HttpPolicyUpdate test.
func TestEnvoyHeaderMatches(t *testing.T) {
	cases := []struct {
		name string
		hm   *envoy_config_route.HeaderMatcher
		req  *httpRequest
		want bool
	}{
		// cilium/proxy HttpPolicyUpdate: exact :path, '.*public$' regex.
		{"exact path", exactHeader(":path", "/allowed"), hubbleHTTP("GET", "http://x/allowed"), true},
		{"exact path, other", exactHeader(":path", "/allowed"), hubbleHTTP("GET", "http://x/notallowed"), false},
		{"regex is a full match", regexHeader(":path", ".*public$"), hubbleHTTP("GET", "http://x/public"), true},
		{"regex is a full match, suffix", regexHeader(":path", ".*public$"), hubbleHTTP("GET", "http://x/publicz"), false},
		// Cilium matches path rules on :path, which carries the query.
		{"path regex vs query", regexHeader(":path", "/metrics"), hubbleHTTP("GET", "http://x/metrics?debug=1"), false},
		{"path regex with query", regexHeader(":path", "/metrics(\\?.*)?"), hubbleHTTP("GET", "http://x/metrics?debug=1"), true},
		{"method regex", regexHeader(":method", "GET|HEAD"), hubbleHTTP("HEAD", "http://x/"), true},
		{"host regex", regexHeader(":authority", "api\\.example\\.com(:\\d+)?"), hubbleHTTP("GET", "http://api.example.com:8080/"), true},
		// Header names are case-insensitive; repeated values are joined with ",".
		{"header name case", exactHeader("X-Team", "a"), hubbleHTTP("GET", "http://x/", "x-team", "a"), true},
		{"repeated header joined", exactHeader("x-team", "a,b"), hubbleHTTP("GET", "http://x/", "X-Team", "a", "X-Team", "b"), true},
		{"repeated header not one value", exactHeader("x-team", "a"), hubbleHTTP("GET", "http://x/", "X-Team", "a", "X-Team", "b"), false},
		// Missing header: no match, and invert_match does not flip that...
		{"missing, exact", exactHeader("x-team", "a"), hubbleHTTP("GET", "http://x/"), false},
		{"missing, inverted exact", inverted(exactHeader("x-team", "a")), hubbleHTTP("GET", "http://x/"), false},
		{"present, inverted exact", inverted(exactHeader("x-team", "a")), hubbleHTTP("GET", "http://x/", "x-team", "b"), true},
		// ...except for a present match: invert == present.
		{"present match, present", presentHeader("x-team", true), hubbleHTTP("GET", "http://x/", "x-team", "a"), true},
		{"present match, missing", presentHeader("x-team", true), hubbleHTTP("GET", "http://x/"), false},
		{"inverted present match, missing", inverted(presentHeader("x-team", true)), hubbleHTTP("GET", "http://x/"), true},
		{"absent match, missing", presentHeader("x-team", false), hubbleHTTP("GET", "http://x/"), true},
		{"absent match, present", presentHeader("x-team", false), hubbleHTTP("GET", "http://x/", "x-team", "a"), false},
		// Envoy's exact "" matches only an empty value (ExactStringMatcher:
		// value == exact), so Cilium's "secret unreadable" encoding (exact ""
		// inverted) matches any non-empty value — despite the translator's
		// "NEVER match" comment. Rules with secrets aren't judged for that
		// reason (TestJudgeFlowHTTPSecretNotJudged); this pins Envoy's side.
		{"inverted empty exact, non-empty value", inverted(exactHeader("x-token", "")), hubbleHTTP("GET", "http://x/", "x-token", "s3cret"), true},
		{"inverted empty exact, missing", inverted(exactHeader("x-token", "")), hubbleHTTP("GET", "http://x/"), false},
	}
	for _, c := range cases {
		got, judged := envoyHeaderMatches(c.hm, c.req)
		if !judged || got != c.want {
			t.Errorf("%s: want %v, got %v (judged %v)", c.name, c.want, got, judged)
		}
	}

	// A redacted header the rule reads can't be judged.
	if _, judged := envoyHeaderMatches(exactHeader("authorization", "x"), hubbleHTTP("GET", "http://x/", "Authorization", hubbleRedacted)); judged {
		t.Error("a redacted header must not be judged")
	}
}

// cilium/proxy network_policy.cc HeaderMatch::allowed: only FAIL actions reject.
func TestCiliumHeaderMatch(t *testing.T) {
	req := hubbleHTTP("GET", "http://x/", "x-team", "a")
	cases := []struct {
		name string
		hm   *cilium.HeaderMatch
		want bool
	}{
		{"fail on mismatch, matches", &cilium.HeaderMatch{Name: "x-team", Value: "a"}, true},
		{"fail on mismatch, mismatches", &cilium.HeaderMatch{Name: "x-team", Value: "b"}, false},
		{"log on mismatch", &cilium.HeaderMatch{Name: "x-team", Value: "b", MismatchAction: cilium.HeaderMatch_CONTINUE_ON_MISMATCH}, true},
		{"add on mismatch", &cilium.HeaderMatch{Name: "x-other", Value: "b", MismatchAction: cilium.HeaderMatch_ADD_ON_MISMATCH}, true},
		{"replace on mismatch", &cilium.HeaderMatch{Name: "x-team", Value: "b", MismatchAction: cilium.HeaderMatch_REPLACE_ON_MISMATCH}, true},
		{"presence", &cilium.HeaderMatch{Name: "x-team"}, true},
		{"fail on match", &cilium.HeaderMatch{Name: "x-team", Value: "a", MatchAction: cilium.HeaderMatch_FAIL_ON_MATCH}, false},
	}
	for _, c := range cases {
		got, judged := ciliumHeaderMatch(c.hm, req)
		if !judged || got != c.want {
			t.Errorf("%s: want %v, got %v (judged %v)", c.name, c.want, got, judged)
		}
	}
	if _, judged := ciliumHeaderMatch(&cilium.HeaderMatch{Name: "x-team", ValueSdsSecret: "ns/s"}, req); judged {
		t.Error("a secret-backed value must not be judged")
	}
}

func httpFlow(method, rawURL string, headers ...string) *flowpb.Flow {
	f := tcp80Flow(l7FrontendNID)
	h := &flowpb.HTTP{Method: method, Url: rawURL}
	for i := 0; i+1 < len(headers); i += 2 {
		h.Headers = append(h.Headers, &flowpb.HTTPHeader{Key: headers[i], Value: headers[i+1]})
	}
	f.L7 = &flowpb.Layer7{Type: flowpb.L7FlowType_REQUEST, Record: &flowpb.Layer7_Http{Http: h}}
	return f
}

// End to end through Cilium's own policy engine and Envoy translator.
func TestJudgeFlowHTTPRequests(t *testing.T) {
	live := api.Rules{backendHTTPRule(t, api.PortRuleHTTP{Method: "GET", Path: "/api/.*"}, api.PortRuleHTTP{Method: "GET", Path: "/healthz"})}
	cand := api.Rules{backendHTTPRule(t,
		api.PortRuleHTTP{Method: "GET", Path: "/api/v2/.*", Headers: []string{"X-Team: payments"}},
		api.PortRuleHTTP{Method: "GET", Path: "/healthz"})}
	base, candE := l7Engines(t, live, cand)

	cases := []struct {
		name string
		flow *flowpb.Flow
		want string // "" = UNCHANGED (no row)
	}{
		{"still matched", httpFlow("GET", "http://backend/healthz"), ""},
		{"query breaks a path rule", httpFlow("GET", "http://backend/healthz?full=1"), ""}, // 403 on both sides
		{"v1 dropped", httpFlow("GET", "http://backend/api/v1/users"), "NEWLY_DROPPED"},
		{"v2 without the header dropped", httpFlow("GET", "http://backend/api/v2/users"), "NEWLY_DROPPED"},
		{"v2 with the header kept", httpFlow("GET", "http://backend/api/v2/users", "X-Team", "payments"), ""},
		{"POST denied either way", httpFlow("POST", "http://backend/api/v1/users"), ""},
	}
	for _, c := range cases {
		row := judgeFlow(slog.Default(), base, candE, c.flow, &verdictCounts{}, false)
		got := ""
		if row != nil {
			got = row.change
		}
		if got != c.want {
			t.Errorf("%s: want %q, got %q (%+v)", c.name, c.want, got, row)
			continue
		}
		if row != nil && (row.l7Judge != "guardbee" || !strings.Contains(row.l7Request, "matched by GuardBee, not Envoy")) {
			t.Errorf("%s: HTTP verdict must carry GuardBee's marker: %+v", c.name, row)
		}
	}

	// A redacted header the candidate reads: not judged, so the row falls
	// back to comparing the rules, and says why.
	row := judgeFlow(slog.Default(), base, candE, httpFlow("GET", "http://backend/api/v2/users", "X-Team", hubbleRedacted), &verdictCounts{}, false)
	if row == nil || row.change != "L7_CHANGED" || !strings.Contains(row.l7Request, "not judged") || row.l7Judge != "" {
		t.Fatalf("redacted header: want an L7_CHANGED row saying it's not judged, got %+v", row)
	}

	// Hubble may redact URL queries without a trace: the gate turns HTTP
	// judging off for the whole run.
	candE.httpGate = func() string { return "Hubble redacts URL queries" }
	row = judgeFlow(slog.Default(), base, candE, httpFlow("GET", "http://backend/api/v1/users"), &verdictCounts{}, false)
	if row == nil || row.change != "L7_CHANGED" || !strings.Contains(row.l7Request, "HTTP requests not judged: Hubble redacts URL queries") {
		t.Fatalf("gated: want L7_CHANGED naming the reason, got %+v", row)
	}
}

func TestJudgeFlowHTTPSecretNotJudged(t *testing.T) {
	secret := api.PortRuleHTTP{Path: "/", HeaderMatches: []*api.HeaderMatch{{Name: "x-token", Secret: &api.Secret{Namespace: "ns", Name: "token"}}}}
	base, cand := l7Engines(t, nil, api.Rules{backendHTTPRule(t, secret)})
	row := judgeFlow(slog.Default(), base, cand, httpFlow("GET", "http://backend/", "x-token", "s3cret"), &verdictCounts{}, false)
	if row == nil || row.l7Judge != "" || !strings.Contains(row.l7Request, "not judged") {
		t.Fatalf("a secret-backed header rule must not be judged: %+v", row)
	}
}
