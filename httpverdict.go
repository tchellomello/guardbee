package main

// HTTP request verdicts: whether Envoy would let a request Hubble recorded
// through, under baseline and under candidate policy.
//
// Unlike DNS (dnsverdict.go), the deciding code isn't Go: Envoy and
// cilium/proxy are C++. What IS Cilium's own is the input: each selector's
// PerSelectorPolicy.EnvoyHTTPRules() is the exact HttpNetworkPolicyRules
// proto the agent sends Envoy, produced by Cilium's EnvoyL7RulesTranslator.
// GuardBee only evaluates those protos, following Envoy v1.37.5
// (cilium/proxy's ENVOY_VERSION at the pinned proxy revision):
//   - source/common/http/header_utility.{h,cc}: every HeaderMatcher of a
//     rule must match; a missing header never matches except for a present
//     match (invert == present); repeated headers are joined with ",";
//     safe_regex is an RE2 full match; invert_match flips the result.
//   - cilium/network_policy.cc: a request is allowed if, among the rules
//     whose selector selects the peer, any HTTP rule matches; an HTTP-less
//     rule allows everything; HeaderMatch actions other than FAIL only
//     rewrite the request.
// So these rows are marked "matched by GuardBee, not Envoy". Anything
// outside that subset (deny/pass rules, mixed precedence, Envoy listeners,
// SNI, secret-backed header values, a redacted header the rule reads,
// unknown matcher kinds) is not judged rather than guessed.

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_type_matcher "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
)

// hubbleRedacted is the value Hubble puts in place of a redacted header
// (pkg/defaults.SensitiveValueRedacted).
const hubbleRedacted = "HUBBLE_REDACTED"

// httpRequest is a Hubble HTTP record as the header map Envoy matches on:
// lowercased names, pseudo-headers included.
type httpRequest struct {
	method, path string
	headers      map[string][]string
	redacted     map[string]bool
}

func httpRequestFromHubble(h *flowpb.HTTP) (*httpRequest, error) {
	u, err := url.Parse(h.GetUrl())
	if err != nil || h.GetMethod() == "" {
		return nil, fmt.Errorf("unusable HTTP record (method %q, url %q)", h.GetMethod(), h.GetUrl())
	}
	// Envoy's :path is the request target, query included.
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" || u.ForceQuery {
		path += "?" + u.RawQuery
	}
	r := &httpRequest{method: h.GetMethod(), path: path, headers: map[string][]string{}, redacted: map[string]bool{}}
	r.headers[":method"] = []string{h.GetMethod()}
	r.headers[":path"] = []string{path}
	if u.Host != "" {
		r.headers[":authority"] = []string{u.Host}
	}
	for _, hd := range h.GetHeaders() {
		name := strings.ToLower(hd.GetKey())
		if hd.GetValue() == hubbleRedacted {
			r.redacted[name] = true
		}
		r.headers[name] = append(r.headers[name], hd.GetValue())
	}
	return r, nil
}

// httpRequestVerdict answers whether the proxy would allow req, sent by (or
// to) peer, on key's port. judged is false when that can't be read off the
// policy without guessing; allowed is then meaningless. A flow whose entry
// isn't a proxy redirect never reaches Envoy: allowed by definition.
func httpRequestVerdict(epp *policy.EndpointPolicy, key policy.Key, peer identity.NumericIdentity, req *httpRequest) (allowed, judged bool) {
	filter, redirected := redirectFilter(epp, key)
	if !redirected {
		return true, true
	}
	if filter == nil || !filterHasParser(filter, policy.ParserTypeHTTP) {
		return false, false
	}
	selected, havePrecedence := false, false
	var precedence policytypes.Precedence
	for cs, psp := range filter.PerSelectorPolicies {
		if !cs.Selects(peer) {
			continue
		}
		if psp != nil {
			if psp.IsDeny() || psp.IsPass() || psp.GetListener() != "" || len(psp.ServerNames) > 0 || usesHeaderSecret(psp) {
				return false, false
			}
			// shortcut: Envoy orders rules by precedence (policy tiers);
			// only a single precedence is modelled. Upgrade if seen live.
			if havePrecedence && psp.GetPrecedence() != precedence {
				return false, false
			}
			precedence, havePrecedence = psp.GetPrecedence(), true
		}
		selected = true
		if psp == nil || psp.EnvoyHTTPRules() == nil {
			allowed = true // no HTTP rules for this selector: any request
			continue
		}
		for _, rule := range psp.EnvoyHTTPRules().GetHttpRules() {
			m, ok := httpRuleMatches(rule, req)
			if !ok {
				return false, false
			}
			allowed = allowed || m
		}
	}
	if !selected {
		// Redirected, yet no rule names this peer: not a case to guess at.
		return false, false
	}
	return allowed, true
}

// usesHeaderSecret: a headerMatches value from a Kubernetes Secret. What
// Envoy gets depends on whether the agent's own secret fetch succeeded (an
// SDS reference, or Cilium's "fetch failed" matcher), which isn't visible
// here, so such rules are never judged.
func usesHeaderSecret(psp *policy.PerSelectorPolicy) bool {
	for _, h := range psp.HTTP {
		for _, hm := range h.HeaderMatches {
			if hm.Secret != nil {
				return true
			}
		}
	}
	return false
}

// httpRuleMatches is HttpNetworkPolicyRule::allowed && headerMatches.
func httpRuleMatches(rule *cilium.HttpNetworkPolicyRule, req *httpRequest) (matches, judged bool) {
	for _, hm := range rule.GetHeaders() {
		m, ok := envoyHeaderMatches(hm, req)
		if !ok {
			return false, false
		}
		if !m {
			return false, true
		}
	}
	for _, hm := range rule.GetHeaderMatches() {
		m, ok := ciliumHeaderMatch(hm, req)
		if !ok {
			return false, false
		}
		if !m {
			return false, true
		}
	}
	return true, true
}

// envoyHeaderMatches is Envoy's HeaderData::matchesHeaders for the
// matcher kinds Cilium's translator emits (plus prefix/suffix/contains).
func envoyHeaderMatches(hm *envoy_config_route.HeaderMatcher, req *httpRequest) (matches, judged bool) {
	name := strings.ToLower(hm.GetName())
	if req.redacted[name] {
		return false, false
	}
	values, present := req.headers[name]
	treatMissing := hm.GetTreatMissingHeaderAsEmpty()
	invert := hm.GetInvertMatch()
	switch spec := hm.GetHeaderMatchSpecifier().(type) {
	case *envoy_config_route.HeaderMatcher_PresentMatch:
		if !present && !treatMissing {
			return invert == spec.PresentMatch, true
		}
		return spec.PresentMatch != invert, true
	case *envoy_config_route.HeaderMatcher_StringMatch:
		if !present && !treatMissing {
			return false, true
		}
		m, ok := envoyStringMatches(spec.StringMatch, strings.Join(values, ","))
		return m != invert, ok
	default:
		return false, false
	}
}

func envoyStringMatches(sm *envoy_type_matcher.StringMatcher, value string) (matches, judged bool) {
	if sm.GetIgnoreCase() {
		value = strings.ToLower(value)
	}
	lower := func(s string) string {
		if sm.GetIgnoreCase() {
			return strings.ToLower(s)
		}
		return s
	}
	switch p := sm.GetMatchPattern().(type) {
	case *envoy_type_matcher.StringMatcher_Exact:
		return value == lower(p.Exact), true
	case *envoy_type_matcher.StringMatcher_Prefix:
		return strings.HasPrefix(value, lower(p.Prefix)), true
	case *envoy_type_matcher.StringMatcher_Suffix:
		return strings.HasSuffix(value, lower(p.Suffix)), true
	case *envoy_type_matcher.StringMatcher_Contains:
		return strings.Contains(value, lower(p.Contains)), true
	case *envoy_type_matcher.StringMatcher_SafeRegex:
		re, err := fullMatchRegex(p.SafeRegex.GetRegex())
		if err != nil {
			return false, false
		}
		return re.MatchString(value), true
	default:
		return false, false
	}
}

// ciliumHeaderMatch is cilium/proxy's HeaderMatch::allowed, minus its
// rewrites: only FAIL actions can reject a request.
func ciliumHeaderMatch(hm *cilium.HeaderMatch, req *httpRequest) (matches, judged bool) {
	name := strings.ToLower(hm.GetName())
	if hm.GetValueSdsSecret() != "" || req.redacted[name] {
		return false, false // the value to compare against isn't visible here
	}
	values, present := req.headers[name]
	var m bool
	if hm.GetValue() == "" {
		m = present
	} else {
		m = present && strings.Join(values, ",") == hm.GetValue()
	}
	if m {
		return hm.GetMatchAction() != cilium.HeaderMatch_FAIL_ON_MATCH, true
	}
	return hm.GetMismatchAction() != cilium.HeaderMatch_FAIL_ON_MISMATCH, true
}

var httpRegexes sync.Map // regex -> *regexp.Regexp

// fullMatchRegex compiles an Envoy safe_regex (RE2, whole-value match).
func fullMatchRegex(expr string) (*regexp.Regexp, error) {
	if re, ok := httpRegexes.Load(expr); ok {
		return re.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(`^(?:` + expr + `)$`)
	if err != nil {
		return nil, err
	}
	httpRegexes.Store(expr, re)
	return re, nil
}

// newHTTPGate returns the reason HTTP requests can't be judged on this
// cluster, "" when they can, checked once and only when first needed.
// Hubble's hubble-redact-http-urlquery drops the query from recorded URLs
// without a trace in the flow, and Cilium's path rules match the query
// too, so with it on (or unknowable) a path verdict would be a guess.
func newHTTPGate(core kubernetes.Interface) func() string {
	return sync.OnceValue(func() string {
		if core == nil {
			return ""
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cm, err := core.CoreV1().ConfigMaps(hubbleNamespace).Get(ctx, "cilium-config", metav1.GetOptions{})
		if err != nil {
			return fmt.Sprintf("can't read %s/cilium-config to check whether Hubble redacts URL queries (%v)", hubbleNamespace, err)
		}
		if cm.Data["hubble-redact-enabled"] == "true" && cm.Data["hubble-redact-http-urlquery"] == "true" {
			return "Hubble redacts URL queries on this cluster (hubble-redact-http-urlquery), and Cilium's path rules match the query"
		}
		return ""
	})
}
