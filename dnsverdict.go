package main

// DNS request verdicts: whether Cilium's DNS proxy would let a query Hubble
// recorded through, under baseline and under candidate policy.
//
// Cilium's own pkg/fqdn/dnsproxy can't be imported: it pulls in Linux-only
// datapath code (pkg/datapath/linux/bandwidth) that breaks the darwin
// release builds. So the substantive semantics come from Cilium's portable
// pkg/fqdn/matchpattern (matchName/matchPattern → regex), and only the glue
// that dnsproxy wraps around it is ported here, unchanged: GeneratePattern
// (joining one selector's rules into one anchored regex) and CheckAllowed's
// loop (any selector that selects the DNS server and whose regex matches the
// lowercased FQDN allows the query). dnsverdict_conformance_test.go (Linux
// only) runs both ports against the real dnsproxy at the pinned version, so
// a Cilium bump that changes either fails CI instead of drifting silently.

import (
	"regexp"
	"strings"
	"sync"

	"github.com/cilium/dns"

	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
)

// dnsQueryVerdict answers, for a query from the endpoint epp was distilled
// for to the DNS server identity server on key's port/protocol, whether the
// DNS proxy would allow it. judged is false when the answer can't be read
// off the policy unambiguously; allowed is then meaningless.
//
// A flow whose egress entry isn't a proxy redirect never reaches the DNS
// proxy, so its query is allowed by definition (judged, allowed). Whether
// the connection itself is allowed at L4 is the caller's isEgressAllowed.
func dnsQueryVerdict(epp *policy.EndpointPolicy, key policy.Key, server identity.NumericIdentity, qname string) (allowed, judged bool) {
	entry, _, found := epp.Lookup(key)
	if !found || !entry.IsAllow() || !entry.IsRedirectEntry() {
		return true, true
	}
	// The agent opens one redirect per L4Filter and loads that filter's
	// PerSelectorPolicies into the proxy (pkg/proxy: UpdateRules(
	// l4.GetPerSelectorPolicies())). Find the one for this exact port.
	var filter *policy.L4Filter
	for f := range epp.SelectorPolicy.L4Policy.Egress.Filters() {
		if f.U8Proto != key.Nexthdr || f.Port != key.DestPort || f.EndPort != 0 {
			continue
		}
		if filter != nil {
			// shortcut: several tiers each holding a port filter; which one
			// the datapath redirects to isn't modelled. Upgrade if seen live.
			return false, false
		}
		filter = f
	}
	if filter == nil || !isDNSFilter(filter) {
		// Redirected through a port range, or to Envoy rather than the DNS
		// proxy: a DNS record we can't tie to the DNS proxy's rules.
		return false, false
	}
	return dnsCheckAllowed(filter.GetPerSelectorPolicies(), server, qname), true
}

func isDNSFilter(f *policy.L4Filter) bool {
	for _, psp := range f.PerSelectorPolicies {
		if psp != nil && psp.GetL7Parser() == policy.ParserTypeDNS {
			return true
		}
	}
	return false
}

// dnsCheckAllowed is the matching loop of dnsproxy.CheckAllowed, ported
// unchanged (see the file comment).
func dnsCheckAllowed(rules policy.L7DataMap, server identity.NumericIdentity, qname string) bool {
	// Compile every selector's pattern first: in dnsproxy one bad pattern
	// fails UpdateAllowed for the whole port, so no rule is loaded and the
	// query is refused.
	regexes := make(map[policy.CachedSelector]*regexp.Regexp, len(rules))
	for selector, psp := range rules {
		re, err := dnsRegex(dnsGeneratePattern(psp))
		if err != nil {
			return false
		}
		regexes[selector] = re
	}
	name := strings.ToLower(dns.Fqdn(qname))
	for selector, re := range regexes {
		if selector.Selects(server) && (re.String() == matchpattern.MatchAllAnchoredPattern || re.MatchString(name)) {
			return true
		}
	}
	return false
}

// dnsGeneratePattern is dnsproxy.GeneratePattern, ported unchanged.
func dnsGeneratePattern(l7Rules *policy.PerSelectorPolicy) string {
	if l7Rules == nil || len(l7Rules.DNS) == 0 {
		return matchpattern.MatchAllAnchoredPattern
	}
	reStrings := make([]string, 0, len(l7Rules.DNS))
	for _, dnsRule := range l7Rules.DNS {
		if len(dnsRule.MatchName) > 0 {
			dnsRuleName := strings.ToLower(dns.Fqdn(dnsRule.MatchName))
			reStrings = append(reStrings, matchpattern.ToUnAnchoredRegexp(dnsRuleName))
		}
		if len(dnsRule.MatchPattern) > 0 {
			dnsPattern := matchpattern.Sanitize(dnsRule.MatchPattern)
			dnsPatternAsRE := matchpattern.ToUnAnchoredRegexp(dnsPattern)
			if dnsPatternAsRE == matchpattern.MatchAllUnAnchoredPattern {
				return matchpattern.MatchAllAnchoredPattern
			}
			reStrings = append(reStrings, dnsPatternAsRE)
		}
	}
	return "^(?:" + strings.Join(reStrings, "|") + ")$"
}

// dnsRegexes caches compiled patterns: the same few rule sets are matched
// against every DNS record in a sample.
var dnsRegexes sync.Map // pattern -> *regexp.Regexp

func dnsRegex(pattern string) (*regexp.Regexp, error) {
	if re, ok := dnsRegexes.Load(pattern); ok {
		return re.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	dnsRegexes.Store(pattern, re)
	return re, nil
}
