package main

import (
	"regexp"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/fqdn/dns"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"google.golang.org/protobuf/proto"
)

// A toFQDNs rule selects nothing by itself: Cilium's name manager watches DNS
// answers and adds an fqdn:<selector> label to the identity of every IP whose
// name matches a selector in a LIVE policy. Hubble reports a destination's
// labels as of now, so a candidate's new selector has no label yet and its
// rule matched nothing (a false NEWLY_DROPPED). This labels the engine's copy
// of the destination the way the name manager would once the candidate is
// applied, from the names Hubble attaches to the flow (destination_names).
//
// The matching is Cilium's own: FQDNSelector.ToRegex() and IdentityLabel(),
// looped exactly like namemanager's unexported deriveLabelsForName.
// destination_names come from the SOURCE endpoint's DNS history, while the
// name manager labels an IP by any endpoint's lookups; for an egress rule of
// that same source the two agree, since its connection follows its own lookup.

type fqdnSelector struct {
	label string
	re    *regexp.Regexp
}

// fqdnSelectorsOf compiles every toFQDNs selector in rules. EgressDeny has no
// toFQDNs, so egress rules are the only place one can appear. A selector that
// doesn't compile can't have passed Parse(), so it is simply skipped.
func fqdnSelectorsOf(rules api.Rules) []fqdnSelector {
	var out []fqdnSelector
	for _, r := range rules {
		for _, eg := range r.Egress {
			for _, sel := range eg.ToFQDNs {
				re, err := sel.ToRegex()
				if err != nil {
					continue
				}
				l := sel.IdentityLabel()
				out = append(out, fqdnSelector{label: l.String(), re: re})
			}
		}
	}
	return out
}

// fqdnCandidate reports whether toFQDNs could ever select this destination:
// Cilium only puts fqdn: labels on world/CIDR identities, never on a pod's.
func fqdnCandidate(ep *flowpb.Endpoint) bool {
	nid := identity.NumericIdentity(ep.GetIdentity())
	switch nid {
	case identity.ReservedIdentityWorld, identity.ReservedIdentityWorldIPv4, identity.ReservedIdentityWorldIPv6:
		return true
	}
	return nid.HasLocalScope()
}

// fqdnDisplayNames is names for a destination toFQDNs could select, nil for
// any other: a pod's names (its Service's DNS name) add nothing to its row.
func fqdnDisplayNames(dst *flowpb.Endpoint, names []string) []string {
	if !fqdnCandidate(dst) || len(names) == 0 {
		return nil
	}
	return names
}

// withFQDNLabels returns dst with the fqdn: label of every selector matching
// one of names, or dst itself when nothing is added. A labelled reserved
// world identity becomes a local-scope one, as Cilium allocates a CIDR
// identity for a selected IP; engineNID then gives each label set its own
// number, so two names behind reserved:world never share one identity.
func withFQDNLabels(dst *flowpb.Endpoint, names []string, sels []fqdnSelector) *flowpb.Endpoint {
	if len(names) == 0 || len(sels) == 0 || !fqdnCandidate(dst) {
		return dst
	}
	lbls := labels.NewLabelsFromModel(dst.GetLabels())
	added := false
	for _, name := range names {
		// Hubble trims the trailing dot the DNS cache keeps; the regexes
		// expect Cilium's lowercase FQDN form.
		fqdn := dns.FQDN(strings.ToLower(name))
		for _, s := range sels {
			if !s.re.MatchString(fqdn) {
				continue
			}
			l := labels.ParseLabel(s.label)
			if _, ok := lbls[l.Key]; !ok {
				lbls[l.Key] = l
				added = true
			}
		}
	}
	if !added {
		return dst
	}
	nid := identity.NumericIdentity(dst.GetIdentity())
	if !nid.HasLocalScope() {
		nid = identity.IdentityScopeLocal
	}
	// A copy for the engine only; the row keeps Hubble's endpoint.
	out := proto.Clone(dst).(*flowpb.Endpoint)
	out.Identity = uint32(nid)
	out.Labels = lbls.GetModel()
	return out
}
