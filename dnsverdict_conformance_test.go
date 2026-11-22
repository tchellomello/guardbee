//go:build linux

package main

// Pins dnsverdict.go's port of dnsproxy.GeneratePattern / CheckAllowed to the
// real thing at the pinned Cilium version. Linux only: dnsproxy pulls in
// Linux-only datapath code, which is exactly why the port exists. CI runs on
// Linux, so a Cilium bump that changes the DNS proxy's matching fails here.

import (
	"log/slog"
	"net/netip"
	"testing"

	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestDNSPortMatchesCiliumDNSProxy(t *testing.T) {
	ruleSets := map[string][]api.Rule{}
	egressTo := func(peer string, dns ...api.PortRuleDNS) api.EgressRule {
		return api.EgressRule{
			EgressCommonRule: api.EgressCommonRule{
				ToEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.ParseSelectLabel(peer))},
			},
			ToPorts: api.PortRules{{
				Ports: []api.PortProtocol{{Port: "53", Protocol: api.ProtoUDP}},
				Rules: &api.L7Rules{DNS: dns},
			}},
		}
	}
	for name, eg := range map[string][]api.EgressRule{
		"match all":         {egressTo("role=backend", api.PortRuleDNS{MatchPattern: "*"})},
		"one label":         {egressTo("role=backend", api.PortRuleDNS{MatchPattern: "*.example.com"})},
		"multi label":       {egressTo("role=backend", api.PortRuleDNS{MatchPattern: "**.cluster.local"})},
		"name, mixed case":  {egressTo("role=backend", api.PortRuleDNS{MatchName: "API.GitHub.com"})},
		"infix wildcard":    {egressTo("role=backend", api.PortRuleDNS{MatchPattern: "foo*bar.com"})},
		"names and pattern": {egressTo("role=backend", api.PortRuleDNS{MatchName: "a.io"}, api.PortRuleDNS{MatchPattern: "*.b.io"})},
		"two servers": {
			egressTo("role=backend", api.PortRuleDNS{MatchName: "only-backend.io"}),
			egressTo("role=other", api.PortRuleDNS{MatchPattern: "*"}),
		},
	} {
		ruleSets[name] = []api.Rule{{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("role=frontend")),
			Egress:           eg,
		}}
	}
	queries := []string{
		"example.com.", "www.example.com", "a.b.example.com.", "WWW.EXAMPLE.COM.",
		"postgres.postgres.svc.cluster.local.", "cluster.local.", "api.github.com",
		"foobar.com.", "fooxyzbar.com.", "foo.bar.com.", "a.io.", "x.b.io.", "b.io.",
		"only-backend.io.", "other.io.", ".",
	}
	servers := []identity.NumericIdentity{l7BackendNID, l7OtherNID, l7FrontendNID}
	portProto := restore.MakeV2PortProto(53, u8proto.UDP)

	for name, rules := range ruleSets {
		t.Run(name, func(t *testing.T) {
			var rs api.Rules
			for i := range rules {
				r := rules[i]
				if err := r.Sanitize(); err != nil {
					t.Fatalf("Sanitize: %v", err)
				}
				rs = append(rs, &r)
			}
			engine, err := newVerdictEngine(slog.Default(), rs, l7Identities)
			if err != nil {
				t.Fatal(err)
			}
			defer engine.close(slog.Default())
			epp, err := engine.distillFor(slog.Default(), l7FrontendNID)
			if err != nil {
				t.Fatal(err)
			}
			var data policy.L7DataMap
			for f := range epp.SelectorPolicy.L4Policy.Egress.Filters() {
				if f.Port == 53 {
					data = f.GetPerSelectorPolicies()
				}
			}
			if data == nil {
				t.Fatal("no port-53 egress filter")
			}

			for _, psp := range data {
				if got, want := dnsGeneratePattern(psp), dnsproxy.GeneratePattern(psp); got != want {
					t.Errorf("GeneratePattern: port %q, Cilium %q", got, want)
				}
			}

			proxy := dnsproxy.NewDNSProxy(dnsproxy.DNSProxyConfig{Logger: slog.Default()}, nil, nil)
			if _, err := proxy.UpdateAllowed(1, portProto, data); err != nil {
				t.Fatalf("UpdateAllowed: %v", err)
			}
			for _, server := range servers {
				for _, q := range queries {
					want, err := proxy.CheckAllowed(1, portProto, server, netip.Addr{}, q)
					if err != nil {
						t.Fatalf("CheckAllowed: %v", err)
					}
					if got := dnsCheckAllowed(data, server, q); got != want {
						t.Errorf("server %d, query %q: port %v, Cilium %v", server, q, got, want)
					}
				}
			}
		})
	}
}
