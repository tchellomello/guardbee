package main

import (
	"log/slog"
	"testing"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/policy/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A live CNP using fromNodes must be skipped and named, not fail the whole
// baseline — and must not take the other policies down with it.
func TestFetchBaselineRulesSkipsFromNodes(t *testing.T) {
	good := &cilium_v2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "good", Namespace: "eu-3"},
		Spec: &api.Rule{
			EndpointSelector: api.NewESFromLabels(),
			Ingress:          []api.IngressRule{{}},
		},
	}
	nodes := &cilium_v2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allowlist-gateway-internal", Namespace: "eu-3"},
		Spec: &api.Rule{
			EndpointSelector: api.NewESFromLabels(),
			Ingress: []api.IngressRule{{IngressCommonRule: api.IngressCommonRule{
				FromNodes: []api.EndpointSelector{api.NewESFromLabels()},
			}}},
		},
	}
	cs := fake.NewSimpleClientset(good, nodes)

	rules, skipped, err := fetchBaselineRules(slog.Default(), cs, "eu-3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("want 1 loadable rule, got %d", len(rules))
	}
	if len(skipped) != 1 || skipped[0] != "CiliumNetworkPolicy eu-3/allowlist-gateway-internal" {
		t.Errorf("unexpected skipped list: %v", skipped)
	}
}
