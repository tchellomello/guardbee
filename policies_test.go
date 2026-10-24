package main

import (
	"testing"

	"github.com/cilium/cilium/pkg/policy/api"
)

// A policy with neither Spec nor Specs set (shouldn't happen for a real
// applied CNP, but the CRD schema makes both optional) summarizes to zero
// rules rather than panicking on a nil Spec.
func TestSummarizeRuleSpecsEmpty(t *testing.T) {
	desc, ingress, egress := summarizeRuleSpecs(nil, nil)
	if desc != "" || ingress != 0 || egress != 0 {
		t.Fatalf("got (%q, %d, %d), want (\"\", 0, 0)", desc, ingress, egress)
	}
}

func TestSummarizeRuleSpecsSingleSpec(t *testing.T) {
	spec := &api.Rule{
		Description: "deny all ingress",
		IngressDeny: []api.IngressDenyRule{{}},
	}
	desc, ingress, egress := summarizeRuleSpecs(spec, nil)
	if desc != "deny all ingress" {
		t.Errorf("description = %q, want %q", desc, "deny all ingress")
	}
	if ingress != 1 {
		t.Errorf("ingressCount = %d, want 1 (one IngressDeny rule)", ingress)
	}
	if egress != 0 {
		t.Errorf("egressCount = %d, want 0", egress)
	}
}

// A CCNP (or CNP) can set Specs (plural) instead of, or alongside, Spec —
// counts must sum across every entry, and descriptions join rather than
// overwrite each other.
func TestSummarizeRuleSpecsMultipleSpecs(t *testing.T) {
	spec := &api.Rule{
		Description: "allow web ingress",
		Ingress:     []api.IngressRule{{}},
	}
	specs := api.Rules{
		{Description: "allow dns egress", Egress: []api.EgressRule{{}}},
		{IngressDeny: []api.IngressDenyRule{{}}, EgressDeny: []api.EgressDenyRule{{}}}, // no description
	}

	desc, ingress, egress := summarizeRuleSpecs(spec, specs)

	wantDesc := "allow web ingress; allow dns egress"
	if desc != wantDesc {
		t.Errorf("description = %q, want %q", desc, wantDesc)
	}
	// ingress: 1 (spec.Ingress) + 1 (specs[1].IngressDeny) = 2
	if ingress != 2 {
		t.Errorf("ingressCount = %d, want 2", ingress)
	}
	// egress: 1 (specs[0].Egress) + 1 (specs[1].EgressDeny) = 2
	if egress != 2 {
		t.Errorf("egressCount = %d, want 2", egress)
	}
}
