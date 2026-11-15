package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var policyVerdictEvent = &flowpb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict}

// Policies the way Cilium's correlation fills them in
// (k8s/apis/cilium.io/utils.GetPolicyFromLabels): Kind is the
// derived-from label verbatim, labels carry the k8s: prefix.
func cnp(ns, name string) *flowpb.Policy {
	return &flowpb.Policy{Kind: "CiliumNetworkPolicy", Namespace: ns, Name: name, Revision: 7,
		Labels: []string{"k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy", "k8s:io.cilium.k8s.policy.name=" + name, "k8s:io.cilium.k8s.policy.namespace=" + ns}}
}

func TestFlowAttribution(t *testing.T) {
	cases := []struct {
		name         string
		flow         *flowpb.Flow
		decision     string
		decidedBy    string
		allow, denyN int
	}{
		{
			name:      "ingress allowed by a CNP",
			flow:      &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED, TrafficDirection: flowpb.TrafficDirection_INGRESS, EventType: policyVerdictEvent, IngressAllowedBy: []*flowpb.Policy{cnp("app", "allow-web")}},
			decision:  decisionAllowed,
			decidedBy: "allowed by CNP:app/allow-web",
			allow:     1,
		},
		{
			name: "egress allowed by two policies",
			flow: &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED, TrafficDirection: flowpb.TrafficDirection_EGRESS, EventType: policyVerdictEvent,
				EgressAllowedBy: []*flowpb.Policy{cnp("app", "a"), {Kind: "CiliumClusterwideNetworkPolicy", Name: "dns"}}},
			decision:  decisionAllowed,
			decidedBy: "allowed by CNP:app/a, CCNP:dns",
			allow:     2,
		},
		{
			name:      "explicit deny, attributed",
			flow:      &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED, DropReasonDesc: flowpb.DropReason_POLICY_DENY, EventType: policyVerdictEvent, EgressDeniedBy: []*flowpb.Policy{{Kind: "CiliumClusterwideNetworkPolicy", Name: "block-metadata"}}},
			decision:  decisionDenied,
			decidedBy: "denied by CCNP:block-metadata",
			denyN:     1,
		},
		// The PR #20 bug: an unattributed POLICY_DENY is a deny rule that
		// matched, not default deny — "add an allow rule" would be wrong advice.
		{
			name:      "explicit deny, not attributed",
			flow:      &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED, DropReasonDesc: flowpb.DropReason_POLICY_DENY, EventType: policyVerdictEvent},
			decision:  decisionDenied,
			decidedBy: "denied by a deny rule, not attributed by Hubble",
		},
		{
			name:      "default deny",
			flow:      &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED, DropReasonDesc: flowpb.DropReason_POLICY_DENIED, EventType: policyVerdictEvent},
			decision:  decisionDefaultDeny,
			decidedBy: "default deny: no policy rule allows it",
		},
		// No attribution on an allow proves nothing (correlation can fail),
		// so it must not claim "no policy selects the endpoint".
		{
			name:      "allowed, not attributed",
			flow:      &flowpb.Flow{Verdict: flowpb.Verdict_FORWARDED, EventType: policyVerdictEvent},
			decision:  decisionAllowed,
			decidedBy: "allowed, no policy attributed by Hubble",
		},
		{
			name:      "redirected counts as allowed",
			flow:      &flowpb.Flow{Verdict: flowpb.Verdict_REDIRECTED, EventType: policyVerdictEvent, IngressAllowedBy: []*flowpb.Policy{cnp("app", "l7")}},
			decision:  decisionAllowed,
			decidedBy: "allowed by CNP:app/l7",
			allow:     1,
		},
		// AUDIT was let through; it must not read as a drop.
		{
			name:      "audit, attributed",
			flow:      &flowpb.Flow{Verdict: flowpb.Verdict_AUDIT, EventType: policyVerdictEvent, IngressDeniedBy: []*flowpb.Policy{cnp("app", "lockdown")}},
			decision:  decisionAudit,
			decidedBy: "audit: would be denied by CNP:app/lockdown",
			denyN:     1,
		},
		{
			name:      "audit, not attributed",
			flow:      &flowpb.Flow{Verdict: flowpb.Verdict_AUDIT, EventType: policyVerdictEvent},
			decision:  decisionAudit,
			decidedBy: "audit: would be denied, no policy attributed by Hubble",
		},
		// Not a policy decision, and not a policy-verdict event: no answer.
		{
			name: "non-policy drop",
			flow: &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED, DropReasonDesc: flowpb.DropReason_CT_NO_MAP_FOUND, EventType: policyVerdictEvent},
		},
		{
			name: "trace event is never attributed",
			flow: &flowpb.Flow{Verdict: flowpb.Verdict_DROPPED, DropReasonDesc: flowpb.DropReason_POLICY_DENIED, EventType: &flowpb.CiliumEventType{Type: monitorAPI.MessageTypeDrop}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := flowAttribution(tc.flow)
			if a.Decision != tc.decision || a.DecidedBy != tc.decidedBy || len(a.AllowedBy) != tc.allow || len(a.DeniedBy) != tc.denyN {
				t.Fatalf("got %+v, want decision=%q decidedBy=%q allowedBy=%d deniedBy=%d", a, tc.decision, tc.decidedBy, tc.allow, tc.denyN)
			}
		})
	}
}

// Kind is shown as Cilium reported it: the CNP/CCNP abbreviations for the
// two Cilium kinds, anything else spelled out, and nothing invented when it's
// missing. A rule with no name label falls back to its labels.
func TestPolicyRefString(t *testing.T) {
	cases := map[string]policyRef{
		"CNP:app/web":                           {Kind: "CiliumNetworkPolicy", Namespace: "app", Name: "web"},
		"CCNP:dns":                              {Kind: "CiliumClusterwideNetworkPolicy", Name: "dns"},
		"NetworkPolicy:app/legacy":              {Kind: "NetworkPolicy", Namespace: "app", Name: "legacy"},
		"app/no-kind":                           {Namespace: "app", Name: "no-kind"},
		"rule{k8s:custom=1,reserved:something}": {Labels: []string{"k8s:custom=1", "reserved:something"}},
	}
	for want, ref := range cases {
		if got := ref.String(); got != want {
			t.Errorf("%+v: got %q, want %q", ref, got, want)
		}
	}
	if refs := toPolicyRefs([]*flowpb.Policy{nil, {}, {Name: "x"}}); len(refs) != 1 || refs[0].Name != "x" {
		t.Errorf("empty entries should be dropped, got %+v", refs)
	}
}

func TestBlameScope(t *testing.T) {
	ns, f, err := blameScope([]string{"app/web"}, "", false, flowFilter{})
	if err != nil || ns != "app" || len(f.pods) != 1 || f.pods[0] != "app/web" || f.types[0] != "policy-verdict" {
		t.Fatalf("positional ns/pod: ns=%q f=%+v err=%v", ns, f, err)
	}
	// -A keeps the run cluster-wide; an explicit -n wins over the positional's namespace.
	if ns, _, _ := blameScope([]string{"app/web"}, "", true, flowFilter{}); ns != "" {
		t.Errorf("-A: got namespace %q", ns)
	}
	if ns, _, _ := blameScope([]string{"app/web"}, "other", false, flowFilter{}); ns != "other" {
		t.Errorf("-n other: got namespace %q", ns)
	}
	// An explicit --type replaces the policy-verdict default.
	if _, f, _ := blameScope(nil, "app", false, flowFilter{types: []string{"drop"}}); len(f.types) != 1 || f.types[0] != "drop" {
		t.Errorf("--type drop: got %v", f.types)
	}
	if _, _, err := blameScope([]string{"a", "b"}, "", false, flowFilter{}); err == nil {
		t.Error("two positionals: want an error")
	}
}

func TestBlameOutput(t *testing.T) {
	f := &flowpb.Flow{
		Time:             timestamppb.New(time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)),
		Verdict:          flowpb.Verdict_DROPPED,
		DropReasonDesc:   flowpb.DropReason_POLICY_DENY,
		TrafficDirection: flowpb.TrafficDirection_EGRESS,
		EventType:        policyVerdictEvent,
		Source:           &flowpb.Endpoint{Namespace: "app", PodName: "netshoot"},
		Destination:      &flowpb.Endpoint{Labels: []string{"reserved:world"}},
		L4:               &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
		EgressDeniedBy:   []*flowpb.Policy{cnp("app", "deny-world")},
	}
	row := toFlowOut(f)
	if row.Direction != "EGRESS" || row.DropReason != "POLICY_DENY" || row.Decision != decisionDenied {
		t.Fatalf("row: %+v", row)
	}
	if line := blameLine(row); !strings.Contains(line, "EGRESS") || !strings.Contains(line, "denied by CNP:app/deny-world") {
		t.Errorf("line: %q", line)
	}

	var buf bytes.Buffer
	writeBlameMarkdown(&buf, "app", flowFilter{pods: []string{"app/netshoot"}}, []flowOut{row})
	out := buf.String()
	for _, want := range []string{"`--pod app/netshoot`", "| EGRESS |", "denied by CNP:app/deny-world | POLICY_DENY |"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}
	buf.Reset()
	writeBlameMarkdown(&buf, "", flowFilter{}, nil)
	if !strings.Contains(buf.String(), "No matching flows") {
		t.Errorf("empty markdown: %s", buf.String())
	}
}
