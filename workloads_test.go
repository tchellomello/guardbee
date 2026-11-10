package main

import (
	"log/slog"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The pasted production CCNP selects by a namespace label plus a NotIn on the
// service account — neither is a pod label, so this only passes if the
// synthetic identity carries Cilium's derived labels.
const apiserverEgressCCNP = `apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: deny-pods-to-kube-apiserver
spec:
  enableDefaultDeny:
    egress: false
    ingress: false
  endpointSelector:
    matchExpressions:
      - key: io.cilium.k8s.namespace.labels.traffic.celonis.cloud/apiserver-egress
        operator: In
        values: ["restricted"]
      - key: io.cilium.k8s.policy.serviceaccount
        operator: NotIn
        values: ["test"]
  egressDeny:
    - toEntities:
      - kube-apiserver
`

func TestMatchWorkloadsNamespaceLabelAndServiceAccount(t *testing.T) {
	logger := slog.Default()
	rules, err := parseCandidateYAML(logger, []byte(apiserverEgressCCNP), "")
	if err != nil {
		t.Fatal(err)
	}
	pod := func(ns, name, sa string, hostNet bool) corev1.Pod {
		return corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       corev1.PodSpec{ServiceAccountName: sa, HostNetwork: hostNet},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning},
		}
	}
	nsLabels := map[string]map[string]string{
		"restricted-ns": {"traffic.celonis.cloud/apiserver-egress": "restricted"},
		"open-ns":       {},
	}
	got, err := matchWorkloads(logger, rules, []corev1.Pod{
		pod("restricted-ns", "app", "app-sa", false),
		pod("restricted-ns", "allowlisted", "test", false),
		pod("restricted-ns", "hostnet", "app-sa", true),
		pod("open-ns", "other", "app-sa", false),
	}, nsLabels)
	if err != nil {
		t.Fatal(err)
	}
	sel := map[string]workloadMatch{}
	for _, m := range got {
		sel[m.Namespace+"/"+m.Name] = m
	}
	if len(sel) != 3 {
		t.Fatalf("hostNetwork pod should be skipped, got %d results", len(sel))
	}
	if m := sel["restricted-ns/app"]; !m.Selected || !m.Egress {
		t.Errorf("restricted-ns/app should be selected with egress policy, got %+v", m)
	}
	if sel["restricted-ns/allowlisted"].Selected {
		t.Error("service account 'test' is excluded by NotIn and must not be selected")
	}
	if sel["open-ns/other"].Selected {
		t.Error("namespace without the label must not be selected")
	}
}

// The egress half of the same pasted CCNP: verdict used to judge only
// ingress-at-destination, so a flow to the kube-apiserver always read
// UNCHANGED. Now the source's egress policy must also allow the flow.
func TestJudgeFlowEgressDenyToKubeAPIServer(t *testing.T) {
	logger := slog.Default()
	const (
		podNID    identity.NumericIdentity = 3000
		otherNID  identity.NumericIdentity = 3001
		apiserver                          = identity.ReservedIdentityKubeAPIServer
	)
	ids := identity.IdentityMap{
		podNID: labels.ParseLabelArray(
			"k8s:io.kubernetes.pod.namespace=testing",
			"k8s:io.cilium.k8s.policy.serviceaccount=default",
			"k8s:io.cilium.k8s.namespace.labels.traffic.celonis.cloud/apiserver-egress=restricted",
		),
		otherNID: labels.ParseLabelArray(
			"k8s:io.kubernetes.pod.namespace=open",
			"k8s:io.cilium.k8s.policy.serviceaccount=default",
		),
		apiserver: labels.ParseLabelArray("reserved:kube-apiserver"),
	}
	rules, err := parseCandidateYAML(logger, []byte(apiserverEgressCCNP), "")
	if err != nil {
		t.Fatal(err)
	}
	baseline, _ := newVerdictEngine(logger, nil, ids)
	defer baseline.close(logger)
	candidate, _ := newVerdictEngine(logger, rules, ids)
	defer candidate.close(logger)

	flow := func(src identity.NumericIdentity) *flowpb.Flow {
		return &flowpb.Flow{
			Source:      &flowpb.Endpoint{Identity: uint32(src)},
			Destination: &flowpb.Endpoint{Identity: uint32(apiserver)},
			L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
		}
	}
	counts := &verdictCounts{}
	row := judgeFlow(logger, baseline, candidate, flow(podNID), counts, false)
	if row == nil || row.change != "NEWLY_DROPPED" {
		t.Fatalf("restricted pod -> kube-apiserver:443 should be NEWLY_DROPPED, got %+v", row)
	}
	if row := judgeFlow(logger, baseline, candidate, flow(otherNID), counts, true); row == nil || row.change != "UNCHANGED" {
		t.Fatalf("pod outside the selector must stay UNCHANGED, got %+v", row)
	}
}

// Local-scope identity numbers are allocated per node, so the same number
// can be the kube-apiserver on one node and a plain CIDR on another. Keying
// the engine by that number made the first-seen labels win cluster-wide.
func TestJudgeFlowSameLocalNumberDifferentLabelsAcrossNodes(t *testing.T) {
	logger := slog.Default()
	const podNID identity.NumericIdentity = 3000
	const shared uint32 = 16777219 // local scope, reused by different nodes

	pod := &flowpb.Endpoint{Identity: uint32(podNID), Labels: []string{
		"k8s:io.kubernetes.pod.namespace=testing",
		"k8s:io.cilium.k8s.policy.serviceaccount=default",
		"k8s:io.cilium.k8s.namespace.labels.traffic.celonis.cloud/apiserver-egress=restricted",
	}}
	ids := identity.IdentityMap{}
	ids[engineNID(pod)] = labels.ParseLabelArray(pod.Labels...)
	rules, err := parseCandidateYAML(logger, []byte(apiserverEgressCCNP), "")
	if err != nil {
		t.Fatal(err)
	}
	baseline, _ := newVerdictEngine(logger, nil, ids)
	defer baseline.close(logger)
	candidate, _ := newVerdictEngine(logger, rules, ids)
	defer candidate.close(logger)

	to := func(lbls ...string) *flowpb.Flow {
		return &flowpb.Flow{
			Source:      pod,
			Destination: &flowpb.Endpoint{Identity: shared, Labels: lbls},
			L4:          &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}},
		}
	}
	counts := &verdictCounts{}
	// Another node's meaning of the number is seen FIRST — it must not
	// poison the later flow that really is the kube-apiserver.
	if row := judgeFlow(logger, baseline, candidate, to("cidr:172.16.0.0/12", "reserved:world"), counts, true); row == nil || row.change != "UNCHANGED" {
		t.Fatalf("plain CIDR destination must be UNCHANGED, got %+v", row)
	}
	if row := judgeFlow(logger, baseline, candidate, to("reserved:kube-apiserver", "reserved:world"), counts, true); row == nil || row.change != "NEWLY_DROPPED" {
		t.Fatalf("kube-apiserver destination reusing the same number must be NEWLY_DROPPED, got %+v", row)
	}
}
