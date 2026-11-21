package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumfake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/policy/api"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestProbeServiceRef(t *testing.T) {
	for host, want := range map[string][2]string{
		"db":                            {"db", "app"},
		"db.database":                   {"db", "database"},
		"DB.database.svc.":              {"db", "database"},
		"db.database.svc.cluster.local": {"db", "database"},
		"db.database.svc.corp.internal": {"db", "database"},
	} {
		name, ns, ok := probeServiceRef(host, "app")
		if !ok || name != want[0] || ns != want[1] {
			t.Errorf("%s: got %s/%s %v, want %s/%s", host, ns, name, ok, want[1], want[0])
		}
	}
	if _, _, ok := probeServiceRef("api.example.com", "app"); ok {
		t.Error("external three-label name treated as a Service")
	}
}

// Real-cluster regression: with socket-level load balancing Hubble reports
// the backend Pod IP and target port, with no destination names and no
// destination Service, so a Service-name probe had zero correlated flows.
func TestProbeServiceHostCorrelatesBackendsAndTargetPort(t *testing.T) {
	s, core := testProbeServer(t)
	_, err := core.CoreV1().Services("database").Create(context.Background(), &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "database"},
		Spec: corev1.ServiceSpec{ClusterIPs: []string{"10.96.0.10"}, Ports: []corev1.ServicePort{
			{Name: "pg", Port: 443, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromString("postgres")},
		}},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	name, port := "pg", int32(5432)
	_, err = core.DiscoveryV1().EndpointSlices("database").Create(context.Background(), &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "db-abc", Namespace: "database", Labels: map[string]string{discoveryv1.LabelServiceName: "db"}},
		Ports:      []discoveryv1.EndpointPort{{Name: &name, Port: &port}},
		Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"10.244.1.7"}}},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	req := testProbeReq()
	req.Host = "db.database.svc.cluster.local"
	svc, note := s.resolveProbeService(context.Background(), req)
	if svc == nil || note != "" || !svc.ports[443] || !svc.ports[5432] || len(svc.addrs) != 2 {
		t.Fatalf("service not resolved: %+v %q", svc, note)
	}
	req.service = svc

	now := time.Now()
	backend := testProbeFlow(now)
	backend.IP.Destination = "10.244.1.7"
	backend.L4.GetTCP().DestinationPort = 5432
	clusterIP := testProbeFlow(now)
	clusterIP.IP.Destination = "10.96.0.10"
	other := testProbeFlow(now)
	other.IP.Destination = "10.244.9.9"
	otherPort := testProbeFlow(now)
	otherPort.IP.Destination = "10.244.1.7"
	otherPort.L4.GetTCP().DestinationPort = 22
	got := correlateProbeFlows([]*flowpb.Flow{backend, clusterIP, other, otherPort}, req, now.Add(-time.Second), now.Add(time.Second))
	if len(got) != 2 || got[0] != backend || got[1] != clusterIP {
		t.Fatalf("got %d correlated flows, want backend and ClusterIP only", len(got))
	}
	if r := probeFlowMismatch(other, req, now.Add(-time.Second), now.Add(time.Second)); !strings.Contains(r, "database/db") {
		t.Fatalf("debug reason does not name the Service: %q", r)
	}

	// Without a resolved Service a remapped port is never evidence.
	req.service = nil
	if got := correlateProbeFlows([]*flowpb.Flow{backend}, req, now.Add(-time.Second), now.Add(time.Second)); len(got) != 0 {
		t.Fatal("target port accepted without a Service mapping")
	}
}

func TestProbeServiceResolutionFailures(t *testing.T) {
	s, core := testProbeServer(t)
	req := testProbeReq()
	req.Host = "api.example.com"
	if svc, note := s.resolveProbeService(context.Background(), req); svc != nil || note != "" {
		t.Fatal("external host resolved", svc, note)
	}
	req.Host = "missing.database"
	if svc, note := s.resolveProbeService(context.Background(), req); svc != nil || note != "" {
		t.Fatal("absent Service produced a result", svc, note)
	}
	core.PrependReactor("get", "services", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, "db", errors.New("rbac"))
	})
	req.Host = "db.database"
	if svc, note := s.resolveProbeService(context.Background(), req); svc != nil || !strings.Contains(note, "forbidden") {
		t.Fatal("forbidden Service read not surfaced", svc, note)
	}
}

// One TCP connection is many trace events; they must read as one row.
func TestProbeFlowsAndSimulationRowsFolded(t *testing.T) {
	now := time.Now()
	flows := []*flowpb.Flow{}
	for i := 0; i < 9; i++ {
		f := testProbeFlow(now.Add(time.Duration(i) * time.Millisecond))
		f.Verdict = flowpb.Verdict_FORWARDED
		flows = append(flows, f)
	}
	dropped := testProbeFlow(now)
	dropped.Verdict = flowpb.Verdict_DROPPED
	folded := foldProbeFlows(append(flows, dropped))
	if len(folded) != 2 || folded[0].Count != 9 || folded[1].Count != 1 {
		t.Fatalf("flows not folded by content: %+v", folded)
	}

	s, _ := testProbeServer(t)
	s.cilium = ciliumfake.NewSimpleClientset()
	const candidate = "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: allow\n  namespace: database\nspec:\n  endpointSelector:\n    matchLabels:\n      app: server\n  ingress:\n    - fromEntities: [all]\n"
	rules, err := parseCandidateYAML(s.logger, []byte(candidate), "database")
	if err != nil {
		t.Fatal(err)
	}
	resp := connectionProbeResponse{Namespace: "app"}
	s.simulateProbe(context.Background(), rules, candidate, flows, &resp)
	if resp.Simulation == nil || len(resp.Simulation.Rows) != 1 || resp.Simulation.Rows[0].Count != 9 || resp.Simulation.Counts.Total != 9 {
		t.Fatalf("simulation rows not folded: %+v", resp.Simulation)
	}
}

// Real-cluster regression: the relay replica on a NotReady node was chosen
// (phase still Running) and every port-forward failed with the kubelet
// unreachable, although a healthy replica existed.
func TestFindHubbleRelayPodPrefersReady(t *testing.T) {
	relay := func(name string, ready corev1.ConditionStatus) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: hubbleNamespace, Labels: relayLabels()},
			Status:     corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: ready}}},
		}
	}
	core := fake.NewSimpleClientset(relay("relay-a-dead-node", corev1.ConditionFalse), relay("relay-b", corev1.ConditionTrue))
	if got, err := findHubbleRelayPod(core); err != nil || got != "relay-b" {
		t.Fatalf("got %q %v, want the Ready replica", got, err)
	}
	core = fake.NewSimpleClientset(relay("relay-a-dead-node", corev1.ConditionFalse))
	if got, err := findHubbleRelayPod(core); err != nil || got != "relay-a-dead-node" {
		t.Fatalf("got %q %v, want the Running fallback", got, err)
	}
}

func relayLabels() map[string]string {
	k, v, _ := strings.Cut(hubbleLabel, "=")
	return map[string]string{k: v}
}

// Real-cluster regression: a toFQDNs CNP in an unrelated namespace made every
// probe simulation inconclusive. A CNP only selects endpoints in its own
// namespace, so only one in the flow's source/destination namespace counts.
func TestProbeProxyGateScopedToFlowNamespaces(t *testing.T) {
	fqdn := func(ns string) *ciliumv2.CiliumNetworkPolicy {
		return &ciliumv2.CiliumNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "fqdn", Namespace: ns}, Spec: &api.Rule{
			EndpointSelector: api.NewESFromMatchRequirements(map[string]string{}, nil),
			Egress:           []api.EgressRule{{ToFQDNs: api.FQDNSelectorSlice{{MatchName: "example.com"}}}},
		}}
	}
	const candidate = "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: allow\n  namespace: database\nspec:\n  endpointSelector:\n    matchLabels:\n      app: server\n  ingress:\n    - fromEntities: [all]\n"
	flows := []*flowpb.Flow{testProbeFlow(time.Now())}
	for ns, wantSim := range map[string]bool{"unrelated": true, "app": false, "database": false} {
		s, _ := testProbeServer(t)
		s.cilium = ciliumfake.NewSimpleClientset(fqdn(ns))
		rules, err := parseCandidateYAML(s.logger, []byte(candidate), "database")
		if err != nil {
			t.Fatal(err)
		}
		resp := connectionProbeResponse{Namespace: "app"}
		s.simulateProbe(context.Background(), rules, candidate, flows, &resp)
		if (resp.Simulation != nil) != wantSim {
			t.Errorf("toFQDNs CNP in %s: simulated=%v, want %v (%v)", ns, resp.Simulation != nil, wantSim, resp.Warnings)
		}
	}
}

// Real-cluster regression: an unrelated NotReady node made every probe's
// capture "incomplete" although neither endpoint ran there.
func TestProbeDownOnPath(t *testing.T) {
	now := time.Now()
	srcSide := testProbeFlow(now)
	srcSide.NodeName = "c/src-node"
	dstSide := testProbeFlow(now)
	dstSide.NodeName = "c/dst-node"
	dstSide.TraceObservationPoint = flowpb.TraceObservationPoint_TO_ENDPOINT
	down := []string{"c/dead-node"}
	if got := probeDownOnPath(down, "src-node", []*flowpb.Flow{srcSide, dstSide}); len(got) != 0 {
		t.Fatal("off-path node treated as on path", got)
	}
	if got := probeDownOnPath([]string{"c/src-node"}, "src-node", []*flowpb.Flow{srcSide, dstSide}); len(got) != 1 {
		t.Fatal("source node outage ignored")
	}
	// Destination is a Pod but only source-side events arrived: the down
	// node may be the destination's, holding an ingress drop.
	if got := probeDownOnPath(down, "src-node", []*flowpb.Flow{srcSide}); len(got) != 1 {
		t.Fatal("possible destination-node outage ignored")
	}
	if got := probeDownOnPath(down, "src-node", nil); len(got) != 1 {
		t.Fatal("outage with no evidence ignored")
	}
}

func noteText(resp connectionProbeResponse) string {
	var parts []string
	for _, n := range resp.Notes {
		parts = append(parts, n.Text)
	}
	return strings.Join(parts, " ")
}

// Every note carries a stable code the UI maps to an icon and short title.
func TestProbeNotesCarryStableCodes(t *testing.T) {
	s, _ := testProbeServer(t)
	s.cilium = ciliumfake.NewSimpleClientset()
	const candidate = "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: allow\n  namespace: database\nspec:\n  endpointSelector:\n    matchLabels:\n      app: server\n  ingress:\n    - fromEntities: [all]\n"
	rules, err := parseCandidateYAML(s.logger, []byte(candidate), "database")
	if err != nil {
		t.Fatal(err)
	}
	resp := connectionProbeResponse{Namespace: "app"}
	s.simulateProbeWithMode(context.Background(), rules, candidate, []*flowpb.Flow{testProbeFlow(time.Now())}, &resp, false)
	if len(resp.Notes) == 0 || resp.Notes[0].Code != noteAdditiveMode || resp.Notes[0].Text == "" {
		t.Fatalf("notes without codes: %+v", resp.Notes)
	}
}
