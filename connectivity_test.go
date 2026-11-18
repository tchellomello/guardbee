package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	relaypb "github.com/cilium/cilium/api/v1/relay"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumfake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func connectionPOST(s *uiServer, req connectionProbeRequest) *httptest.ResponseRecorder {
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "http://127.0.0.1:4747/api/probes/connection", bytes.NewReader(body))
	r.Header.Set("Origin", "http://127.0.0.1:4747")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleConnectionProbe(w, r)
	return w
}

func TestConnectionProtocolValidationAndLegacy(t *testing.T) {
	s, core := testProbeServer(t)
	for _, protocol := range []string{"", "tcp", "udp", " TCP", "SCTP", "UDP;id"} {
		req := testProbeReq()
		req.Protocol = protocol
		if w := connectionPOST(s, req); w.Code != 400 {
			t.Fatalf("accepted %q: %d %s", protocol, w.Code, w.Body.String())
		}
	}
	noProbeMutation(t, core)
	req := testProbeReq()
	req.Protocol = "UDP"
	if w := connectionPOST(&uiServer{}, req); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := probePOST(s, req); w.Code != 400 {
		t.Fatal("UDP accepted on legacy TCP route")
	}
	// Missing protocol remains TCP only on the old API.
	req.Protocol = ""
	s.probes.capture = func(context.Context, *uiServer, connectionProbeRequest) (*probeCapture, error) {
		return nil, fmt.Errorf("test capture unavailable")
	}
	w := probePOST(s, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"protocol":"TCP"`) {
		t.Fatal(w.Code, w.Body.String())
	}
}

func udpFlow(now time.Time) *flowpb.Flow {
	f := testProbeFlow(now)
	f.L4.Protocol = &flowpb.Layer4_UDP{UDP: &flowpb.UDP{DestinationPort: 443}}
	return f
}

func TestConnectionUDPCaptureAndMixedProtocolCorrelation(t *testing.T) {
	now := time.Now()
	req := testProbeReq()
	req.Protocol = "UDP"
	udp := udpFlow(now)
	tcp := testProbeFlow(now)
	got := correlateProbeFlows([]*flowpb.Flow{tcp, udp}, req, now.Add(-time.Second), now.Add(time.Second))
	if len(got) != 1 || got[0] != udp {
		t.Fatal("mixed protocol capture", got)
	}
	req.Host = "DB.APP.SVC."
	udp.DestinationNames = []string{"db.app.svc"}
	absent := udpFlow(now)
	if got := correlateProbeFlows([]*flowpb.Flow{udp, absent}, req, now.Add(-time.Second), now.Add(time.Second)); len(got) != 1 {
		t.Fatal("UDP DNS correlation must require exact names", got)
	}
	s, _ := testProbeServer(t)
	client := &fakeProbeObserver{stream: &fakeProbeStream{events: []*observerpb.GetFlowsResponse{probeNodeEvent(relaypb.NodeState_NODE_CONNECTED, "worker")}}}
	s.probes.dial = func(context.Context, *uiServer) (observerpb.ObserverClient, func(), error) {
		return client, func() {}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	capture, err := startProbeCapture(ctx, s, req)
	if err != nil {
		t.Fatal(err)
	}
	capture.stop()
	if client.request.Whitelist[0].Protocol[0] != "UDP" {
		t.Fatal(client.request)
	}
}

func TestConnectionUDPOutcomesAndIncompleteCapture(t *testing.T) {
	for _, tt := range []struct {
		exit    int32
		outcome string
		lost    bool
	}{{0, "generated", false}, {1, "failed", false}, {127, "inconclusive", false}, {124, "inconclusive", false}, {0, "generated", true}} {
		t.Run(fmt.Sprint(tt), func(t *testing.T) {
			s, core := testProbeServer(t)
			req := testProbeReq()
			req.Protocol = "UDP"
			req.CandidateYAML = "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: allow\nspec:\n  endpointSelector: {}\n  ingress:\n    - fromEntities: [all]\n"
			stored := testProbePod()
			s.probes.capture = func(context.Context, *uiServer, connectionProbeRequest) (*probeCapture, error) {
				c := &probeCapture{stop: func() {}}
				if tt.lost {
					c.err = fmt.Errorf("lost events")
				}
				return c, nil
			}
			core.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) { return true, stored.DeepCopy(), nil })
			core.PrependReactor("update", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
				stored = a.(ktesting.UpdateAction).GetObject().(*corev1.Pod).DeepCopy()
				ec := stored.Spec.EphemeralContainers[0]
				if ec.Command[4] != "python3" || ec.Command[7] != udpProbeScript {
					t.Fatal(ec.Command)
				}
				reason := "Error"
				if tt.exit == 0 {
					reason = "Completed"
				}
				stored.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: ec.Name, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: reason, ExitCode: tt.exit}}}}
				return true, stored.DeepCopy(), nil
			})
			w := connectionPOST(s, req)
			var resp connectionProbeResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatal(w.Code, w.Body.String())
			}
			if resp.Outcome != tt.outcome || resp.Protocol != "UDP" {
				t.Fatal(resp)
			}
			if tt.lost && (resp.Simulation != nil || !strings.Contains(strings.Join(resp.Warnings, " "), "Simulation inconclusive: capture")) {
				t.Fatal(resp)
			}
		})
	}
}

func TestConnectionExplicitUnchangedDecisionsRealEngine(t *testing.T) {
	for _, protocol := range []string{"TCP", "UDP"} {
		for _, allowed := range []bool{true, false} {
			t.Run(fmt.Sprint(protocol, allowed), func(t *testing.T) {
				s, _ := testProbeServer(t)
				peer := "not-client"
				if allowed {
					peer = "client"
				}
				candidate := "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: edit\n  namespace: database\nspec:\n  endpointSelector:\n    matchLabels:\n      app: server\n  ingress:\n    - fromEndpoints:\n        - matchLabels:\n            app: " + peer + "\n"
				if allowed {
					candidate = strings.Replace(candidate, "    - fromEndpoints:\n        - matchLabels:\n            app: client", "    - fromEntities: [all]", 1)
				}
				decoded, err := decodeCandidateYAML([]byte(candidate), "app")
				if err != nil {
					t.Fatal(err)
				}
				s.cilium = ciliumfake.NewSimpleClientset(&ciliumv2.CiliumNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "edit", Namespace: "database"}, Spec: decoded.rule})
				rules, err := parseCandidateYAML(s.logger, []byte(candidate), "app")
				if err != nil {
					t.Fatal(err)
				}
				f := testProbeFlow(time.Now())
				if protocol == "UDP" {
					f = udpFlow(time.Now())
				}
				resp := connectionProbeResponse{Namespace: "app"}
				s.simulateProbe(context.Background(), rules, candidate, []*flowpb.Flow{f}, &resp)
				if resp.Simulation == nil || len(resp.Simulation.Rows) != 1 {
					t.Fatal(resp)
				}
				row := resp.Simulation.Rows[0]
				if row.Change != "UNCHANGED" || row.BaselineAllowed == nil || row.CandidateAllowed == nil || *row.BaselineAllowed != allowed || *row.CandidateAllowed != allowed {
					t.Fatal(row)
				}
				b, _ := json.Marshal(row)
				if !strings.Contains(string(b), fmt.Sprintf(`"candidateAllowed":%t`, allowed)) {
					t.Fatal(string(b))
				}
				// A real observed drop with an unresolved destination cannot be invented.
				f.Destination = nil
				f.Verdict = flowpb.Verdict_DROPPED
				resp = connectionProbeResponse{Namespace: "app"}
				s.simulateProbe(context.Background(), rules, candidate, []*flowpb.Flow{f}, &resp)
				if resp.Simulation == nil || len(resp.Simulation.Rows) != 0 || resp.Simulation.Counts.NotSimulated != 1 {
					t.Fatal(resp)
				}
			})
		}
	}
}

func TestUDPFixedProgramSingleDatagramAndArgumentSafety(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("local Python 3 unavailable")
	}
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("local timeout unavailable")
	}
	// Use a local non-loopback interface: production rejects loopback even
	// after DNS resolution, and the test must exercise the unmodified script.
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	var ip net.IP
	for _, addr := range addresses {
		if n, ok := addr.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			ip = n.IP.To4()
			break
		}
	}
	if ip == nil {
		t.Skip("no local non-loopback IPv4 interface")
	}
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	req := testProbeReq()
	req.Protocol, req.Host, req.Port = "UDP", ip.String(), server.LocalAddr().(*net.UDPAddr).Port
	argv := secureProbeContainer("test", testProbeImage, req).Command
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("fixed UDP program: %v %s", err, out)
	}
	buf := make([]byte, 1024)
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := server.ReadFromUDP(buf)
	if err != nil || string(buf[:n]) != "guardbee-connectivity-probe" {
		t.Fatal(n, err, string(buf[:n]))
	}
	_ = server.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := server.ReadFromUDP(buf); err == nil {
		t.Fatal("sent more than one datagram")
	}
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	for _, args := range [][]string{{"127.0.0.1", fmt.Sprint(req.Port)}, {"localhost", fmt.Sprint(req.Port)}, {"224.0.0.1", fmt.Sprint(req.Port)}, {"::1", fmt.Sprint(req.Port)}, {"fe80::1%lo", fmt.Sprint(req.Port)}, {ip.String(), "1; touch " + marker}, {"$(touch " + marker + ")", fmt.Sprint(req.Port)}} {
		cmd := exec.CommandContext(ctx, "timeout", "-k", "1s", "8s", "python3", "-I", "-c", udpProbeScript, args[0], args[1])
		if err := cmd.Run(); err == nil {
			t.Fatal("unsafe target or argument accepted", args)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("operator argument evaluated", err)
	}
}
