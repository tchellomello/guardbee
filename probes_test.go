package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	relaypb "github.com/cilium/cilium/api/v1/relay"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	ciliumfake "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	"github.com/cilium/cilium/pkg/policy/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
)

const testProbeImage = "registry.example/probe@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testProbeReq() connectionProbeRequest {
	return connectionProbeRequest{Protocol: "TCP", Namespace: "app", Pod: "client", UID: "uid-1", Host: "192.0.2.2", Port: 443}
}
func testProbePod() *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "client", Namespace: "app", UID: types.UID("uid-1"), ResourceVersion: "7", Labels: map[string]string{"app": "client"}}, Spec: corev1.PodSpec{NodeName: "worker", ServiceAccountName: "workload", Containers: []corev1.Container{{Name: "app", Image: "app:1"}}, Volumes: []corev1.Volume{{Name: "token"}}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
}

func testProbeServer(t *testing.T) (*uiServer, *fake.Clientset) {
	t.Helper()
	b, err := newProbeBackend(true, testProbeImage)
	if err != nil {
		t.Fatal(err)
	}
	b.timeout = 100 * time.Millisecond
	b.poll = time.Millisecond
	b.drain = time.Millisecond
	core := fake.NewSimpleClientset(testProbePod())
	core.PrependReactor("create", "selfsubjectaccessreviews", func(a ktesting.Action) (bool, runtime.Object, error) {
		return true, &authv1.SelfSubjectAccessReview{Status: authv1.SubjectAccessReviewStatus{Allowed: true}}, nil
	})
	b.capture = func(context.Context, *uiServer, connectionProbeRequest) (*probeCapture, error) {
		return &probeCapture{stop: func() {}}, nil
	}
	b.logs = func(context.Context, *uiServer, connectionProbeRequest, string) error { return nil }
	return &uiServer{core: core, cilium: ciliumfake.NewSimpleClientset(), logger: slog.Default(), probes: b}, core
}

func noProbeMutation(t *testing.T, core *fake.Clientset) {
	t.Helper()
	for _, a := range core.Actions() {
		if a.GetVerb() == "update" || a.GetVerb() == "patch" || a.GetVerb() == "delete" || a.GetResource().Resource == "pods" && a.GetVerb() == "create" {
			t.Fatalf("unexpected mutation: %#v", a)
		}
	}
}

func TestProbeOptInAndListen(t *testing.T) {
	for _, image := range []string{"", "busybox", "r@sha256:bad", "r@sha256:" + strings.Repeat("A", 64), "r;bad@sha256:" + strings.Repeat("a", 64)} {
		if _, err := newProbeBackend(true, image); err == nil {
			t.Fatalf("accepted %q", image)
		}
	}
	if b, err := newProbeBackend(false, "bad"); b != nil || err != nil {
		t.Fatal("disabled should not require image")
	}
	for _, addr := range []string{"0.0.0.0:4747", "localhost:4747", ":4747", "example.com:4747", "127.0.0.1", "127.0.0.1:0", "[::1]:65536"} {
		if validateProbeListenAddr(addr) == nil {
			t.Fatalf("accepted %s", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:4747", "[::1]:4747"} {
		if err := validateProbeListenAddr(addr); err != nil {
			t.Fatal(err)
		}
	}
	s := &uiServer{}
	w := httptest.NewRecorder()
	s.handleProbeCapabilities(w, httptest.NewRequest("GET", "/", nil))
	var caps struct {
		Enabled   bool     `json:"enabled"`
		Protocols []string `json:"protocols"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &caps); err != nil || caps.Enabled || !reflect.DeepEqual(caps.Protocols, []string{"TCP", "UDP"}) {
		t.Fatal(w.Body.String())
	}
	w = connectionPOST(s, testProbeReq())
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	s.handleProbePods(w, httptest.NewRequest("GET", "/api/probes/pods?namespace=app", nil))
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}

func TestProbeInputAndCSRF(t *testing.T) {
	s, core := testProbeServer(t)
	valid, _ := json.Marshal(testProbeReq())
	for _, tt := range []struct {
		name, origin, host, ct, body, site, method string
		code                                       int
	}{
		{"missing origin", "", "127.0.0.1:4747", "application/json", string(valid), "", "POST", 403},
		{"cross origin", "http://evil.example", "127.0.0.1:4747", "application/json", string(valid), "", "POST", 403},
		{"rebound DNS", "http://evil.example:4747", "evil.example:4747", "application/json", string(valid), "", "POST", 403},
		{"wrong port", "http://127.0.0.1:4748", "127.0.0.1:4747", "application/json", string(valid), "", "POST", 403},
		{"origin path", "http://127.0.0.1:4747/", "127.0.0.1:4747", "application/json", string(valid), "", "POST", 403},
		{"fetch cross site", "http://127.0.0.1:4747", "127.0.0.1:4747", "application/json", string(valid), "cross-site", "POST", 403},
		{"form", "http://127.0.0.1:4747", "127.0.0.1:4747", "text/plain", string(valid), "", "POST", 415},
		{"bad JSON", "http://127.0.0.1:4747", "127.0.0.1:4747", "application/json", "not json", "", "POST", 400},
		{"extra JSON", "http://127.0.0.1:4747", "127.0.0.1:4747", "application/json", string(valid) + " {}", "", "POST", 400},
		{"unknown field", "http://127.0.0.1:4747", "127.0.0.1:4747", "application/json", "{\"command\":\"sh\"}", "", "POST", 400},
		{"body bound", "http://127.0.0.1:4747", "127.0.0.1:4747", "application/json", "{\"candidateYAML\":\"" + strings.Repeat("x", probeBodyLimit) + "\"}", "", "POST", 400},
		{"method", "http://127.0.0.1:4747", "127.0.0.1:4747", "application/json", string(valid), "", "GET", 405},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(tt.method, "http://"+tt.host+"/api/probes/connection", strings.NewReader(tt.body))
			r.Header.Set("Origin", tt.origin)
			r.Header.Set("Content-Type", tt.ct)
			r.Header.Set("Sec-Fetch-Site", tt.site)
			w := httptest.NewRecorder()
			s.handleConnectionProbe(w, r)
			if w.Code != tt.code {
				t.Fatalf("%d: %s", w.Code, w.Body.String())
			}
		})
	}
	for _, mutate := range []func(*connectionProbeRequest){func(r *connectionProbeRequest) { r.Namespace = "" }, func(r *connectionProbeRequest) { r.Pod = "bad/name" }, func(r *connectionProbeRequest) { r.UID = "" }, func(r *connectionProbeRequest) { r.Port = 0 }, func(r *connectionProbeRequest) { r.Port = 65536 }, func(r *connectionProbeRequest) { r.Host = "--help" }, func(r *connectionProbeRequest) { r.Host = "https://db.app.svc" }, func(r *connectionProbeRequest) { r.Host = "fe80::1%eth0" }, func(r *connectionProbeRequest) { r.Host = "0.0.0.0" }, func(r *connectionProbeRequest) { r.Host = "224.0.0.1" }, func(r *connectionProbeRequest) { r.CandidateYAML = "kind: Pod" }} {
		r := testProbeReq()
		mutate(&r)
		if w := connectionPOST(s, r); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	noProbeMutation(t, core)
}

func TestProbeRBACChecksExactSubresources(t *testing.T) {
	for _, denied := range []string{"pods//get", "pods/ephemeralcontainers/update", "pods/log/get"} {
		t.Run(denied, func(t *testing.T) {
			s, core := testProbeServer(t)
			core.PrependReactor("create", "selfsubjectaccessreviews", func(a ktesting.Action) (bool, runtime.Object, error) {
				v := a.(ktesting.CreateAction).GetObject().(*authv1.SelfSubjectAccessReview).Spec.ResourceAttributes
				if v.Namespace != "app" || v.Name != "client" || v.Group != "" {
					t.Fatalf("wrong authorization: %+v", v)
				}
				return true, &authv1.SelfSubjectAccessReview{Status: authv1.SubjectAccessReviewStatus{Allowed: v.Resource+"/"+v.Subresource+"/"+v.Verb != denied}}, nil
			})
			w := connectionPOST(s, testProbeReq())
			if w.Code != 403 {
				t.Fatal(w.Code, w.Body.String())
			}
			noProbeMutation(t, core)
		})
	}
	s, core := testProbeServer(t)
	core.PrependReactor("create", "selfsubjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("RBAC unavailable") })
	if w := connectionPOST(s, testProbeReq()); w.Code != 403 {
		t.Fatal(w.Code)
	}
	noProbeMutation(t, core)
}

func TestProbeUIDReReadAndEligibility(t *testing.T) {
	for _, stage := range []int{1, 2} {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			s, core := testProbeServer(t)
			reads := 0
			stopped := false
			s.probes.capture = func(context.Context, *uiServer, connectionProbeRequest) (*probeCapture, error) {
				return &probeCapture{stop: func() { stopped = true }}, nil
			}
			core.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
				reads++
				p := testProbePod()
				if reads == stage {
					p.UID = "replacement"
				}
				return true, p, nil
			})
			w := connectionPOST(s, testProbeReq())
			if w.Code != 409 {
				t.Fatal(w.Code, w.Body.String())
			}
			if stage == 2 && !stopped {
				t.Fatal("capture not stopped")
			}
			noProbeMutation(t, core)
		})
	}
	for _, mutate := range []func(*corev1.Pod){func(p *corev1.Pod) { p.Spec.HostNetwork = true }, func(p *corev1.Pod) { p.Spec.HostPID = true }, func(p *corev1.Pod) { p.Spec.HostIPC = true }, func(p *corev1.Pod) { v := true; p.Spec.ShareProcessNamespace = &v }, func(p *corev1.Pod) { p.Status.Phase = corev1.PodPending }, func(p *corev1.Pod) { p.Annotations = map[string]string{"kubernetes.io/config.mirror": "x"} }, func(p *corev1.Pod) { p.Spec.OS = &corev1.PodOS{Name: corev1.Windows} }, func(p *corev1.Pod) { now := metav1.Now(); p.DeletionTimestamp = &now }} {
		p := testProbePod()
		mutate(p)
		if normalProbePod(p) {
			t.Fatalf("unsafe eligible Pod %+v", p)
		}
	}
	for _, n := range []int{8, 32} {
		s, core := testProbeServer(t)
		p := testProbePod()
		for i := 0; i < n; i++ {
			prefix := "old-"
			if n == 8 {
				prefix = "guardbee-tcp-"
			}
			p.Spec.EphemeralContainers = append(p.Spec.EphemeralContainers, corev1.EphemeralContainer{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: fmt.Sprint(prefix, i)}})
		}
		core.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) { return true, p, nil })
		if w := connectionPOST(s, testProbeReq()); w.Code != 409 {
			t.Fatal(w.Code)
		}
		noProbeMutation(t, core)
	}
}

func TestProbeRuntimeOutcomesSecurityAndNoWorkloadMutation(t *testing.T) {
	for _, tt := range []struct {
		reason  string
		exit    int32
		outcome string
	}{{"Completed", 0, "connected"}, {"Error", 1, "failed"}, {"Error", 124, "inconclusive"}, {"OOMKilled", 137, "inconclusive"}, {"Error", 127, "inconclusive"}} {
		t.Run(fmt.Sprint(tt.exit), func(t *testing.T) {
			s, core := testProbeServer(t)
			capturing := false
			stopped := false
			logged := false
			s.probes.capture = func(ctx context.Context, _ *uiServer, _ connectionProbeRequest) (*probeCapture, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("capture needs deadline")
				}
				capturing = true
				return &probeCapture{stop: func() { stopped = true }}, nil
			}
			s.probes.logs = func(ctx context.Context, _ *uiServer, _ connectionProbeRequest, name string) error {
				logged = true
				if !strings.HasPrefix(name, "guardbee-connection-") {
					t.Fatal(name)
				}
				return errors.New("logs denied")
			}
			original := testProbePod()
			stored := original.DeepCopy()
			core.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) { return true, stored.DeepCopy(), nil })
			core.PrependReactor("update", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
				if !capturing {
					t.Fatal("injected before capture readiness")
				}
				if a.GetSubresource() != "ephemeralcontainers" {
					t.Fatal("non-subresource mutation")
				}
				p := a.(ktesting.UpdateAction).GetObject().(*corev1.Pod)
				if p.UID != original.UID || p.ResourceVersion != original.ResourceVersion {
					t.Fatal("missing UID/resourceVersion precondition")
				}
				ec := p.Spec.EphemeralContainers[0]
				expected := secureProbeContainer(ec.Name, testProbeImage, testProbeReq())
				if !reflect.DeepEqual(ec, expected) {
					t.Fatalf("unexpected container %+v", ec)
				}
				sc := ec.SecurityContext
				if !*sc.RunAsNonRoot || *sc.RunAsUser != 65532 || *sc.Privileged || *sc.AllowPrivilegeEscalation || !*sc.ReadOnlyRootFilesystem || len(ec.VolumeMounts) > 0 || len(ec.Env) > 0 || ec.TargetContainerName != "" || len(ec.Args) > 0 || len(sc.Capabilities.Add) > 0 {
					t.Fatal("unsafe container")
				}
				q := p.DeepCopy()
				q.Spec.EphemeralContainers = nil
				if !reflect.DeepEqual(q, original) {
					t.Fatal("workload mutated")
				}
				stored = p.DeepCopy()
				stored.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: ec.Name, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: tt.reason, ExitCode: tt.exit}}}}
				return true, p, nil
			})
			w := connectionPOST(s, testProbeReq())
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			var resp connectionProbeResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp.Outcome != tt.outcome || !stopped || !logged || resp.ContainerName == "" || resp.Flows == nil || resp.Warnings == nil {
				t.Fatalf("bad response %+v stop %v logs %v", resp, stopped, logged)
			}
			if strings.Contains(resp.Message, "POLICY_DENY") {
				t.Fatal("nc result falsely attributed to policy")
			}
			for _, a := range core.Actions() {
				if a.GetVerb() == "delete" || a.GetVerb() == "patch" || a.GetSubresource() == "exec" {
					t.Fatal("forbidden mutation")
				}
			}
		})
	}
}

func TestProbeCaptureFailureTimeoutUpdateFailureConcurrency(t *testing.T) {
	s, core := testProbeServer(t)
	s.probes.capture = func(context.Context, *uiServer, connectionProbeRequest) (*probeCapture, error) {
		return nil, errors.New("relay unavailable")
	}
	w := connectionPOST(s, testProbeReq())
	if w.Code != 200 || !strings.Contains(w.Body.String(), "no container injected") {
		t.Fatal(w.Body.String())
	}
	noProbeMutation(t, core)
	s, core = testProbeServer(t)
	stops := 0
	s.probes.capture = func(context.Context, *uiServer, connectionProbeRequest) (*probeCapture, error) {
		return &probeCapture{stop: func() { stops++ }}, nil
	}
	start := time.Now()
	w = connectionPOST(s, testProbeReq())
	if time.Since(start) > time.Second || !strings.Contains(w.Body.String(), "inconclusive") || stops == 0 {
		t.Fatal(w.Body.String(), stops)
	}
	if len(s.probes.slots) != 0 || len(s.probes.active) != 0 {
		t.Fatal("concurrency slot leaked")
	}
	s, core = testProbeServer(t)
	core.PrependReactor("update", "pods", func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("conflict") })
	w = connectionPOST(s, testProbeReq())
	if !strings.Contains(w.Body.String(), "inspect the Pod before retrying") {
		t.Fatal(w.Body.String())
	}
	s, core = testProbeServer(t)
	s.probes.slots <- struct{}{}
	s.probes.slots <- struct{}{}
	if w = connectionPOST(s, testProbeReq()); w.Code != 429 {
		t.Fatal(w.Code)
	}
	noProbeMutation(t, core)
	s, core = testProbeServer(t)
	s.probes.active["app/client"] = true
	if w = connectionPOST(s, testProbeReq()); w.Code != 429 {
		t.Fatal(w.Code)
	}
	noProbeMutation(t, core)
}

func testProbeFlow(now time.Time) *flowpb.Flow {
	return &flowpb.Flow{Time: timestamppb.New(now), Source: &flowpb.Endpoint{Namespace: "app", PodName: "client", Identity: 1000, Labels: []string{"k8s:app=client", "k8s:io.kubernetes.pod.namespace=app"}}, Destination: &flowpb.Endpoint{Namespace: "database", PodName: "server", Identity: 1001, Labels: []string{"k8s:app=server", "k8s:io.kubernetes.pod.namespace=database"}}, IP: &flowpb.IP{Destination: "192.0.2.2"}, L4: &flowpb.Layer4{Protocol: &flowpb.Layer4_TCP{TCP: &flowpb.TCP{DestinationPort: 443}}}}
}

func TestProbeCorrelation(t *testing.T) {
	now := time.Now()
	flows := []*flowpb.Flow{testProbeFlow(now)}
	for _, mutate := range []func(*flowpb.Flow){func(f *flowpb.Flow) { f.Source.PodName = "client-other" }, func(f *flowpb.Flow) { f.Source.Namespace = "other" }, func(f *flowpb.Flow) { f.Time = timestamppb.New(now.Add(-time.Hour)) }, func(f *flowpb.Flow) { f.Time = timestamppb.New(now.Add(time.Hour)) }, func(f *flowpb.Flow) { f.Time = nil }, func(f *flowpb.Flow) { f.IP.Destination = "192.0.2.3" }, func(f *flowpb.Flow) { f.L4.GetTCP().DestinationPort = 80 }, func(f *flowpb.Flow) { f.L4 = nil }, func(f *flowpb.Flow) { f.IP = nil }} {
		f := testProbeFlow(now)
		mutate(f)
		flows = append(flows, f)
	}
	got := correlateProbeFlows(flows, testProbeReq(), now.Add(-time.Second), now.Add(time.Second))
	if len(got) != 1 || got[0] != flows[0] {
		t.Fatal("incorrect correlation", len(got))
	}
}

func TestProbeSimulationRealEngineCrossNamespaceAndUnverifiedGroups(t *testing.T) {
	s, _ := testProbeServer(t)
	policy := &ciliumv2.CiliumNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny", Namespace: "database"}, Spec: &api.Rule{EndpointSelector: api.NewESFromMatchRequirements(map[string]string{"app": "server"}, nil), Ingress: []api.IngressRule{{IngressCommonRule: api.IngressCommonRule{FromEndpoints: []api.EndpointSelector{api.NewESFromMatchRequirements(map[string]string{"app": "not-client"}, nil)}}}}}}
	s.cilium = ciliumfake.NewSimpleClientset(policy)
	const candidate = "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: allow\n  namespace: database\nspec:\n  endpointSelector:\n    matchLabels:\n      app: server\n  ingress:\n    - fromEntities: [all]\n"
	rules, err := parseCandidateYAML(s.logger, []byte(candidate), "app")
	if err != nil {
		t.Fatal(err)
	}
	resp := connectionProbeResponse{Namespace: "app"}
	s.simulateProbe(context.Background(), rules, candidate, []*flowpb.Flow{testProbeFlow(time.Now())}, &resp)
	if resp.Simulation == nil || resp.Simulation.BaselineRuleCount != 1 || resp.Simulation.Counts.NewlyAllowed != 1 {
		t.Fatalf("missing full baseline %+v simulation %+v", resp, resp.Simulation)
	}
	row := resp.Simulation.Rows[0]
	if row.BaselineAllowed == nil || row.CandidateAllowed == nil || *row.BaselineAllowed || !*row.CandidateAllowed {
		t.Fatal("newly allowed decisions lost", row)
	}
	// CIDR-group labels can be present on real Hubble identities, but the
	// new candidate's IPcache injection is not reproduced. Never expand CIDRs.
	groupCandidate := strings.Replace(candidate, "    - fromEntities: [all]", "    - fromCIDRSet:\n        - cidrGroupRef: external", 1)
	groupRules, err := parseCandidateYAML(s.logger, []byte(groupCandidate), "app")
	if err != nil {
		t.Fatal(err)
	}
	resp = connectionProbeResponse{}
	s.simulateProbe(context.Background(), groupRules, groupCandidate, []*flowpb.Flow{testProbeFlow(time.Now())}, &resp)
	if resp.Simulation != nil || !strings.Contains(strings.Join(resp.Warnings, " "), "unverified") {
		t.Fatal(resp)
	}
	if !hasCIDRGroupRef(map[string]any{"specs": []any{map[string]any{"cidrGroupRef": "group"}}}) || hasCIDRGroupRef(map[string]any{"cidrGroupRef": ""}) {
		t.Fatal("group detection")
	}
	proxy := api.Rules{&api.Rule{Egress: []api.EgressRule{{ToFQDNs: []api.FQDNSelector{{MatchName: "example.com"}}}}}}
	if !probeProxyRules(proxy) {
		t.Fatal("FQDN not gated")
	}
	resp = connectionProbeResponse{}
	s.simulateProbe(context.Background(), proxy, "", []*flowpb.Flow{testProbeFlow(time.Now())}, &resp)
	if resp.Simulation != nil || !strings.Contains(strings.Join(resp.Warnings, " "), "proxy") {
		t.Fatal(resp)
	}
}

func TestProbePodListing(t *testing.T) {
	s, core := testProbeServer(t)
	p := testProbePod()
	p.Name = "host"
	p.Spec.HostNetwork = true
	_, _ = core.CoreV1().Pods("app").Create(context.Background(), p, metav1.CreateOptions{})
	w := httptest.NewRecorder()
	s.handleProbePods(w, httptest.NewRequest("GET", "/api/probes/pods?namespace=app", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), `"name":"host"`) || !strings.Contains(w.Body.String(), "uid-1") {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleProbePods(w, httptest.NewRequest("GET", "/api/probes/pods", nil))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	core.PrependReactor("create", "selfsubjectaccessreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &authv1.SelfSubjectAccessReview{}, nil
	})
	w = httptest.NewRecorder()
	s.handleProbePods(w, httptest.NewRequest("GET", "/api/probes/pods?namespace=app", nil))
	if w.Code != http.StatusForbidden {
		t.Fatal(w.Code)
	}
}

type fakeProbeObserver struct {
	observerpb.ObserverClient
	stream  *fakeProbeStream
	err     error
	request *observerpb.GetFlowsRequest
}

func (f *fakeProbeObserver) GetFlows(ctx context.Context, r *observerpb.GetFlowsRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[observerpb.GetFlowsResponse], error) {
	f.request = r
	f.stream.ctx = ctx
	return f.stream, f.err
}

type fakeProbeStream struct {
	grpc.ClientStream
	ctx        context.Context
	events     []*observerpb.GetFlowsResponse
	headersErr error
}

func (f *fakeProbeStream) Header() (metadata.MD, error) { return nil, f.headersErr }
func (f *fakeProbeStream) Recv() (*observerpb.GetFlowsResponse, error) {
	if len(f.events) > 0 {
		e := f.events[0]
		f.events = f.events[1:]
		return e, nil
	}
	<-f.ctx.Done()
	return nil, f.ctx.Err()
}
func probeNodeEvent(state relaypb.NodeState, names ...string) *observerpb.GetFlowsResponse {
	return &observerpb.GetFlowsResponse{ResponseTypes: &observerpb.GetFlowsResponse_NodeStatus{NodeStatus: &relaypb.NodeStatusEvent{StateChange: state, NodeNames: names}}}
}

func TestProbeCaptureReadyBoundCancellationAndErrors(t *testing.T) {
	for _, scenario := range []string{"connected", "unavailable", "header-error", "getflows-error", "no-ready", "dial-error"} {
		t.Run(scenario, func(t *testing.T) {
			s, _ := testProbeServer(t)
			req := testProbeReq()
			req.nodeName = "worker"
			stream := &fakeProbeStream{}
			client := &fakeProbeObserver{stream: stream}
			closed := 0
			s.probes.dial = func(context.Context, *uiServer) (observerpb.ObserverClient, func(), error) {
				if scenario == "dial-error" {
					return nil, nil, errors.New("dial failed")
				}
				return client, func() { closed++ }, nil
			}
			switch scenario {
			case "connected":
				stream.events = append(stream.events, probeNodeEvent(relaypb.NodeState_NODE_CONNECTED, "cluster/other"), probeNodeEvent(relaypb.NodeState_NODE_CONNECTED, "cluster/worker"))
				for i := 0; i < 300; i++ {
					stream.events = append(stream.events, &observerpb.GetFlowsResponse{ResponseTypes: &observerpb.GetFlowsResponse_Flow{Flow: testProbeFlow(time.Now())}})
				}
				stream.events = append(stream.events, &observerpb.GetFlowsResponse{ResponseTypes: &observerpb.GetFlowsResponse_LostEvents{LostEvents: &flowpb.LostEvent{NumEventsLost: 2}}}, probeNodeEvent(relaypb.NodeState_NODE_UNAVAILABLE, "cluster/worker"))
			case "unavailable":
				stream.events = []*observerpb.GetFlowsResponse{probeNodeEvent(relaypb.NodeState_NODE_UNAVAILABLE, "cluster/worker")}
			case "header-error":
				stream.headersErr = errors.New("headers failed")
			case "getflows-error":
				client.err = errors.New("getflows failed")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			capture, err := startProbeCapture(ctx, s, req)
			if scenario != "connected" {
				if err == nil {
					t.Fatal("expected capture failure")
				}
				if scenario != "dial-error" && closed != 1 {
					t.Fatal("dial resources leaked")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !client.request.Follow || client.request.Number != 0 || len(client.request.Whitelist) != 1 || client.request.Whitelist[0].DestinationIp[0] != req.Host {
				t.Fatal("incorrect capture request")
			}
			<-ctx.Done()
			capture.stop()
			capture.stop()
			flows, captureErr, overflow := capture.snapshot()
			if len(flows) != 256 || !overflow || captureErr == nil || closed != 1 {
				t.Fatalf("capture bound/error/cleanup: %d %v %v %d", len(flows), overflow, captureErr, closed)
			}
		})
	}
}

func TestProbeLogsBoundAndDirectCommand(t *testing.T) {
	var requested bool
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = true
		if r.URL.Path != "/api/v1/namespaces/app/pods/client/log" || r.URL.Query().Get("container") != "guardbee-tcp-test" || r.URL.Query().Get("limitBytes") != "4096" || r.URL.Query().Get("follow") != "" {
			t.Errorf("unsafe log request %s", r.URL)
		}
		_, _ = w.Write([]byte(strings.Repeat("x", 10000)))
	}))
	defer h.Close()
	core, err := kubernetes.NewForConfig(&rest.Config{Host: h.URL})
	if err != nil {
		t.Fatal(err)
	}
	s := &uiServer{core: core}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := readProbeLogs(ctx, s, testProbeReq(), "guardbee-tcp-test"); err != nil || !requested {
		t.Fatal(err, requested)
	}
	expected := []string{"timeout", "-k", "1s", "8s", "nc", "-n", "-z", "-v", "-w", "5", "192.0.2.2", "443"}
	ec := secureProbeContainer("probe", testProbeImage, testProbeReq())
	if !reflect.DeepEqual(ec.Command, expected) {
		t.Fatalf("command changed: %v", ec.Command)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if err := readProbeLogs(ctx, s, testProbeReq(), "guardbee-tcp-test"); err == nil {
		t.Fatal("canceled log read succeeded")
	}
}

func TestProbeNonPolicyTargetsAndSystemPodsRejected(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1", "169.254.169.254", "fe80::1", "ff02::1", "255.255.255.255", "::"} {
		r := testProbeReq()
		r.Host = host
		if validateConnectionProbe(r) == nil {
			t.Fatal("unsafe target", host)
		}
	}
	for _, ns := range []string{"kube-system", "kube-public", "kube-node-lease", "cilium-system", "hubble-system"} {
		r := testProbeReq()
		r.Namespace = ns
		if validateConnectionProbe(r) == nil {
			t.Fatal("unsafe namespace", ns)
		}
		p := testProbePod()
		p.Namespace = ns
		if normalProbePod(p) {
			t.Fatal("unsafe Pod", ns)
		}
	}
	p := testProbePod()
	p.Status.Conditions = nil
	if normalProbePod(p) {
		t.Fatal("unready Pod accepted")
	}
	p = testProbePod()
	p.Spec.NodeName = ""
	if normalProbePod(p) {
		t.Fatal("unscheduled Pod accepted")
	}
}

func TestProbeHostnameValidationCommandAndCorrelation(t *testing.T) {
	for _, host := range []string{"db.app.svc", "DB.APP.SVC.", "example.com", "db"} {
		req := testProbeReq()
		req.Host = host
		if err := validateConnectionProbe(req); err != nil {
			t.Fatal(host, err)
		}
		ec := secureProbeContainer("dns", testProbeImage, req)
		for _, arg := range ec.Command {
			if arg == "-n" || arg == "sh" {
				t.Fatal("hostname DNS disabled or shell used", ec.Command)
			}
		}
		if ec.Command[len(ec.Command)-2] != strings.ToLower(host) {
			t.Fatal(ec.Command)
		}
	}
	for _, host := range []string{"-x", "example.com;id", "https://example.com", "db:443", "db/path", "db name", "db\nname", "a..b", "localhost", "test.localhost", "example.com.."} {
		req := testProbeReq()
		req.Host = host
		if validateConnectionProbe(req) == nil {
			t.Fatal("invalid hostname accepted", host)
		}
	}
	req := testProbeReq()
	req.Host = "DB.APP.SVC."
	now := time.Now()
	matched := testProbeFlow(now)
	matched.DestinationNames = []string{"db.app.svc"}
	alias := testProbeFlow(now)
	alias.DestinationNames = []string{"other.app.svc"}
	absent := testProbeFlow(now)
	got := correlateProbeFlows([]*flowpb.Flow{matched, alias, absent}, req, now.Add(-time.Second), now.Add(time.Second))
	if len(got) != 1 || got[0] != matched {
		t.Fatal("hostname correlated by port alone", got)
	}
	s, _ := testProbeServer(t)
	stream := &fakeProbeStream{events: []*observerpb.GetFlowsResponse{probeNodeEvent(relaypb.NodeState_NODE_CONNECTED, "worker")}}
	client := &fakeProbeObserver{stream: stream}
	s.probes.dial = func(context.Context, *uiServer) (observerpb.ObserverClient, func(), error) {
		return client, func() {}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req.nodeName = "worker"
	capture, err := startProbeCapture(ctx, s, req)
	if err != nil {
		t.Fatal(err)
	}
	capture.stop()
	if len(client.request.Whitelist[0].DestinationIp) != 0 {
		t.Fatal("hostname passed as Hubble IP filter")
	}
}

func TestProbeSimulationNetworkPolicyAndReplacement(t *testing.T) {
	s, core := testProbeServer(t)
	candidate := "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: edit\n  namespace: database\nspec:\n  endpointSelector:\n    matchLabels:\n      app: server\n  ingress:\n    - fromEndpoints:\n        - matchLabels:\n            app: not-client\n"
	rules, err := parseCandidateYAML(s.logger, []byte(candidate), "app")
	if err != nil {
		t.Fatal(err)
	}
	baseYAML := strings.Replace(candidate, "    - fromEndpoints:\n        - matchLabels:\n            app: not-client", "    - fromEntities: [all]", 1)
	decoded, err := decodeCandidateYAML([]byte(baseYAML), "app")
	if err != nil {
		t.Fatal(err)
	}
	base := &ciliumv2.CiliumNetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "edit", Namespace: "database"}, Spec: decoded.rule}
	s.cilium = ciliumfake.NewSimpleClientset(base)
	resp := connectionProbeResponse{Namespace: "app"}
	flows := []*flowpb.Flow{testProbeFlow(time.Now())}
	s.simulateProbe(context.Background(), rules, candidate, flows, &resp)
	if resp.Simulation == nil || resp.Simulation.Counts.NewlyDropped != 1 || !strings.Contains(noteText(resp), "replaces live") {
		t.Fatalf("narrowed edit hidden: %+v %+v", resp, resp.Simulation)
	}
	row := resp.Simulation.Rows[0]
	if row.BaselineAllowed == nil || row.CandidateAllowed == nil || !*row.BaselineAllowed || *row.CandidateAllowed {
		t.Fatal("newly dropped decisions lost", row)
	}
	additive := connectionProbeResponse{Namespace: "app"}
	s.simulateProbeWithMode(context.Background(), rules, candidate, flows, &additive, false)
	if additive.Simulation == nil || additive.Simulation.Counts.Unchanged != 1 || additive.Simulation.Counts.NewlyDropped != 0 || !strings.Contains(noteText(additive), "Additive simulation") {
		t.Fatalf("explicit additive mode not honored: %+v", additive)
	}
	// A NetworkPolicy only selects Pods in its own namespace: one elsewhere in
	// the cluster cannot enforce on this flow and must not block simulation.
	_, err = core.NetworkingV1().NetworkPolicies("unrelated").Create(context.Background(), &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny", Namespace: "unrelated"}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	resp = connectionProbeResponse{}
	s.simulateProbe(context.Background(), rules, candidate, flows, &resp)
	if resp.Simulation == nil {
		t.Fatal("unrelated-namespace NetworkPolicy blocked simulation", resp.Warnings)
	}
	// One in the flow's destination namespace can, and is not modeled.
	_, err = core.NetworkingV1().NetworkPolicies("database").Create(context.Background(), &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny", Namespace: "database"}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	resp = connectionProbeResponse{}
	s.simulateProbe(context.Background(), rules, candidate, flows, &resp)
	if resp.Simulation != nil || !strings.Contains(strings.Join(resp.Warnings, " "), "NetworkPolicy objects in namespace database") {
		t.Fatal(resp)
	}
	core.PrependReactor("list", "networkpolicies", func(ktesting.Action) (bool, runtime.Object, error) { return true, nil, errors.New("list forbidden") })
	resp = connectionProbeResponse{}
	s.simulateProbe(context.Background(), rules, candidate, flows, &resp)
	if resp.Simulation != nil || !strings.Contains(strings.Join(resp.Warnings, " "), "inventory unavailable") {
		t.Fatal(resp)
	}
	if !hasCIDRGroupRef(map[string]any{"spec": map[string]any{"cidrGroupSelector": map[string]any{}}}) {
		t.Fatal("group selector missed")
	}
}

func TestProbeRawAgentSemanticsSuppressed(t *testing.T) {
	for _, raw := range []string{`{"spec":{"ingress":[{"authentication":{"mode":"required"}}]}}`, `{"spec":{"egress":[{"authentication":{"mode":"test-always-fail"}}]}}`, `{"spec":{"egress":[{"toServices":[{"k8sService":{"serviceName":"db","namespace":"app"}}]}]}}`, `{"spec":{"ingressDeny":[{"toPorts":[{"ports":[{"port":"http","protocol":"TCP"}]}]}]}}`, `{"spec":{"egress":[{"toPorts":[{"ports":[{"port":"https"}]}]}]}}`} {
		if probeRawSemantics([]byte(raw)) == nil {
			t.Fatal("agent semantics accepted", raw)
		}
	}
	if err := probeRawSemantics([]byte(`{"spec":{"ingress":[{"authentication":{"mode":"disabled"},"toPorts":[{"ports":[{"port":"443"}]}]}]}}`)); err != nil {
		t.Fatal(err)
	}
}

func TestProbeIncompleteCaptureSuppressesSimulation(t *testing.T) {
	for _, scenario := range []string{"lost", "overflow", "capture-error"} {
		t.Run(scenario, func(t *testing.T) {
			s, core := testProbeServer(t)
			req := testProbeReq()
			req.CandidateYAML = "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: allow\nspec:\n  endpointSelector: {}\n  ingress:\n    - fromEntities: [all]\n"
			stored := testProbePod()
			s.probes.capture = func(context.Context, *uiServer, connectionProbeRequest) (*probeCapture, error) {
				c := &probeCapture{stop: func() {}}
				if scenario == "overflow" {
					c.overflow = true
				} else {
					c.err = errors.New(scenario)
				}
				return c, nil
			}
			core.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) { return true, stored, nil })
			core.PrependReactor("update", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
				p := a.(ktesting.UpdateAction).GetObject().(*corev1.Pod)
				stored = p.DeepCopy()
				stored.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: p.Spec.EphemeralContainers[0].Name, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Completed", ExitCode: 0}}}}
				return true, p, nil
			})
			w := connectionPOST(s, req)
			var resp connectionProbeResponse
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			if resp.Outcome != "connected" || resp.Simulation != nil || !strings.Contains(strings.Join(resp.Warnings, " "), "Simulation inconclusive: capture") {
				t.Fatal(resp)
			}
		})
	}
}

func TestProbeCancellationStopsCaptureAndReleasesSlot(t *testing.T) {
	s, core := testProbeServer(t)
	stopped := false
	injected := false
	s.probes.capture = func(ctx context.Context, _ *uiServer, _ connectionProbeRequest) (*probeCapture, error) {
		return &probeCapture{stop: func() { stopped = true }}, nil
	}
	core.PrependReactor("update", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
		injected = true
		return true, a.(ktesting.UpdateAction).GetObject(), nil
	})
	body, _ := json.Marshal(testProbeReq())
	r := httptest.NewRequest("POST", "http://127.0.0.1:4747/api/probes/connection", bytes.NewReader(body))
	r.Header.Set("Origin", "http://127.0.0.1:4747")
	r.Header.Set("Content-Type", "application/json")
	ctx, cancel := context.WithCancel(r.Context())
	r = r.WithContext(ctx)
	core.PrependReactor("get", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
		if injected {
			cancel()
		}
		return true, testProbePod(), nil
	})
	w := httptest.NewRecorder()
	s.handleConnectionProbe(w, r)
	if !stopped || len(s.probes.slots) != 0 || len(s.probes.active) != 0 || !strings.Contains(w.Body.String(), "inconclusive") {
		t.Fatal("cancellation leak", w.Body.String())
	}
}
