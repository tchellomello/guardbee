package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

func TestProbeRejectsPreviousPendingContainer(t *testing.T) {
	for _, prefix := range []string{"guardbee-tcp-", "guardbee-connection-"} {
		for _, state := range []corev1.ContainerState{{}, {Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}}, {Running: &corev1.ContainerStateRunning{}}} {
			s, core := testProbeServer(t)
			pod := testProbePod()
			name := prefix + "previous"
			pod.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: name}}}
			pod.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: name, State: state}}
			core.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) { return true, pod.DeepCopy(), nil })
			w := connectionPOST(s, testProbeReq())
			if w.Code != 409 || !strings.Contains(w.Body.String(), name) {
				t.Fatalf("pending attempt not blocked: %d %s", w.Code, w.Body.String())
			}
			noProbeMutation(t, core)
			pod.Status.EphemeralContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{}}
			if pendingProbeContainer(pod) != "" {
				t.Fatal("completed attempt prevents later tests")
			}
		}
	}
}

func TestProbeRechecksPendingContainerBeforeUpdate(t *testing.T) {
	s, core := testProbeServer(t)
	reads := 0
	core.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		reads++
		p := testProbePod()
		if reads > 1 {
			p.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "guardbee-connection-concurrent"}}}
		}
		return true, p, nil
	})
	if w := connectionPOST(s, testProbeReq()); w.Code != 409 {
		t.Fatalf("concurrent pending attempt not blocked: %d", w.Code)
	}
	noProbeMutation(t, core)
}

func TestProbeRuntimeWaitingExplained(t *testing.T) {
	s, core := testProbeServer(t)
	p := testProbePod()
	p.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: "probe", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "ImagePullBackOff"}}}}
	core.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) { return true, p, nil })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := s.waitProbe(ctx, testProbeReq(), "probe")
	if err == nil || !strings.Contains(err.Error(), "ImagePullBackOff") || !strings.Contains(err.Error(), "may still start later") {
		t.Fatalf("missing actionable wait state: %v", err)
	}
}

func TestProbeResultCarriesReviewContext(t *testing.T) {
	s, _ := testProbeServer(t)
	s.target = kubeTarget{context: "alpha-review", apiServer: "https://cluster.example"}
	s.probes.capture = func(context.Context, *uiServer, connectionProbeRequest) (*probeCapture, error) {
		return nil, context.DeadlineExceeded
	}
	w := connectionPOST(s, testProbeReq())
	var result connectionProbeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.UID != "uid-1" || result.Context != "alpha-review" || result.APIServer != "https://cluster.example" || result.Image != testProbeImage || result.DurationMs < 0 {
		t.Fatalf("review context missing: %+v", result)
	}
	if _, err := time.Parse(time.RFC3339Nano, result.StartedAt); err != nil {
		t.Fatal(err)
	}
}

func TestProbeRejectsAmbiguousNumericHosts(t *testing.T) {
	for _, host := range []string{"127.1", "2130706433", "0177.0.0.1", "999.999.999.999"} {
		req := testProbeReq()
		req.Host = host
		if validateConnectionProbe(req) == nil {
			t.Errorf("accepted ambiguous numeric target %s", host)
		}
	}
}

func TestUnavailableProbeRuntimeCannotUseUnrelatedWorkloadTraffic(t *testing.T) {
	s, core := testProbeServer(t)
	req := testProbeReq()
	req.CandidateYAML = "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: test\nspec:\n  endpointSelector: {}\n  ingress:\n    - fromEntities: [all]\n"
	stored := testProbePod()
	capture := &probeCapture{stop: func() {}}
	s.probes.capture = func(context.Context, *uiServer, connectionProbeRequest) (*probeCapture, error) { return capture, nil }
	core.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) { return true, stored.DeepCopy(), nil })
	core.PrependReactor("update", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
		stored = a.(ktesting.UpdateAction).GetObject().(*corev1.Pod).DeepCopy()
		name := stored.Spec.EphemeralContainers[0].Name
		stored.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: name, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Error", ExitCode: 127}}}}
		capture.flows = []*flowpb.Flow{testProbeFlow(time.Now())}
		return true, stored.DeepCopy(), nil
	})
	w := connectionPOST(s, req)
	var response connectionProbeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Simulation != nil || len(response.Flows) != 1 || !strings.Contains(strings.Join(response.Warnings, " "), "runtime could not be verified") {
		t.Fatalf("unavailable runtime misrepresented: %+v", response)
	}
}

func TestCandidateScopeDoesNotDefaultToProbeSource(t *testing.T) {
	s, core := testProbeServer(t)
	empty := ""
	req := testProbeReq()
	req.Protocol = "TCP"
	req.CandidateNamespace = &empty
	req.CandidateYAML = "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: test\nspec:\n  endpointSelector: {}\n  ingress:\n    - fromEntities: [all]\n"
	w := connectionPOST(s, req)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "no metadata.namespace") {
		t.Fatalf("source namespace silently used for candidate: %d %s", w.Code, w.Body.String())
	}
	noProbeMutation(t, core)
	// Namespaced parent scope remains supported without copying it into YAML.
	req.CandidateNamespace = &req.Namespace
	s.probes.capture = func(context.Context, *uiServer, connectionProbeRequest) (*probeCapture, error) {
		return nil, context.DeadlineExceeded
	}
	if w := connectionPOST(s, req); w.Code != 200 {
		t.Fatalf("valid candidate default namespace rejected: %d %s", w.Code, w.Body.String())
	}
	noProbeMutation(t, core)
}

func TestPodInventoryExplainsIneligiblePods(t *testing.T) {
	s, core := testProbeServer(t)
	ready := testProbePod()
	unready := ready.DeepCopy()
	unready.Name = "not-ready"
	unready.Status.Conditions = nil
	busy := ready.DeepCopy()
	busy.Name = "busy"
	busy.Spec.EphemeralContainers = []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "guardbee-connection-pending"}}}
	core.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &corev1.PodList{Items: []corev1.Pod{*ready, *unready, *busy}}, nil
	})
	w := httptest.NewRecorder()
	s.handleProbePods(w, httptest.NewRequest("GET", "/api/probes/pods?namespace=app", nil))
	var out struct {
		Pods []struct {
			Name string `json:"name"`
		} `json:"pods"`
		Excluded map[string]int `json:"excluded"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Pods) != 1 || out.Pods[0].Name != ready.Name || out.Excluded["Pod must be Running, Ready, and not terminating"] != 1 || out.Excluded["A previous GuardBee test is pending or running"] != 1 {
		t.Fatalf("inventory did not explain exclusions: %s", w.Body.String())
	}
}

func TestProbeTaggedImagesAndPullPolicy(t *testing.T) {
	for _, image := range []string{"nicolaka/netshoot:latest", "registry.example:5000/team/probe:v1", "busybox:1.37", testProbeImage} {
		if _, err := newProbeBackend(true, image); err != nil {
			t.Errorf("valid image %q rejected: %v", image, err)
		}
		ec := secureProbeContainer("test", image, testProbeReq())
		want := corev1.PullAlways
		if strings.Contains(image, "@sha256:") {
			want = corev1.PullIfNotPresent
		}
		if ec.ImagePullPolicy != want {
			t.Errorf("%s pull policy: %s", image, ec.ImagePullPolicy)
		}
	}
	for _, image := range []string{"netshoot", "nicolaka/netshoot:", "nicolaka/netshoot:latest --privileged", "https://registry/probe:v1", "r@sha256:no", "r;id:latest", "r:latest\n"} {
		if validProbeImage(image) {
			t.Errorf("invalid image accepted: %q", image)
		}
	}
}
