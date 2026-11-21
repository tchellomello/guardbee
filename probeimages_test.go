package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

// The built-in catalog is what ships: every entry must load, be pinned by
// digest (tags are re-pulled on every test), and declare only protocols it
// was vetted for.
func TestBuiltinProbeImagesPinnedAndValid(t *testing.T) {
	images, err := loadProbeImages("")
	if err != nil {
		t.Fatal(err)
	}
	if len(images) < 2 {
		t.Fatalf("built-in catalog has %d images", len(images))
	}
	for _, img := range images {
		if !img.pinned() {
			t.Errorf("built-in image %s is not digest-pinned: %s", img.ID, img.Image)
		}
	}
	busybox := images[1]
	if busybox.ID != "busybox" || busybox.supports("UDP") || !busybox.supports("TCP") {
		t.Fatalf("busybox has no Python 3; it must be TCP-only: %+v", busybox)
	}
}

func TestProbeImageCatalogValidation(t *testing.T) {
	const good = "docker.io/library/busybox:1.37"
	for name, doc := range map[string]string{
		"empty":            "images: []",
		"unknown field":    "images: [{id: a, name: A, image: " + good + ", protocols: [TCP], protocol: UDP}]",
		"bad id":           "images: [{id: A_B, name: A, image: " + good + ", protocols: [TCP]}]",
		"duplicate id":     "images: [{id: a, name: A, image: " + good + ", protocols: [TCP]}, {id: a, name: B, image: " + good + ", protocols: [TCP]}]",
		"no name":          "images: [{id: a, name: ' ', image: " + good + ", protocols: [TCP]}]",
		"untagged image":   "images: [{id: a, name: A, image: busybox, protocols: [TCP]}]",
		"option as image":  "images: [{id: a, name: A, image: '--privileged', protocols: [TCP]}]",
		"no protocols":     "images: [{id: a, name: A, image: " + good + "}]",
		"unknown protocol": "images: [{id: a, name: A, image: " + good + ", protocols: [SCTP]}]",
		"repeat protocol":  "images: [{id: a, name: A, image: " + good + ", protocols: [TCP, TCP]}]",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "images.yaml")
			if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadProbeImages(path); err == nil {
				t.Fatal("invalid catalog accepted")
			}
		})
	}
	path := filepath.Join(t.TempDir(), "images.json")
	if err := os.WriteFile(path, []byte(`{"images":[{"id":"mirror","name":"Mirror","image":"registry.corp/netshoot:v1","protocols":["TCP","UDP"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	images, err := loadProbeImages(path)
	if err != nil || len(images) != 1 || images[0].pinned() {
		t.Fatalf("JSON catalog with a tag-only image not loaded: %+v %v", images, err)
	}
}

func TestProbeImageFlags(t *testing.T) {
	if b, err := newProbeBackendFromFlags(false, "", ""); b != nil || err != nil {
		t.Fatal("probes enabled without --enable-probes")
	}
	if _, err := newProbeBackendFromFlags(false, testProbeImage, ""); err == nil {
		t.Fatal("--probe-image without --enable-probes silently ignored")
	}
	if _, err := newProbeBackendFromFlags(true, testProbeImage, "x.yaml"); err == nil {
		t.Fatal("both image flags accepted")
	}
	b, err := newProbeBackendFromFlags(true, "", "")
	if err != nil || len(b.images) < 2 {
		t.Fatal("built-in catalog not the default", err)
	}
	b, err = newProbeBackendFromFlags(true, testProbeImage, "")
	if err != nil || len(b.images) != 1 || b.images[0].Image != testProbeImage || b.images[0].Name != "probe" {
		t.Fatalf("--probe-image is not a one-image catalog: %+v %v", b, err)
	}
}

// The browser names a catalog entry; it can never supply the image itself,
// and an entry is only offered for the protocols it supports.
func TestProbeRequestPicksCatalogImageByID(t *testing.T) {
	s, core := testProbeServer(t)
	s.probes.images = []probeImage{
		{ID: "full", Name: "Full", Image: testProbeImage, Protocols: []string{"TCP", "UDP"}},
		{ID: "tcp-only", Name: "TCP only", Image: "registry.example/tcp:1", Protocols: []string{"TCP"}},
	}
	req := testProbeReq()
	req.Protocol = "UDP"
	req.ImageID = "tcp-only"
	if w := connectionPOST(s, req); w.Code != 400 || !strings.Contains(w.Body.String(), "does not support UDP") {
		t.Fatal("UDP ran on a TCP-only image", w.Code, w.Body.String())
	}
	req.ImageID = "registry.evil/x:1"
	if w := connectionPOST(s, req); w.Code != 400 {
		t.Fatal("free-form image accepted as an id", w.Code)
	}
	noProbeMutation(t, core)

	// A raw "image" field is an unknown field, never an override.
	body := `{"namespace":"app","pod":"client","uid":"uid-1","host":"192.0.2.2","port":443,"protocol":"TCP","image":"registry.evil/x:1"}`
	r := httptest.NewRequest("POST", "http://127.0.0.1:4747/api/probes/connection", strings.NewReader(body))
	r.Header.Set("Origin", "http://127.0.0.1:4747")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleConnectionProbe(w, r)
	if w.Code != 400 {
		t.Fatal("request-supplied image not rejected", w.Code)
	}

	var injected string
	stored := testProbePod()
	core.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) { return true, stored.DeepCopy(), nil })
	core.PrependReactor("update", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
		p := a.(ktesting.UpdateAction).GetObject().(*corev1.Pod)
		ec := p.Spec.EphemeralContainers[0]
		injected = ec.Image
		stored = p.DeepCopy()
		stored.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: ec.Name, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Completed"}}}}
		return true, p, nil
	})
	req = testProbeReq()
	req.Protocol = "TCP"
	req.ImageID = "tcp-only"
	w = connectionPOST(s, req)
	var resp connectionProbeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if injected != "registry.example/tcp:1" || resp.Image != injected || resp.ImageID != "tcp-only" {
		t.Fatalf("picked image not injected/reported: injected %q resp %q/%q", injected, resp.Image, resp.ImageID)
	}
}

func TestProbeCapabilitiesListCatalog(t *testing.T) {
	s, _ := testProbeServer(t)
	s.probes.images = []probeImage{{ID: "a", Name: "A", Image: testProbeImage, Protocols: []string{"TCP"}}, {ID: "b", Name: "B", Image: "registry.example/b:1", Protocols: []string{"TCP", "UDP"}}}
	w := httptest.NewRecorder()
	s.handleProbeCapabilities(w, httptest.NewRequest("GET", "/", nil))
	var got struct {
		Image  string
		Images []struct {
			ID        string
			Protocols []string
			Pinned    bool
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Image != testProbeImage || len(got.Images) != 2 || !got.Images[0].Pinned || got.Images[1].Pinned || !reflect.DeepEqual(got.Images[1].Protocols, []string{"TCP", "UDP"}) {
		t.Fatalf("catalog not exposed: %+v", got)
	}
}

func streamPOST(s *uiServer, req connectionProbeRequest) (*httptest.ResponseRecorder, []map[string]json.RawMessage) {
	if req.Protocol == "" {
		req.Protocol = "TCP"
	}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "http://127.0.0.1:4747/api/probes/connection/stream", bytes.NewReader(body))
	r.Header.Set("Origin", "http://127.0.0.1:4747")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.handleConnectionProbeStream(w, r)
	var lines []map[string]json.RawMessage
	sc := bufio.NewScanner(bytes.NewReader(w.Body.Bytes()))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var m map[string]json.RawMessage
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			lines = append(lines, m)
		}
	}
	return w, lines
}

func TestProbeStreamReportsStagesThenOneResult(t *testing.T) {
	s, core := testProbeServer(t)
	stored := testProbePod()
	core.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) { return true, stored.DeepCopy(), nil })
	core.PrependReactor("update", "pods", func(a ktesting.Action) (bool, runtime.Object, error) {
		p := a.(ktesting.UpdateAction).GetObject().(*corev1.Pod)
		stored = p.DeepCopy()
		stored.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: p.Spec.EphemeralContainers[0].Name, State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Completed"}}}}
		return true, p, nil
	})
	w, lines := streamPOST(s, testProbeReq())
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Fatal(w.Code, w.Header())
	}
	var stages []string
	for _, l := range lines[:len(lines)-1] {
		var stage string
		if json.Unmarshal(l["stage"], &stage) != nil {
			t.Fatalf("non-stage line before the end: %v", l)
		}
		stages = append(stages, stage)
	}
	if want := []string{"authorize", "capture", "inject", "run", "collect"}; !reflect.DeepEqual(stages, want) {
		t.Fatalf("stages %v, want %v", stages, want)
	}
	var resp connectionProbeResponse
	if err := json.Unmarshal(lines[len(lines)-1]["result"], &resp); err != nil || resp.Outcome != "connected" {
		t.Fatalf("no terminal result: %s %v", lines[len(lines)-1]["result"], err)
	}
}

func TestProbeStreamErrors(t *testing.T) {
	// Rejected before anything happens: an ordinary HTTP status, no stream.
	s, _ := testProbeServer(t)
	req := testProbeReq()
	req.Port = 0
	if w, _ := streamPOST(s, req); w.Code != 400 || w.Header().Get("Content-Type") == "application/x-ndjson" {
		t.Fatal("validation error streamed", w.Code)
	}
	// Rejected after the stream began: a terminal error line with the status
	// the non-streaming endpoint would have used.
	s, core := testProbeServer(t)
	changed := testProbePod()
	changed.UID = "uid-replaced"
	core.PrependReactor("get", "pods", func(ktesting.Action) (bool, runtime.Object, error) { return true, changed, nil })
	w, lines := streamPOST(s, testProbeReq())
	last := lines[len(lines)-1]
	var status int
	if w.Code != 200 || json.Unmarshal(last["status"], &status) != nil || status != 409 || last["error"] == nil {
		t.Fatalf("mid-stream rejection lost its status: %d %v", w.Code, last)
	}
	noProbeMutation(t, core)
}
