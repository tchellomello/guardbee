package main

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestHandleServices(t *testing.T) {
	svc := func(ns, name string, port int32) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
			Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: port, Protocol: corev1.ProtocolTCP}}},
		}
	}
	core := fake.NewSimpleClientset(svc("postgres", "postgres", 5432), svc("ai", "ollama", 11434))
	srv := &uiServer{logger: slog.Default(), core: core}
	get := func(q string) (int, []serviceOut) {
		w := httptest.NewRecorder()
		srv.handleServices(w, httptest.NewRequest(http.MethodGet, "/api/services"+q, nil))
		var resp struct {
			Services []serviceOut `json:"services"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp.Services
	}

	if code, got := get("?namespace=ai"); code != 200 || len(got) != 1 || got[0].Name != "ollama" || got[0].Ports[0].Port != 11434 {
		t.Fatalf("one namespace: %d %+v", code, got)
	}
	if code, got := get(""); code != 200 || len(got) != 2 || got[0].Namespace != "ai" {
		t.Fatalf("all namespaces, sorted: %d %+v", code, got)
	}

	// Without "list" on services the UI falls back to flows: a 403, not a 500.
	core.PrependReactor("list", "services", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, "", nil)
	})
	if code, _ := get(""); code != http.StatusForbidden {
		t.Fatalf("forbidden list: want 403, got %d", code)
	}
}
