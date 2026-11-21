package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ktesting "k8s.io/client-go/testing"
)

func probeInjected(s *uiServer) bool {
	for _, a := range s.core.(interface{ Actions() []ktesting.Action }).Actions() {
		if a.GetSubresource() == "ephemeralcontainers" {
			return true
		}
	}
	return false
}

// An external hostname can't be tied to any Hubble flow without DNS
// visibility, so it must be refused before a container is injected rather
// than run into a guaranteed INCONCLUSIVE (www.google.com on a live cluster).
func TestProbeExternalHostnameRejectedBeforeInjection(t *testing.T) {
	for _, host := range []string{"www.google.com", "google.com", "missing", "missing.database"} {
		s, _ := testProbeServer(t)
		req := testProbeReq()
		req.Protocol = "TCP"
		req.Host = host
		w := connectionPOST(s, req)
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "External hostnames") {
			t.Fatalf("%s: got %d %q, want 422 external-host error", host, w.Code, w.Body.String())
		}
		if probeInjected(s) {
			t.Fatalf("%s: container injected for an uncorrelatable host", host)
		}
	}
}

func TestProbeServiceAndIPTargetsStillRun(t *testing.T) {
	for _, host := range []string{"192.0.2.2", "db.database", "db.database.svc.cluster.local"} {
		s, core := testProbeServer(t)
		if _, err := core.CoreV1().Services("database").Create(context.Background(), &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "database"},
			Spec:       corev1.ServiceSpec{ClusterIPs: []string{"10.96.0.10"}, Ports: []corev1.ServicePort{{Port: 443, Protocol: corev1.ProtocolTCP}}},
		}, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
		req := testProbeReq()
		req.Protocol = "TCP"
		req.Host = host
		if w := connectionPOST(s, req); w.Code == http.StatusUnprocessableEntity {
			t.Fatalf("%s rejected: %s", host, w.Body.String())
		}
		if !probeInjected(s) {
			t.Fatalf("%s: probe never ran", host)
		}
	}
}

// A Service-shaped name GuardBee may not read still runs, with the RBAC
// warning: the fix is a grant, and the transport outcome is still useful.
func TestProbeUnreadableServiceStillRunsWithWarning(t *testing.T) {
	s, core := testProbeServer(t)
	core.PrependReactor("get", "services", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, "db", errors.New("rbac"))
	})
	req := testProbeReq()
	req.Protocol = "TCP"
	req.Host = "db.database"
	w := connectionPOST(s, req)
	if w.Code == http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "forbidden") || !probeInjected(s) {
		t.Fatalf("got %d %q, want a run with the forbidden warning", w.Code, w.Body.String())
	}
}

func TestProbeLocalhostRedirectsToListenAddr(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := probeLocalhostRedirect("127.0.0.1:4747", next)
	for _, tt := range []struct {
		method, url, want string
		code              int
	}{
		{"GET", "http://localhost:4747/?tab=verdict", "http://127.0.0.1:4747/?tab=verdict", http.StatusTemporaryRedirect},
		{"GET", "http://LOCALHOST:4747/", "http://127.0.0.1:4747/", http.StatusTemporaryRedirect},
		{"GET", "http://127.0.0.1:4747/", "", http.StatusTeapot},
		{"GET", "http://app.localhost:4747/", "", http.StatusTeapot},
		{"POST", "http://localhost:4747/", "", http.StatusTeapot},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(tt.method, tt.url, nil))
		if w.Code != tt.code || w.Header().Get("Location") != tt.want {
			t.Fatalf("%s %s: got %d %q", tt.method, tt.url, w.Code, w.Header().Get("Location"))
		}
	}
}
