package main

// Exercises handleVerdict's input-validation paths directly, without a live
// cluster — those don't touch s.core/s.cilium/s.cfg at all, so a zero-value
// uiServer is enough. The cluster-dependent path (a real candidate judged
// against real flows) is covered by live curl checks against the real
// cluster instead of a mock here, matching how the rest of this project
// tests (see journal.md) — Kubernetes port-forwarding isn't something a unit
// test can fake without obscuring more than it proves.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleVerdictRejectsMissingCandidateYAML(t *testing.T) {
	srv := &uiServer{logger: slog.Default()}
	body, _ := json.Marshal(verdictRequest{Namespace: "testing"})
	req := httptest.NewRequest(http.MethodPost, "/api/verdict", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	srv.handleVerdict(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a missing candidateYAML, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleVerdictRejectsUnparseableBody(t *testing.T) {
	srv := &uiServer{logger: slog.Default()}
	req := httptest.NewRequest(http.MethodPost, "/api/verdict", bytes.NewReader([]byte("not json")))
	rec := httptest.NewRecorder()

	srv.handleVerdict(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unparseable request body, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandleVerdictRejectsUnsupportedKind(t *testing.T) {
	srv := &uiServer{logger: slog.Default()}
	body, _ := json.Marshal(verdictRequest{Namespace: "testing", CandidateYAML: "kind: Pod\n"})
	req := httptest.NewRequest(http.MethodPost, "/api/verdict", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	srv.handleVerdict(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unsupported kind, got %d: %s", rec.Code, rec.Body.String())
	}
}
