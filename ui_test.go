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

// A scoped egressDeny (toCIDR+toPorts) must parse as valid but be flagged
// Lossy: templatePolicyModel can only hold the empty catchall `- {}`, so
// converting it would silently turn "block one CIDR:443" into "deny all
// egress". The trivial `- {}` form the editor itself emits must NOT be
// flagged, or every round-trip of the editor's own output would break.
func TestHandlePolicyParseFlagsLossyScopedDeny(t *testing.T) {
	srv := &uiServer{logger: slog.Default()}
	parse := func(t *testing.T, y string) policyParseResponse {
		t.Helper()
		body, _ := json.Marshal(policyValidateRequest{Namespace: "default", CandidateYAML: y})
		w := httptest.NewRecorder()
		srv.handlePolicyParse(w, httptest.NewRequest(http.MethodPost, "/api/policy/parse", bytes.NewReader(body)))
		var resp policyParseResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshaling response: %v", err)
		}
		return resp
	}
	const head = "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: p\n  namespace: default\nspec:\n  endpointSelector:\n    matchLabels:\n      run: x\n"

	scoped := parse(t, head+"  egressDeny:\n    - toCIDR:\n        - 98.67.213.35/32\n      toPorts:\n        - ports:\n            - port: \"443\"\n              protocol: TCP\n")
	if !scoped.Valid || !scoped.Lossy {
		t.Fatalf("scoped egressDeny: want valid+lossy, got %+v", scoped)
	}
	catchall := parse(t, head+"  ingressDeny:\n    - {}\n  egressDeny:\n    - {}\n")
	if !catchall.Valid || catchall.Lossy {
		t.Fatalf("catchall deny: want valid, not lossy, got %+v", catchall)
	}
}

// Exact round-trip contract with ui/src/policy.ts's generator: a scoped deny
// fits the editor model only when enableDefaultDeny matches what the
// generator would emit (explicit false for a deny-only direction, nothing
// otherwise). A deny-only policy WITHOUT the opt-out genuinely default-denies
// everything else in Cilium, so regenerating it with the opt-out would
// silently change its meaning — must be flagged lossy.
func TestHandlePolicyParseDenyRoundTripFit(t *testing.T) {
	srv := &uiServer{logger: slog.Default()}
	parse := func(y string) policyParseResponse {
		body, _ := json.Marshal(policyValidateRequest{Namespace: "default", CandidateYAML: y})
		w := httptest.NewRecorder()
		srv.handlePolicyParse(w, httptest.NewRequest(http.MethodPost, "/api/policy/parse", bytes.NewReader(body)))
		var resp policyParseResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshaling response: %v", err)
		}
		return resp
	}
	const head = "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: p\n  namespace: default\nspec:\n  endpointSelector:\n    matchLabels:\n      run: x\n"
	const deny = "  egressDeny:\n    - toCIDR:\n        - 98.67.213.35/32\n      toPorts:\n        - ports:\n            - port: \"443\"\n              protocol: TCP\n"

	// Deny-only + explicit opt-out == exactly what the generator emits.
	fit := parse(head + "  ingressDeny:\n    - {}\n" + deny + "  enableDefaultDeny:\n    egress: false\n")
	if !fit.Valid || fit.Lossy {
		t.Fatalf("deny-only with opt-out: want valid, not lossy, got %+v", fit)
	}
	if fit.Policy == nil || len(fit.Policy.EgressRules) != 1 || !fit.Policy.EgressRules[0].Deny || fit.Policy.EgressDenyAll {
		t.Fatalf("expected one Deny egress rule and no EgressDenyAll, got %+v", fit.Policy)
	}
	if got := fit.Policy.EgressRules[0]; len(got.ToCIDRs) != 1 || got.ToCIDRs[0] != "98.67.213.35/32" || len(got.ToPorts) != 1 || got.ToPorts[0].Port != "443" {
		t.Fatalf("deny rule contents lost: %+v", got)
	}

	// Egress-only (ingress unmanaged) round-trips: the model records
	// IngressUnmanaged so regeneration doesn't add `ingressDeny: - {}`.
	eo := parse(head + deny + "  enableDefaultDeny:\n    egress: false\n")
	if !eo.Valid || eo.Lossy || eo.Policy == nil || !eo.Policy.IngressUnmanaged {
		t.Fatalf("egress-only deny with opt-out: want valid, not lossy, IngressUnmanaged, got %+v", eo)
	}
	// Deny-only WITHOUT the opt-out is real default-deny egress: not representable.
	if r := parse(head + "  ingressDeny:\n    - {}\n" + deny); !r.Valid || !r.Lossy {
		t.Fatalf("deny-only without opt-out: want valid+lossy, got %+v", r)
	}
	// An unrepresentable construct (ICMP deny) must be flagged.
	if r := parse(head + "  ingressDeny:\n    - {}\n  egressDeny:\n    - icmps:\n        - fields:\n            - type: 8\n              family: IPv4\n  enableDefaultDeny:\n    egress: false\n"); !r.Valid || !r.Lossy {
		t.Fatalf("icmp deny: want valid+lossy, got %+v", r)
	}
}
