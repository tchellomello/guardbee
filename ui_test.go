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
	flowpb "github.com/cilium/cilium/api/v1/flow"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestRebindingGuard(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h := rebindingGuard("myhost.lan:4747", ok)
	for host, want := range map[string]int{
		"127.0.0.1:4747":        200,
		"[::1]:4747":            200,
		"192.168.1.5:4747":      200,
		"localhost:5173":        200, // vite dev proxy
		"LOCALHOST":             200,
		"myhost.lan:4747":       200, // the exact --addr
		"evil.example:4747":     403, // rebound DNS name
		"evil.example":          403,
		"localhost.evil:4747":   403,
		"myhost.lan:4748":       403,
		"127.0.0.1.nip.io:4747": 403,
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/policies", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %q: got %d, want %d", host, rec.Code, want)
		}
	}
}

func TestRebindingGuardSecFetchSite(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h := rebindingGuard("127.0.0.1:4747", ok)
	for site, want := range map[string]int{
		"":            200, // curl, scripts, older browsers
		"none":        200, // typed URL / bookmark
		"same-origin": 200, // the UI itself, and the vite dev proxy's forwarded requests
		"cross-site":  403,
		"same-site":   403,
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/flows/stream", nil)
		req.Host = "127.0.0.1:4747"
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Sec-Fetch-Site %q: got %d, want %d", site, rec.Code, want)
		}
	}
}

func TestRebindingGuardSecurityHeaders(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h := rebindingGuard("127.0.0.1:4747", ok)
	for name, mod := range map[string]func(*http.Request){
		"ok":         func(*http.Request) {},
		"cross-site": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"bad host":   func(r *http.Request) { r.Host = "evil.example:4747" },
	} {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "127.0.0.1:4747"
		mod(req)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		for k, v := range map[string]string{
			"X-Frame-Options":         "DENY",
			"Content-Security-Policy": "frame-ancestors 'none'",
			"X-Content-Type-Options":  "nosniff",
		} {
			if got := rec.Header().Get(k); got != v {
				t.Errorf("%s: %s = %q, want %q", name, k, got, v)
			}
		}
	}
}

func TestLoopbackListenAddr(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:4747":   true,
		"127.0.0.2:4747":   true,
		"[::1]:4747":       true,
		"localhost:4747":   true,
		"0.0.0.0:4747":     false,
		":4747":            false,
		"[::]:4747":        false,
		"192.168.1.5:4747": false,
		"myhost.lan:4747":  false,
	} {
		if got := loopbackListenAddr(addr); got != want {
			t.Errorf("%s: got %v, want %v", addr, got, want)
		}
	}
}

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

// L7 rules, toFQDNs and the other port extras have no place in the editor
// model (templatePortRule is port + protocol). Regenerating from it would
// drop an HTTP/DNS rule and silently open the port to every request, so
// they must read as lossy and the editor keeps the user's text.
func TestHandlePolicyParseFlagsLossyL7(t *testing.T) {
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
	const port = "      toPorts:\n        - ports:\n            - port: \"80\"\n              protocol: TCP\n"
	for name, body := range map[string]string{
		"ingress http": "  ingress:\n    - fromEntities: [cluster]\n" + port + "          rules:\n            http:\n              - method: GET\n",
		"egress dns":   "  egress:\n    - toEntities: [cluster]\n      toPorts:\n        - ports:\n            - port: \"53\"\n              protocol: UDP\n          rules:\n            dns:\n              - matchPattern: \"*\"\n",
		"toFQDNs":      "  egress:\n    - toFQDNs:\n        - matchName: api.github.com\n",
		"serverNames":  "  egress:\n    - toEntities: [world]\n      toPorts:\n        - ports:\n            - port: \"443\"\n              protocol: TCP\n          serverNames: [api.github.com]\n",
	} {
		if got := parse(head + body); !got.Valid || !got.Lossy {
			t.Errorf("%s: want valid+lossy, got %+v", name, got)
		}
	}
	if plain := parse(head + "  ingress:\n    - fromEntities: [cluster]\n" + port); !plain.Valid || plain.Lossy {
		t.Errorf("bare ports must still fit the editor: %+v", plain)
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

// A "---"-separated paste holds more than one policy; the editor model holds
// one. It must come back valid but Lossy with the document count, never as a
// plain valid parse of the first policy (which silently dropped the rest).
// An invalid later document must fail the whole paste, as it would in verdict.
func TestHandlePolicyParseMultiDocumentIsLossy(t *testing.T) {
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
	doc := func(name string) string {
		return "apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: " + name +
			"\n  namespace: default\nspec:\n  endpointSelector:\n    matchLabels:\n      app: " + name +
			"\n  ingress:\n    - fromEndpoints:\n        - matchLabels:\n            app: web\n"
	}

	two := parse(doc("first") + "---\n" + doc("second"))
	if !two.Valid || !two.Lossy || two.Documents != 2 || two.Policy == nil || two.Policy.Name != "first" {
		t.Fatalf("two documents: want valid, lossy, documents=2, policy=first; got %+v", two)
	}
	single := parse(doc("only"))
	if !single.Valid || single.Lossy || single.Documents != 0 {
		t.Fatalf("one document: want valid, not lossy, no document count; got %+v", single)
	}
	broken := parse(doc("first") + "---\nkind: CiliumNetworkPolicy\nspec: [\n")
	if broken.Valid {
		t.Fatalf("invalid second document: want invalid, got %+v", broken)
	}
}

// ?client=1 is the header's fast path: binary + pinned version without any
// cluster call. A uiServer with no clients proves it never reaches detection
// (which would dereference them).
func TestHandleVersionClientSkipsCluster(t *testing.T) {
	srv := &uiServer{logger: slog.Default()}
	w := httptest.NewRecorder()
	srv.handleVersion(w, httptest.NewRequest(http.MethodGet, "/api/version?client=1", nil))
	var resp versionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshaling response: %v", err)
	}
	if resp.Binary != version || resp.Pinned != pinnedCiliumVersion || !resp.Unknown {
		t.Fatalf("want binary=%q pinned=%q unknown, got %+v", version, pinnedCiliumVersion, resp)
	}
}

// The web form's filter goes through the same validation as the CLI flags:
// blank fields mean "no filter", enum names are checked, and a pod
// combination that can't match in the namespace is rejected up front.
func TestFlowFilterParams(t *testing.T) {
	f, err := flowFilterParams{FromLabel: []string{" reserved:world ", ""}, Verdict: []string{"DROPPED"}, ToPort: []string{""}}.filter("app")
	if err != nil {
		t.Fatalf("valid params: %v", err)
	}
	if len(f.fromLabels) != 1 || f.fromLabels[0] != "reserved:world" || len(f.toPorts) != 0 || len(f.verdicts) != 1 {
		t.Fatalf("got %+v", f)
	}
	if _, err := (flowFilterParams{Verdict: []string{"nope"}}).filter("app"); err == nil {
		t.Error("invalid verdict: want an error")
	}
	if _, err := (flowFilterParams{FromPod: []string{"x/a"}, ToPod: []string{"y/b"}}).filter("app"); err == nil {
		t.Error("both pods outside the namespace: want an error")
	}
	if _, err := (flowFilterParams{Type: []string{"policy_verdict"}}).filter("app"); err == nil {
		t.Error("invalid type: want an error")
	}
	q, _ := url.ParseQuery("namespace=app&fromIp=10.0.0.0/8&dropReason=POLICY_DENIED&toPod=db&pod=web&type=policy-verdict")
	got := flowFilterParamsFromQuery(q)
	if got.FromIP[0] != "10.0.0.0/8" || got.DropReason[0] != "POLICY_DENIED" || got.ToPod[0] != "db" || got.Pod[0] != "web" || got.Type[0] != "policy-verdict" {
		t.Fatalf("from query: %+v", got)
	}
	f, err = got.filter("app")
	if err != nil || f.pods[0] != "web" || f.types[0] != "policy-verdict" {
		t.Fatalf("pod/type not carried into the filter: %+v, %v", f, err)
	}
}

func TestFlowFilterParamsL7(t *testing.T) {
	q, _ := url.ParseQuery("httpMethod=GET&httpPath=/metrics&httpStatus=403&toFqdn=api.github.com")
	f, err := flowFilterParamsFromQuery(q).filter("app")
	if err != nil {
		t.Fatal(err)
	}
	if f.httpMethods[0] != "GET" || f.httpPaths[0] != "/metrics" || f.httpStatuses[0] != "403" || f.toFQDNs[0] != "api.github.com" {
		t.Fatalf("L7 params not carried into the filter: %+v", f)
	}
}

func TestHandleFlowFilterOptions(t *testing.T) {
	srv := &uiServer{logger: slog.Default()}
	w := httptest.NewRecorder()
	srv.handleFlowFilterOptions(w, httptest.NewRequest(http.MethodGet, "/api/flow-filter-options", nil))
	var resp flowFilterOptions
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}
	if !slices.Contains(resp.Verdicts, "DROPPED") || slices.Contains(resp.Verdicts, "VERDICT_UNKNOWN") {
		t.Errorf("verdicts: %v", resp.Verdicts)
	}
	if !slices.Contains(resp.DropReasons, "POLICY_DENIED") || slices.Contains(resp.DropReasons, "DROP_REASON_UNKNOWN") {
		t.Errorf("drop reasons missing POLICY_DENIED or include UNKNOWN (%d values)", len(resp.DropReasons))
	}
	if !slices.Contains(resp.EventTypes, "policy-verdict") {
		t.Errorf("event types: %v", resp.EventTypes)
	}
}

// Flow rows carry each endpoint's identity labels, which the filter fields'
// autocomplete offers for --from-label/--to-label.
func TestToFlowOutCarriesLabels(t *testing.T) {
	out := toFlowOut(&flowpb.Flow{
		Source:      &flowpb.Endpoint{Labels: []string{"reserved:world"}},
		Destination: &flowpb.Endpoint{Namespace: "app", PodName: "db-0", Labels: []string{"k8s:app=db"}},
	})
	if !slices.Equal(out.SourceLabels, []string{"reserved:world"}) || !slices.Equal(out.DestinationLabels, []string{"k8s:app=db"}) {
		t.Fatalf("labels not passed through: %+v", out)
	}
}

// The Flows tab's rows carry the same attribution blame prints, under the
// JSON names the UI reads.
func TestToFlowOutCarriesAttribution(t *testing.T) {
	out := toFlowOut(&flowpb.Flow{
		Verdict:          flowpb.Verdict_FORWARDED,
		TrafficDirection: flowpb.TrafficDirection_INGRESS,
		EventType:        policyVerdictEvent,
		IngressAllowedBy: []*flowpb.Policy{cnp("app", "allow-web")},
	})
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"direction":"INGRESS"`, `"decision":"allowed"`, `"decidedBy":"allowed by CNP:app/allow-web"`, `"allowedBy":[{"kind":"CiliumNetworkPolicy","namespace":"app","name":"allow-web"`, `"display":"CNP:app/allow-web"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("JSON missing %s:\n%s", want, b)
		}
	}
}
