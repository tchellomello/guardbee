package main

// Milestone 1 of the web UI (see Obsidian
// projects/cilium-network-policy-editor/design-2026-10-12.md): a local HTTP
// server exposing the same flows/verdict capability as the "flows"/"verdict"
// subcommands over a small JSON API, for a browser frontend instead of
// terminal output. No new cluster footprint — same kubeconfig-based access
// as every other subcommand, and the JSON responses are built from the exact
// same computeVerdict/fetchFlows functions the CLI itself calls, never a
// parallel implementation (see verdict.go's verdictComputation doc comment).
//
// Candidate authoring (milestone 2) is explicitly out of scope here — this
// only ever reads an already-written candidate (pasted as YAML text) and
// reports its effect, same as "verdict" does today.

import (
	"encoding/json"
	"fmt"
	iofs "io/fs"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	ciliumclient "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func runUI(args []string) {
	fs := pflag.NewFlagSet("ui", pflag.ExitOnError)
	// Deliberately not registerCommonFlags: unlike every other subcommand,
	// "ui" has no --namespace/--all-namespaces of its own — the namespace
	// scope is chosen per-request in the browser (see NamespaceScope.tsx),
	// not once at server startup. Registering those flags here would accept
	// them silently without them doing anything.
	var kubeconfig, addr, templatesDir string
	fs.StringVar(&kubeconfig, "kubeconfig", "", "path to kubeconfig (default: KUBECONFIG env or ~/.kube/config)")
	fs.StringVar(&addr, "addr", "127.0.0.1:4747", "address to listen on")
	fs.StringVar(&templatesDir, "templates-dir", "", "directory of generic/ingress/egress CiliumNetworkPolicy YAML presets (default: built-in templates/)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %[1]s ui [--addr host:port] [--templates-dir path]

Starts a local web UI at the given address: the same flows/verdict
capability as the "flows" and "verdict" subcommands, in a browser instead of
a terminal. Uses the same kubeconfig-based cluster access as every other
subcommand — no new cluster footprint, no remote hosting, no auth (that's a
stated future direction once this is proven locally, not this milestone).
Namespace scope (one namespace, or all) is chosen per-request in the
browser, not as a flag here.

Policy Editor presets (Blank/Default-deny/etc. starting policies, and the
per-rule "Web", "DNS", etc. buttons) are loaded from a directory of real
CiliumNetworkPolicy YAML under generic/, ingress/, egress/ subdirectories —
--templates-dir points at an external one; omitted, the binary's own
built-in defaults are used.

Flags:
`, binName)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n  %[1]s ui\n  %[1]s ui --addr 127.0.0.1:9000\n  %[1]s ui --templates-dir ./my-presets\n", binName)
	}
	_ = fs.Parse(args)

	core, cilium, cfg, err := newClientsets(kubeconfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" ui: building clients: %v\n", err)
		os.Exit(1)
	}

	logger := slog.Default()
	tFS, err := templatesFS(templatesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" ui: --templates-dir: %v\n", err)
		os.Exit(1)
	}
	templates := loadTemplates(logger, tFS)
	logger.Info("loaded policy editor templates",
		"generic", len(templates.Generic), "ingress", len(templates.Ingress), "egress", len(templates.Egress))

	srv := &uiServer{core: core, cilium: cilium, cfg: cfg, logger: logger, templates: templates}

	static, err := iofs.Sub(uiAssets, "ui/dist")
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" ui: embedded frontend assets: %v\n", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/verdict", srv.handleVerdict)
	mux.HandleFunc("GET /api/verdict/stream", srv.handleVerdictStream)
	mux.HandleFunc("GET /api/flows", srv.handleFlows)
	mux.HandleFunc("GET /api/namespaces", srv.handleNamespaces)
	mux.HandleFunc("GET /api/pods", srv.handlePods)
	mux.HandleFunc("GET /api/policies", srv.handlePolicies)
	mux.HandleFunc("GET /api/policies/edit", srv.handlePolicyForEdit)
	mux.HandleFunc("POST /api/policy/validate", srv.handlePolicyValidate)
	mux.HandleFunc("POST /api/policy/parse", srv.handlePolicyParse)
	mux.HandleFunc("GET /api/templates", srv.handleTemplates)
	mux.HandleFunc("GET /api/version", srv.handleVersion)
	mux.Handle("/", http.FileServerFS(static))

	fmt.Printf("%s ui: listening on http://%s\n", binName, addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, binName+" ui: %v\n", err)
		os.Exit(1)
	}
}

// uiServer holds the clientsets built once at startup, reused by every
// request handler — the same clients newClientsets gives every other
// subcommand, just long-lived instead of built-and-discarded per CLI
// invocation.
type uiServer struct {
	core      kubernetes.Interface
	cilium    ciliumclient.Interface
	cfg       *rest.Config
	logger    *slog.Logger
	templates templatesResponse
}

// handleTemplates serves the Policy Editor's preset templates (see
// templates.go), loaded once at startup from --templates-dir or the
// binary's built-in defaults.
func (s *uiServer) handleTemplates(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.templates)
}

// versionResponse backs GET /api/version — the UI's counterpart to the CLI's
// Phase 1 stderr skew warning (see clusterversion.go's warnOnVersionSkew),
// shaped for the persistent banner component (VersionBanner.tsx) rather than
// a one-line stderr print. Unknown is true whenever hubble was unreachable
// or every node's version was unparseable — the banner renders nothing in
// that case, same as the CLI prints nothing.
type versionResponse struct {
	Pinned       string   `json:"pinned"`
	Detected     string   `json:"detected,omitempty"`
	Skewed       bool     `json:"skewed"`
	NodeSkew     bool     `json:"nodeSkew"`
	NodeVersions []string `json:"nodeVersions,omitempty"`
	Unknown      bool     `json:"unknown"`
}

func (s *uiServer) handleVersion(w http.ResponseWriter, r *http.Request) {
	status := detectClusterCiliumVersion(r.Context(), s.core, s.cfg)
	resp := versionResponse{
		Pinned:       pinnedCiliumVersion,
		Detected:     status.detected,
		Skewed:       status.state == clusterVersionSkewed,
		NodeSkew:     status.state == clusterVersionNodeSkew,
		NodeVersions: status.nodeVersions,
		Unknown:      status.state == clusterVersionUnknown,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// verdictRequest is the "ui" subcommand's JSON request body for POST
// /api/verdict, mirroring the "verdict" subcommand's own flags/argument:
// Namespace "" means cluster-wide (same as omitting --namespace or passing
// --all-namespaces), CandidateYAML is the candidate CNP/CCNP as pasted text
// (not a file path — the web form has no filesystem access to the user's
// machine the way the CLI does).
type verdictRequest struct {
	Namespace     string `json:"namespace"`
	CandidateYAML string `json:"candidateYAML"`
	Last          uint64 `json:"last"`
	ShowUnchanged bool   `json:"showUnchanged"`
}

// verdictCountsOut/verdictRowOut/verdictResponse are JSON-friendly mirrors
// of verdict.go's unexported verdictCounts/verdictRow/verdictComputation
// (encoding/json only marshals exported fields) — built by handleVerdict
// from the exact same verdictComputation the CLI prints, never recomputed
// independently.
type verdictCountsOut struct {
	Unchanged    int `json:"unchanged"`
	NewlyDropped int `json:"newlyDropped"`
	NewlyAllowed int `json:"newlyAllowed"`
	NotSimulated int `json:"notSimulated"`
	ReplySkipped int `json:"replySkipped"`
	Total        int `json:"total"`
}

type verdictRowOut struct {
	Change      string `json:"change"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Port        uint16 `json:"port"`
	Count       int    `json:"count"`
	Explanation string `json:"explanation"`
}

type verdictResponse struct {
	Namespace          string           `json:"namespace"`
	CandidateRuleCount int              `json:"candidateRuleCount"`
	BaselineRuleCount  int              `json:"baselineRuleCount"`
	FlowsRequested     uint64           `json:"flowsRequested"`
	FlowsSampled       int              `json:"flowsSampled"`
	Counts             verdictCountsOut `json:"counts"`
	Rows               []verdictRowOut  `json:"rows"`
}

func (s *uiServer) handleVerdict(w http.ResponseWriter, r *http.Request) {
	var req verdictRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("decoding request: %v", err), http.StatusBadRequest)
		return
	}
	if req.Last == 0 {
		req.Last = 50
	}
	if req.CandidateYAML == "" {
		http.Error(w, "candidateYAML is required", http.StatusBadRequest)
		return
	}

	candidateRules, err := parseCandidateYAML(s.logger, []byte(req.CandidateYAML), req.Namespace)
	if err != nil {
		http.Error(w, fmt.Sprintf("parsing candidate: %v", err), http.StatusBadRequest)
		return
	}

	comp, err := computeVerdict(s.logger, s.core, s.cilium, s.cfg, req.Namespace, candidateRules, req.Last, req.ShowUnchanged)
	if err != nil {
		http.Error(w, fmt.Sprintf("computing verdict: %v", err), http.StatusInternalServerError)
		return
	}

	resp := verdictResponse{
		Namespace:          comp.namespace,
		CandidateRuleCount: comp.candidateRuleCount,
		BaselineRuleCount:  comp.baselineRuleCount,
		FlowsRequested:     comp.flowsRequested,
		FlowsSampled:       comp.flowsSampled,
		Counts:             toCountsOut(comp.counts),
		Rows:               make([]verdictRowOut, len(comp.rows)),
	}
	for i, row := range comp.rows {
		resp.Rows[i] = toRowOut(row, comp.rowCounts[i])
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// toCountsOut/toRowOut convert the internal verdictCounts/verdictRow into
// their JSON-friendly mirrors — shared by handleVerdict (one JSON response)
// and handleVerdictStream (one SSE event per judged flow), so both encode
// the exact same shape.
func toCountsOut(c *verdictCounts) verdictCountsOut {
	return verdictCountsOut{
		Unchanged:    c.unchanged,
		NewlyDropped: c.newlyDropped,
		NewlyAllowed: c.newlyAllowed,
		NotSimulated: c.notSimulated,
		ReplySkipped: c.replySkipped,
		Total:        c.total,
	}
}

func toRowOut(row *verdictRow, count int) verdictRowOut {
	return verdictRowOut{
		Change:      row.change,
		Source:      row.src,
		Destination: row.dst,
		Protocol:    row.proto,
		Port:        row.port,
		Count:       count,
		Explanation: changeExplanation(row.change),
	}
}

// verdictStreamEvent is one Server-Sent Event payload for GET
// /api/verdict/stream — the browser equivalent of "verdict --follow".
// Row is set only when this judged flow produced a reportable change
// (same rule as judgeFlow/--show-unchanged); Counts is the running tally
// sent with every event, so the UI's summary badges stay live even for
// flows that never produce a visible row (UNCHANGED without
// show-unchanged, not-simulated, reply-skipped).
type verdictStreamEvent struct {
	Row    *verdictRowOut   `json:"row,omitempty"`
	Counts verdictCountsOut `json:"counts"`
}

// handleVerdictStream is the streaming counterpart to handleVerdict — same
// judging logic (judgeFlow via the shared baseline/candidate engines from
// buildVerdictEngines), but pushed live over Server-Sent Events as flows
// arrive instead of computed once over a bounded batch. GET + query params
// (not POST + JSON body) because EventSource, the browser API this is built
// for, only supports GET. Stops when the client disconnects (r.Context()
// cancels) — the same "caller owns why we stopped" contract streamFlows
// documents, just a different caller than the CLI's Ctrl+C.
func (s *uiServer) handleVerdictStream(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	namespace := q.Get("namespace")
	candidateYAML := q.Get("candidateYAML")
	showUnchanged := q.Get("showUnchanged") == "true"
	last := uint64(50)
	if v := q.Get("last"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			last = n
		}
	}
	if candidateYAML == "" {
		http.Error(w, "candidateYAML is required", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported by this response writer", http.StatusInternalServerError)
		return
	}

	candidateRules, err := parseCandidateYAML(s.logger, []byte(candidateYAML), namespace)
	if err != nil {
		http.Error(w, fmt.Sprintf("parsing candidate: %v", err), http.StatusBadRequest)
		return
	}

	_, baseline, candidate, err := buildVerdictEngines(s.logger, s.cilium, namespace, candidateRules)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer baseline.close(s.logger)
	defer candidate.close(s.logger)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	counts := &verdictCounts{}
	_, streamErr := streamFlows(r.Context(), s.core, s.cfg, namespace, last, func(f *flowpb.Flow) {
		row := judgeFlow(s.logger, baseline, candidate, f, counts, showUnchanged)
		event := verdictStreamEvent{Counts: toCountsOut(counts)}
		if row != nil {
			out := toRowOut(row, 1)
			event.Row = &out
		}
		data, err := json.Marshal(event)
		if err != nil {
			return
		}
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	})
	// A canceled context (client disconnected, the normal way this ends) is
	// not an error worth logging; anything else is a real stream failure,
	// but the response is already committed (SSE headers sent) so the only
	// thing left to do is stop — there's no clean way to report an error to
	// an EventSource mid-stream beyond just closing the connection.
	if streamErr != nil && r.Context().Err() == nil {
		s.logger.Error("verdict stream ended with an error", "error", streamErr)
	}
}

// flowOut/flowsResponse are the JSON mirror of the "flows" subcommand's own
// printed rows (see flows.go's runFlows print closure) — same fields, plus
// DropReason (the CLI's terminal line has no room for it, but a browser
// table column does). This is Hubble's own already-happened verdict on a
// DROPPED flow, straight off the datapath — not this tool's simulated one —
// so it's squarely in-bounds despite "only ingress is simulated" (see
// AGENTS.md's known v1 simplifications): nothing here is being guessed.
type flowOut struct {
	Time        string `json:"time"`
	Verdict     string `json:"verdict"`
	DropReason  string `json:"dropReason,omitempty"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	L4          string `json:"l4"`
}

type flowsResponse struct {
	Namespace string    `json:"namespace"`
	Flows     []flowOut `json:"flows"`
}

func (s *uiServer) handleFlows(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	last := uint64(50)
	if v := r.URL.Query().Get("last"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			last = n
		}
	}

	flows, err := fetchFlows(s.core, s.cfg, namespace, last)
	if err != nil {
		http.Error(w, fmt.Sprintf("tapping flows: %v", err), http.StatusInternalServerError)
		return
	}

	resp := flowsResponse{Namespace: namespace, Flows: make([]flowOut, len(flows))}
	for i, f := range flows {
		out := flowOut{
			Time:        f.GetTime().AsTime().Format(time.RFC3339),
			Verdict:     f.GetVerdict().String(),
			Source:      endpointString(f.GetSource()),
			Destination: endpointString(f.GetDestination()),
			L4:          l4String(f.GetL4()),
		}
		// Only meaningful on a dropped flow — DROP_REASON_UNKNOWN on every
		// forwarded one would just be noise in the table.
		if reason := f.GetDropReasonDesc(); reason != flowpb.DropReason_DROP_REASON_UNKNOWN {
			out.DropReason = reason.String()
		}
		resp.Flows[i] = out
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// policyOut/policiesResponse back GET /api/policies — the live
// CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy state for a namespace
// (or every namespace), the same read the "policies" CLI subcommand does
// (policies.go's runPolicies), shaped for a browser table. Before this, the
// web UI's only signal of "what's actually running" was an opaque
// baselineRuleCount number buried inside a Verdict run — this is the one
// real CLI/UI parity gap, closed by reusing listPolicySummaries rather than
// querying the clientset a second, separate way.
type policyOut struct {
	Kind             string `json:"kind"`
	Name             string `json:"name"`
	Namespace        string `json:"namespace,omitempty"`
	Description      string `json:"description,omitempty"`
	IngressRuleCount int    `json:"ingressRuleCount"`
	EgressRuleCount  int    `json:"egressRuleCount"`
}

type policiesResponse struct {
	Namespace string      `json:"namespace"`
	Policies  []policyOut `json:"policies"`
}

func (s *uiServer) handlePolicies(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")

	summaries, err := listPolicySummaries(r.Context(), s.cilium, namespace)
	if err != nil {
		http.Error(w, fmt.Sprintf("listing policies: %v", err), http.StatusInternalServerError)
		return
	}

	resp := policiesResponse{Namespace: namespace, Policies: make([]policyOut, len(summaries))}
	for i, p := range summaries {
		resp.Policies[i] = policyOut{
			Kind:             p.Kind,
			Name:             p.Name,
			Namespace:        p.Namespace,
			Description:      p.Description,
			IngressRuleCount: p.IngressRuleCount,
			EgressRuleCount:  p.EgressRuleCount,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handlePolicyForEdit backs GET /api/policies/edit?kind=&name=&namespace= —
// "Edit in Policy Editor" from the Policies tab: fetches one live CNP/CCNP
// and converts it into the same templatePolicyModel JSON shape a generic
// template already uses (see templates.go's convertRuleToPolicyModel), so
// the frontend's existing "load a preset" code path (PolicyEditorPanel.tsx's
// handleLoadPreset) handles it with no new parsing logic. Known v1
// simplification: only the first entry of a multi-spec policy's Specs list
// loads (see policies.go's firstRuleSpec); a non-trivial IngressDeny/
// EgressDeny beyond the trivial all-deny `- {}` this editor itself ever
// generates is also not reconstructed — same limit the editor already has
// when authoring from scratch, not a new one introduced here.
func (s *uiServer) handlePolicyForEdit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	kind := q.Get("kind")
	name := q.Get("name")
	namespace := q.Get("namespace")
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	var model templatePolicyModel
	switch kind {
	case "CiliumNetworkPolicy":
		if namespace == "" {
			http.Error(w, "namespace is required for a CiliumNetworkPolicy", http.StatusBadRequest)
			return
		}
		cnp, err := s.cilium.CiliumV2().CiliumNetworkPolicies(namespace).Get(r.Context(), name, metav1.GetOptions{})
		if err != nil {
			http.Error(w, fmt.Sprintf("fetching CiliumNetworkPolicy %s/%s: %v", namespace, name, err), http.StatusInternalServerError)
			return
		}
		rule := firstRuleSpec(cnp.Spec, cnp.Specs)
		if rule == nil {
			http.Error(w, fmt.Sprintf("CiliumNetworkPolicy %s/%s has no rule spec", namespace, name), http.StatusInternalServerError)
			return
		}
		model = convertRuleToPolicyModel(kind, cnp.Name, cnp.Namespace, rule)
	case "CiliumClusterwideNetworkPolicy":
		ccnp, err := s.cilium.CiliumV2().CiliumClusterwideNetworkPolicies().Get(r.Context(), name, metav1.GetOptions{})
		if err != nil {
			http.Error(w, fmt.Sprintf("fetching CiliumClusterwideNetworkPolicy %s: %v", name, err), http.StatusInternalServerError)
			return
		}
		rule := firstRuleSpec(ccnp.Spec, ccnp.Specs)
		if rule == nil {
			http.Error(w, fmt.Sprintf("CiliumClusterwideNetworkPolicy %s has no rule spec", name), http.StatusInternalServerError)
			return
		}
		model = convertRuleToPolicyModel(kind, ccnp.Name, "", rule)
	default:
		http.Error(w, fmt.Sprintf("unsupported kind %q", kind), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(model)
}

// namespacesResponse backs GET /api/namespaces — real namespace names for
// the frontend's namespace field autocomplete (NamespaceScope.tsx). The
// scoped RBAC ClusterRole already grants list on namespaces (it's needed
// for "ui"'s own cluster access to work at all, same as every other
// subcommand), so this needs no new permission.
type namespacesResponse struct {
	Namespaces []string `json:"namespaces"`
}

func (s *uiServer) handleNamespaces(w http.ResponseWriter, r *http.Request) {
	list, err := s.core.CoreV1().Namespaces().List(r.Context(), metav1.ListOptions{})
	if err != nil {
		http.Error(w, fmt.Sprintf("listing namespaces: %v", err), http.StatusInternalServerError)
		return
	}
	names := make([]string, len(list.Items))
	for i, ns := range list.Items {
		names[i] = ns.Name
	}
	sort.Strings(names)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(namespacesResponse{Namespaces: names})
}

// podOut/podsResponse back GET /api/pods — real pod names and their live
// labels for a namespace, used by the Policy Editor's topology graph to show
// which actual cluster pods a candidate endpointSelector/fromEndpoints rule
// would match (PolicyGraph.tsx's selected-node detail panel), the same
// "ground truth over guesswork" principle as namespace autocomplete.
type podOut struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

type podsResponse struct {
	Namespace string   `json:"namespace"`
	Pods      []podOut `json:"pods"`
}

func (s *uiServer) handlePods(w http.ResponseWriter, r *http.Request) {
	namespace := r.URL.Query().Get("namespace")
	if namespace == "" {
		http.Error(w, "namespace is required", http.StatusBadRequest)
		return
	}

	list, err := s.core.CoreV1().Pods(namespace).List(r.Context(), metav1.ListOptions{})
	if err != nil {
		http.Error(w, fmt.Sprintf("listing pods: %v", err), http.StatusInternalServerError)
		return
	}
	pods := make([]podOut, len(list.Items))
	for i, p := range list.Items {
		pods[i] = podOut{Name: p.Name, Labels: p.Labels}
	}
	sort.Slice(pods, func(i, j int) bool { return pods[i].Name < pods[j].Name })

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(podsResponse{Namespace: namespace, Pods: pods})
}

type policyValidateRequest struct {
	Namespace     string `json:"namespace"`
	CandidateYAML string `json:"candidateYAML"`
}

type policyValidateResponse struct {
	Valid     bool   `json:"valid"`
	RuleCount int    `json:"ruleCount,omitempty"`
	Error     string `json:"error,omitempty"`
}

func (s *uiServer) handlePolicyValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req policyValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	trimmed := strings.TrimSpace(req.CandidateYAML)
	if trimmed == "" {
		_ = json.NewEncoder(w).Encode(policyValidateResponse{
			Valid: false,
			Error: "candidate policy is empty",
		})
		return
	}

	rules, err := parseCandidateYAML(s.logger, []byte(req.CandidateYAML), req.Namespace)
	if err != nil {
		_ = json.NewEncoder(w).Encode(policyValidateResponse{
			Valid: false,
			Error: err.Error(),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(policyValidateResponse{
		Valid:     true,
		RuleCount: len(rules),
	})
}

// policyParseResponse mirrors policyValidateResponse's {valid, error} shape
// on failure — PolicyEditorPanel.tsx's YAML import/hand-edit path needs one
// consistent error shape regardless of which of the two endpoints reported
// it — but on success carries back the structured templatePolicyModel
// (Policy on success, Error on failure; the two are mutually exclusive).
type policyParseResponse struct {
	Valid  bool                 `json:"valid"`
	Policy *templatePolicyModel `json:"policy,omitempty"`
	Error  string               `json:"error,omitempty"`
}

// handlePolicyParse backs POST /api/policy/parse — the Policy Editor's
// "import/hand-edit the YAML directly" path (PolicyEditorPanel.tsx):
// unlike handlePolicyValidate, which only ever reports pass/fail plus a
// rule count, this parses the candidate all the way into the same
// templatePolicyModel shape handlePolicyForEdit already returns for a live
// policy, so the frontend can feed a successfully-parsed edit straight
// back into the graph/model (via its own toPolicyModel). Picks the first
// rule the same way handlePolicyForEdit/firstRuleSpec already do for a live
// CNP/CCNP's Spec/Specs pair — same known v1 simplification, now also
// applied to a pasted/hand-edited candidate's Spec/Specs pair.
func (s *uiServer) handlePolicyParse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req policyValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	trimmed := strings.TrimSpace(req.CandidateYAML)
	if trimmed == "" {
		_ = json.NewEncoder(w).Encode(policyParseResponse{
			Valid: false,
			Error: "candidate policy is empty",
		})
		return
	}

	decoded, err := decodeCandidateYAML([]byte(req.CandidateYAML), req.Namespace)
	if err != nil {
		_ = json.NewEncoder(w).Encode(policyParseResponse{
			Valid: false,
			Error: err.Error(),
		})
		return
	}
	if decoded.rule == nil {
		_ = json.NewEncoder(w).Encode(policyParseResponse{
			Valid: false,
			Error: fmt.Sprintf("%s has no rule spec (spec/specs both empty)", decoded.kind),
		})
		return
	}

	// Build the model from decoded.rule before calling decoded.parse()
	// below, not after: Parse()'s underlying Sanitize() canonicalizes
	// EndpointSelector/peer-selector matchLabels keys in place (e.g.
	// "io.kubernetes.pod.namespace" becomes "any:io.kubernetes.pod.namespace",
	// a label-source prefix Cilium's own label parsing adds), mutating the
	// exact same api.Rule decoded.rule points at. convertRuleToPolicyModel
	// copies every field into a fresh templatePolicyModel, so taking this
	// snapshot first keeps the matchLabels keys in the plain, un-prefixed
	// form templateNamespaceLabelKey/the frontend both expect — the same
	// form handlePolicyForEdit's live-policy path already relies on by
	// never calling Parse() on what it hands to convertRuleToPolicyModel.
	model := convertRuleToPolicyModel(decoded.kind, decoded.name, decoded.namespace, decoded.rule)

	if _, err := decoded.parse(s.logger); err != nil {
		_ = json.NewEncoder(w).Encode(policyParseResponse{
			Valid: false,
			Error: err.Error(),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(policyParseResponse{Valid: true, Policy: &model})
}

