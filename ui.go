package main

// Milestone 1 of the web UI (see Obsidian
// projects/cilium-network-policy-editor/design-2026-10-12.md): a local HTTP
// server exposing the same flows/verdict capability as the "flows"/"verdict"
// subcommands over a small JSON API, for a browser frontend instead of
// terminal output. No new cluster footprint — same kubeconfig-based access
// as every other subcommand, and the JSON responses are built from the exact
// same computeVerdictWithMode/fetchFlows functions the CLI itself calls, never a
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
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	ciliumclient "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/spf13/pflag"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
	var enableProbes bool
	var probeImage, probeImagesFile string
	registerDebugFlag(fs)
	fs.BoolVar(&enableProbes, "enable-probes", false, "opt in to TCP/UDP connectivity tests that append ephemeral containers to running Pods")
	fs.StringVar(&probeImage, "probe-image", "", "offer only this timeout/nc image (Python 3 for UDP), repository:tag or repository@sha256:digest (default: the built-in vetted image catalog)")
	fs.StringVar(&probeImagesFile, "probe-images-file", "", "YAML/JSON catalog of probe images the UI may pick from, replacing the built-in vetted one (see probes/images.yaml)")
	fs.StringVar(&kubeconfig, "kubeconfig", "", "path to kubeconfig (default: KUBECONFIG env or ~/.kube/config)")
	registerHubbleNamespaceFlag(fs)
	registerHubbleAddrFlag(fs)
	fs.StringVar(&addr, "addr", "127.0.0.1:4747", "address to listen on")
	fs.StringVar(&templatesDir, "templates-dir", "", "directory of generic/ingress/egress CiliumNetworkPolicy YAML presets (default: built-in templates/)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %[1]s ui [--addr host:port] [--templates-dir path]

Starts a local web UI at the given address: the same flows/verdict
capability as the "flows" and "verdict" subcommands, in a browser instead of
a terminal. Uses the same kubeconfig-based cluster access as every other
subcommand — read-only by default, no remote hosting, no auth (that's a
stated future direction once this is proven locally, not this milestone).
Namespace scope (one namespace, or all) is chosen per-request in the
browser, not as a flag here.

Policy Editor presets (Blank/Default-deny/etc. starting policies, and the
per-rule "Web", "DNS", etc. buttons) are loaded from a directory of real
CiliumNetworkPolicy YAML under generic/, ingress/, egress/ subdirectories —
--templates-dir points at an external one; omitted, the binary's own
built-in defaults are used.

Connectivity tests are disabled unless --enable-probes is supplied. This
opt-in appends immutable ephemeral containers to running Pods, requires
additional RBAC, and permits numeric-loopback serving only. The browser picks
the probe image from a catalog the server was started with, never a free-form
image: the built-in vetted catalog by default, --probe-images-file to replace
it, or --probe-image for exactly one image. Images need timeout and nc, plus
Python 3 for UDP; see the connectivity-test guide.

Flags:
`, binName)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n  %[1]s ui\n  %[1]s ui --addr 127.0.0.1:9000\n  %[1]s ui --templates-dir ./my-presets\n  %[1]s ui --enable-probes\n  %[1]s ui --enable-probes --probe-images-file ./probe-images.yaml\n", binName)
	}
	_ = fs.Parse(args)
	checkHubbleAddr("ui")
	probes, err := newProbeBackendFromFlags(enableProbes, probeImage, probeImagesFile)
	if err == nil && enableProbes {
		err = validateProbeListenAddr(addr)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" ui: %v\n", err)
		os.Exit(1)
	}

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
	logger.Debug("loaded policy editor templates",
		"generic", len(templates.Generic), "ingress", len(templates.Ingress), "egress", len(templates.Egress))

	target := resolveKubeTarget(kubeconfig, cfg)
	logger.Debug("ui server configured",
		"addr", addr,
		"context", target.context,
		"apiServer", target.apiServer,
		"enableProbes", enableProbes,
		"probeImage", probeImage,
		"probeImagesFile", probeImagesFile,
	)
	fmt.Printf("%s ui: using kubeconfig context %q (%s)\n", binName, target.context, target.apiServer)
	srv := &uiServer{core: core, cilium: cilium, cfg: cfg, target: target, logger: logger, templates: templates, probes: probes}

	static, err := iofs.Sub(uiAssets, "ui/dist")
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" ui: embedded frontend assets: %v\n", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/probes/capabilities", srv.handleProbeCapabilities)
	mux.HandleFunc("GET /api/probes/pods", srv.handleProbePods)
	mux.HandleFunc("POST /api/probes/connection", srv.handleConnectionProbe)
	mux.HandleFunc("POST /api/probes/connection/stream", srv.handleConnectionProbeStream)
	mux.HandleFunc("POST /api/verdict", srv.handleVerdict)
	mux.HandleFunc("GET /api/verdict/stream", srv.handleVerdictStream)
	mux.HandleFunc("GET /api/flows", srv.handleFlows)
	mux.HandleFunc("GET /api/flows/stream", srv.handleFlowsStream)
	mux.HandleFunc("GET /api/flow-filter-options", srv.handleFlowFilterOptions)
	mux.HandleFunc("GET /api/namespaces", srv.handleNamespaces)
	mux.HandleFunc("GET /api/pods", srv.handlePods)
	mux.HandleFunc("GET /api/services", srv.handleServices)
	mux.HandleFunc("GET /api/policies", srv.handlePolicies)
	mux.HandleFunc("GET /api/policies/edit", srv.handlePolicyForEdit)
	mux.HandleFunc("POST /api/policy/validate", srv.handlePolicyValidate)
	mux.HandleFunc("POST /api/policy/parse", srv.handlePolicyParse)
	mux.HandleFunc("POST /api/policy/workloads", srv.handlePolicyWorkloads)
	mux.HandleFunc("GET /api/templates", srv.handleTemplates)
	mux.HandleFunc("GET /api/version", srv.handleVersion)
	mux.HandleFunc("GET /api/compat", srv.handleCompat)
	var root http.Handler = http.FileServerFS(static)
	if probes != nil {
		root = probeLocalhostRedirect(addr, root)
	}
	mux.Handle("/", root)

	fmt.Printf("%s ui: listening on http://%s\n", binName, addr)
	if !loopbackListenAddr(addr) {
		fmt.Fprintf(os.Stderr, "%s ui: WARNING: --addr %s is not loopback. The UI has no authentication: every /api route serves cluster data with this kubeconfig's identity to anyone who can reach that address.\n", binName, addr)
	}
	// ReadHeaderTimeout bounds slowloris-style header dribbling. No
	// ReadTimeout/WriteTimeout: /api/verdict/stream, /api/flows/stream and the
	// probe stream are long-lived SSE/NDJSON responses that a write deadline
	// would cut off mid-stream.
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           rebindingGuard(addr, srv.debugLogRequests(mux)),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	if err := httpSrv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, binName+" ui: %v\n", err)
		os.Exit(1)
	}
}

// rebindingGuard is the DNS-rebinding defense for the whole server, not just
// the probe endpoints: a hostile page can point its own name at 127.0.0.1
// and then read every read-only /api response (flows, policies, Pods) as
// same-origin. Its requests still carry that name in Host, so only an IP
// literal, localhost or the exact --addr is served. A rebinding attack needs
// a DNS name, so an IP literal Host is never one.
//
// It also refuses cross-site and same-site requests by Sec-Fetch-Site: a
// hostile page can't read the responses, but an <img src=.../api/flows/stream>
// would still open hubble-relay port-forwards and List calls with the
// operator's credentials. A missing header (curl, scripts, older browsers) is
// allowed, and so is Origin-less GET, since browsers omit Origin on plain
// navigations and subresource loads; the probe POST keeps its stricter
// probeSameOrigin check. The headers stop the UI from being framed
// (clickjacking) or content-sniffed; a full CSP is out of scope because
// index.html loads Google Fonts and an inline theme script.
func rebindingGuard(addr string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" || site == "same-site" {
			http.Error(w, "cross-site request refused: open the UI directly at its own address", http.StatusForbidden)
			return
		}
		if !trustedHost(r.Host, addr) {
			http.Error(w, "unexpected Host header (DNS-rebinding protection): open the UI by IP address, localhost, or the exact --addr", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func trustedHost(host, addr string) bool {
	if strings.EqualFold(host, addr) {
		return true
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]") // Host without a port
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	return strings.EqualFold(h, "localhost")
}

// loopbackListenAddr reports whether --addr only accepts local connections:
// an empty host (":4747") or 0.0.0.0 listens on every interface.
func loopbackListenAddr(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.IsLoopback()
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *uiServer) debugLogRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !debugLogging || !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.logger.Debug("api request",
			"method", r.Method,
			"path", r.URL.Path,
			"query", r.URL.RawQuery,
			"status", rec.status,
			"duration", time.Since(start).Round(time.Millisecond),
		)
	})
}

// uiServer holds the clientsets built once at startup, reused by every
// request handler — the same clients newClientsets gives every other
// subcommand, just long-lived instead of built-and-discarded per CLI
// invocation.
type uiServer struct {
	probes    *probeBackend
	core      kubernetes.Interface
	cilium    ciliumclient.Interface
	cfg       *rest.Config
	target    kubeTarget // the cluster the clients above talk to, fixed for the server's lifetime
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
	// Binary is this build's own version (version.go), shown in the UI header.
	Binary       string   `json:"binary"`
	Pinned       string   `json:"pinned"`
	Detected     string   `json:"detected,omitempty"`
	Skewed       bool     `json:"skewed"`
	NodeSkew     bool     `json:"nodeSkew"`
	NodeVersions []string `json:"nodeVersions,omitempty"`
	Unknown      bool     `json:"unknown"`
}

// handleVersion backs GET /api/version. ?client=1 skips cluster detection,
// like `guardbee version --client`: the header shows the binary version on
// page load, without waiting up to the detection timeout for hubble-relay.
func (s *uiServer) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Query().Get("client") == "1" {
		_ = json.NewEncoder(w).Encode(versionResponse{Binary: version, Pinned: pinnedCiliumVersion, Unknown: true})
		return
	}
	status := detectClusterCiliumVersion(r.Context(), s.core, s.cfg)
	resp := versionResponse{
		Binary:       version,
		Pinned:       pinnedCiliumVersion,
		Detected:     status.detected,
		Skewed:       status.state == clusterVersionSkewed,
		NodeSkew:     status.state == clusterVersionNodeSkew,
		NodeVersions: status.nodeVersions,
		Unknown:      status.state == clusterVersionUnknown,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// compatGateOut/compatResponse back GET /api/compat — the UI's and CLI's
// shared source for "what does GuardBee refuse to parse, and why," read
// directly off compat.go's featureGates table rather than making the user
// reverse-engineer it from a rejection error. KindLabel is a human string
// (not featureGateKind's own int) since this is a display-only endpoint —
// the frontend has no reason to know how a gate is detected, only what it
// is and why it's gated.
type compatGateOut struct {
	Name       string `json:"name"`
	MinVersion string `json:"minVersion,omitempty"`
	MaxVersion string `json:"maxVersion,omitempty"`
	Reason     string `json:"reason"`
}

type compatResponse struct {
	Pinned string          `json:"pinned"`
	Gates  []compatGateOut `json:"gates"`
}

func (s *uiServer) handleCompat(w http.ResponseWriter, r *http.Request) {
	// Initialized non-nil: a nil slice marshals to JSON "null", and the
	// frontend always expects an array to .map over, even transiently
	// before featureGates has its first entry.
	resp := compatResponse{Pinned: pinnedCiliumVersion, Gates: []compatGateOut{}}
	for _, g := range featureGates {
		resp.Gates = append(resp.Gates, compatGateOut{
			Name:       g.name,
			MinVersion: g.minVersion,
			MaxVersion: g.maxVersion,
			Reason:     g.reason,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// policyBodyLimit caps the non-probe JSON POST bodies: candidate policies are
// KiB, and decoding plus YAML parsing amplifies an unbounded body ~10x in RSS.
const policyBodyLimit = 1 << 20

// verdictRequest is the "ui" subcommand's JSON request body for POST
// /api/verdict, mirroring the "verdict" subcommand's own flags/argument:
// Namespace "" means cluster-wide (same as omitting --namespace or passing
// --all-namespaces), CandidateYAML is the candidate CNP/CCNP as pasted text
// (not a file path — the web form has no filesystem access to the user's
// machine the way the CLI does).
type verdictRequest struct {
	ReplaceExisting bool   `json:"replaceExisting"`
	Namespace       string `json:"namespace"`
	CandidateYAML   string `json:"candidateYAML"`
	Last            uint64 `json:"last"`
	ShowUnchanged   bool   `json:"showUnchanged"`
	flowFilterParams
}

// flowFilterParams is the web form's version of the flow filter flags
// (flowFilter, flows.go), shared by every endpoint that fetches flows: the
// verdict POST body embeds it, and the GET endpoints (EventSource can't POST)
// read the same names from the query string. Names mirror the flags:
// fromPod = --from-pod, verdict = --verdict, dropReason = --drop-reason-desc,
// pod = --pod, type = --type.
type flowFilterParams struct {
	Pod        []string `json:"pod,omitempty"`
	FromPod    []string `json:"fromPod,omitempty"`
	FromLabel  []string `json:"fromLabel,omitempty"`
	FromIP     []string `json:"fromIp,omitempty"`
	ToPod      []string `json:"toPod,omitempty"`
	ToService  []string `json:"toService,omitempty"`
	ToLabel    []string `json:"toLabel,omitempty"`
	ToIP       []string `json:"toIp,omitempty"`
	ToPort     []string `json:"toPort,omitempty"`
	Verdict    []string `json:"verdict,omitempty"`
	DropReason []string `json:"dropReason,omitempty"`
	Type       []string `json:"type,omitempty"`
	HTTPMethod []string `json:"httpMethod,omitempty"`
	HTTPPath   []string `json:"httpPath,omitempty"`
	HTTPStatus []string `json:"httpStatus,omitempty"`
	ToFQDN     []string `json:"toFqdn,omitempty"`
}

func flowFilterParamsFromQuery(q url.Values) flowFilterParams {
	return flowFilterParams{
		Pod:     q["pod"],
		FromPod: q["fromPod"], FromLabel: q["fromLabel"], FromIP: q["fromIp"],
		ToPod: q["toPod"], ToService: q["toService"], ToLabel: q["toLabel"], ToIP: q["toIp"], ToPort: q["toPort"],
		Verdict: q["verdict"], DropReason: q["dropReason"], Type: q["type"],
		HTTPMethod: q["httpMethod"], HTTPPath: q["httpPath"], HTTPStatus: q["httpStatus"], ToFQDN: q["toFqdn"],
	}
}

// filter turns form values into a flowFilter, the same validation the CLI's
// flags get: blanks are dropped (an empty form field means "no filter",
// whereas Hubble rejects an empty pod name outright), enum names are checked
// like hubble does, and a combination that can't match anything in the
// namespace is reported now, as a 400, rather than from inside the fetch.
func (p flowFilterParams) filter(namespace string) (flowFilter, error) {
	clean := func(vals []string) []string {
		var out []string
		for _, v := range vals {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	r := flowFilterFlags{
		f: flowFilter{
			pods:     clean(p.Pod),
			fromPods: clean(p.FromPod), fromLabels: clean(p.FromLabel), fromIPs: clean(p.FromIP),
			toPods: clean(p.ToPod), toServices: clean(p.ToService), toLabels: clean(p.ToLabel),
			toIPs: clean(p.ToIP), toPorts: clean(p.ToPort), types: clean(p.Type),
			httpMethods: clean(p.HTTPMethod), httpPaths: clean(p.HTTPPath), httpStatuses: clean(p.HTTPStatus), toFQDNs: clean(p.ToFQDN),
		},
		verdicts:    clean(p.Verdict),
		dropReasons: clean(p.DropReason),
	}
	f, err := r.parse()
	if err != nil {
		return flowFilter{}, err
	}
	if _, err := flowWhitelist(namespace, f); err != nil {
		return flowFilter{}, err
	}
	return f, nil
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
	L7Changed    int `json:"l7Changed"`
	NotSimulated int `json:"notSimulated"`
	ReplySkipped int `json:"replySkipped"`
	Total        int `json:"total"`
}

type verdictRowOut struct {
	BaselineAllowed  *bool  `json:"baselineAllowed,omitempty"`
	CandidateAllowed *bool  `json:"candidateAllowed,omitempty"`
	Change           string `json:"change"`
	Source           string `json:"source"`
	Destination      string `json:"destination"`
	Protocol         string `json:"protocol"`
	Port             uint16 `json:"port"`
	Count            int    `json:"count"`
	Explanation      string `json:"explanation"`
	// Side/SourceLabels/DestinationLabels: see verdictRow.side/srcLabels/dstLabels.
	Side              string   `json:"side,omitempty"`
	SourceLabels      []string `json:"sourceLabels,omitempty"`
	DestinationLabels []string `json:"destinationLabels,omitempty"`
	// DestinationService: see verdictRow.dstService.
	DestinationService string `json:"destinationService,omitempty"`
	// DestinationNames: see verdictRow.dstNames.
	DestinationNames []string `json:"destinationNames,omitempty"`
	// L7Baseline/L7Candidate: see verdictRow.l7Baseline/l7Candidate.
	L7Baseline  string `json:"l7Baseline,omitempty"`
	L7Candidate string `json:"l7Candidate,omitempty"`
	// L7Request/L7Judge: see verdictRow.l7Request/l7Judge.
	L7Request string `json:"l7Request,omitempty"`
	L7Judge   string `json:"l7Judge,omitempty"`
}

type verdictResponse struct {
	Namespace          string           `json:"namespace"`
	CandidateRuleCount int              `json:"candidateRuleCount"`
	BaselineRuleCount  int              `json:"baselineRuleCount"`
	FlowsRequested     uint64           `json:"flowsRequested"`
	FlowsSampled       int              `json:"flowsSampled"`
	Counts             verdictCountsOut `json:"counts"`
	Rows               []verdictRowOut  `json:"rows"`
	SkippedPolicies    []string         `json:"skippedPolicies,omitempty"`
	// Warnings: candidate constructs that can't work as written
	// (candidateWarnings).
	Warnings []string `json:"warnings,omitempty"`
	// Context/APIServer: the cluster this verdict judged (see kubeTarget).
	// Stamped on every result rather than served once per page, so stacked
	// UI runs stay labeled correctly if the server restarts on another context.
	Context   string `json:"context,omitempty"`
	APIServer string `json:"apiServer,omitempty"`
}

func (s *uiServer) handleVerdict(w http.ResponseWriter, r *http.Request) {
	var req verdictRequest
	r.Body = http.MaxBytesReader(w, r.Body, policyBodyLimit)
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

	filter, err := req.flowFilterParams.filter(req.Namespace)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	comp, err := computeVerdictWithMode(r.Context(), s.logger, s.core, s.cilium, s.cfg, req.Namespace, filter, candidateRules, req.Last, req.ShowUnchanged, req.ReplaceExisting)
	if err != nil {
		http.Error(w, fmt.Sprintf("computing verdict: %v", err), http.StatusInternalServerError)
		return
	}
	comp.target = s.target

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toVerdictResponse(comp))
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
		L7Changed:    c.l7Changed,
		NotSimulated: c.notSimulated,
		ReplySkipped: c.replySkipped,
		Total:        c.total,
	}
}

func toRowOut(row *verdictRow, count int) verdictRowOut {
	return verdictRowOut{
		BaselineAllowed:  row.baselineAllowed,
		CandidateAllowed: row.candidateAllowed,
		Change:           row.change,
		Source:           row.src,
		Destination:      row.dst,
		Protocol:         row.proto,
		Port:             row.port,
		Count:            count,
		Explanation:      changeExplanation(row.change),

		Side:               row.side,
		SourceLabels:       row.srcLabels,
		DestinationLabels:  row.dstLabels,
		DestinationService: row.dstService,
		DestinationNames:   row.dstNames,
		L7Baseline:         row.l7Baseline,
		L7Candidate:        row.l7Candidate,
		L7Request:          row.l7Request,
		L7Judge:            row.l7Judge,
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
	// SkippedPolicies is set only on the first event, before any flow.
	SkippedPolicies []string `json:"skippedPolicies,omitempty"`
	// Warnings: see verdictResponse.Warnings; first event only.
	Warnings          []string `json:"warnings,omitempty"`
	BaselineRuleCount int      `json:"baselineRuleCount,omitempty"`
	// CandidateRuleCount is set only on the first event, like BaselineRuleCount.
	CandidateRuleCount int `json:"candidateRuleCount,omitempty"`
	// Context/APIServer are set only on the first event too, see verdictResponse.
	Context   string `json:"context,omitempty"`
	APIServer string `json:"apiServer,omitempty"`
}

// handleVerdictStream is the streaming counterpart to handleVerdict — same
// judging logic (judgeFlow via the shared baseline/candidate engines from
// buildVerdictEnginesWith), but pushed live over Server-Sent Events as flows
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
	replaceExisting := q.Get("replaceExisting") == "true"
	filter, err := flowFilterParamsFromQuery(q).filter(namespace)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
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

	baselineRuleCount, skipped, _, baseline, candidate, err := buildVerdictEnginesWith(s.logger, s.core, s.cilium, namespace, candidateRules, replaceExisting)
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
	// First event carries what the baseline load knows (rule count, skipped
	// policies) so the UI can show it before the first flow arrives.
	if first, err := json.Marshal(verdictStreamEvent{Counts: toCountsOut(counts), BaselineRuleCount: baselineRuleCount, CandidateRuleCount: len(candidateRules), SkippedPolicies: skipped, Warnings: candidateWarnings(candidateRules), Context: s.target.context, APIServer: s.target.apiServer}); err == nil {
		fmt.Fprintf(w, "data: %s\n\n", first)
		flusher.Flush()
	}
	_, streamErr := streamFlows(r.Context(), s.core, s.cfg, namespace, filter, last, func(f *flowpb.Flow) {
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

// flowsResponse backs GET /api/flows: flowOut rows (blame.go), the same
// shape `blame --format json` prints.
type flowsResponse struct {
	Namespace string    `json:"namespace"`
	Flows     []flowOut `json:"flows"`
}

// flowsQuery reads the namespace/last/filter query parameters shared by the
// one-shot and streaming flows endpoints.
func flowsQuery(q url.Values) (namespace string, last uint64, filter flowFilter, err error) {
	namespace = q.Get("namespace")
	last = 50
	if v := q.Get("last"); v != "" {
		if n, perr := strconv.ParseUint(v, 10, 64); perr == nil {
			last = n
		}
	}
	filter, err = flowFilterParamsFromQuery(q).filter(namespace)
	return namespace, last, filter, err
}

func (s *uiServer) handleFlows(w http.ResponseWriter, r *http.Request) {
	namespace, last, filter, err := flowsQuery(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	flows, err := fetchFlows(r.Context(), s.core, s.cfg, namespace, filter, last)
	if err != nil {
		http.Error(w, fmt.Sprintf("tapping flows: %v", err), http.StatusInternalServerError)
		return
	}

	resp := flowsResponse{Namespace: namespace, Flows: make([]flowOut, len(flows))}
	for i, f := range flows {
		resp.Flows[i] = toFlowOut(f)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleFlowsStream is `guardbee flows --follow` for the browser: the same
// streamFlows the CLI uses, one Server-Sent Event per flow, until the client
// disconnects — the Flows tab's counterpart to handleVerdictStream.
func (s *uiServer) handleFlowsStream(w http.ResponseWriter, r *http.Request) {
	namespace, last, filter, err := flowsQuery(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported by this response writer", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	_, streamErr := streamFlows(r.Context(), s.core, s.cfg, namespace, filter, last, func(f *flowpb.Flow) {
		data, err := json.Marshal(toFlowOut(f))
		if err != nil {
			return
		}
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	})
	// Same as handleVerdictStream: a disconnect is the normal end; anything
	// else can only be logged, the SSE response is already committed.
	if streamErr != nil && r.Context().Err() == nil {
		s.logger.Error("flows stream ended with an error", "error", streamErr)
	}
}

// flowFilterOptions backs GET /api/flow-filter-options: the values the UI's
// verdict, drop-reason and event-type pickers offer, read from the pinned
// Cilium's own flow.Verdict/flow.DropReason enums and monitor message type
// names (the same lists --verdict, --drop-reason-desc and --type validate
// against), so the pickers can't offer a value Hubble would reject or miss
// one it accepts.
type flowFilterOptions struct {
	Verdicts    []string `json:"verdicts"`
	DropReasons []string `json:"dropReasons"`
	EventTypes  []string `json:"eventTypes"`
}

func (s *uiServer) handleFlowFilterOptions(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(flowFilterOptions{Verdicts: verdictNames(), DropReasons: dropReasonNames(), EventTypes: eventTypeNames()})
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

type serviceOut struct {
	Namespace string           `json:"namespace"`
	Name      string           `json:"name"`
	Ports     []servicePortOut `json:"ports,omitempty"`
}

type servicePortOut struct {
	Port     int32  `json:"port"`
	Protocol string `json:"protocol"`
}

// handleServices backs the connectivity test's Host suggestions: Service
// names and ports in one namespace, or every namespace when none is given.
// A Forbidden list (RBAC without "list" on services) is reported as 403 so
// the UI can fall back to Services seen in flows rather than show an error.
func (s *uiServer) handleServices(w http.ResponseWriter, r *http.Request) {
	list, err := s.core.CoreV1().Services(r.URL.Query().Get("namespace")).List(r.Context(), metav1.ListOptions{})
	if apierrors.IsForbidden(err) {
		http.Error(w, fmt.Sprintf("listing services: %v", err), http.StatusForbidden)
		return
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("listing services: %v", err), http.StatusInternalServerError)
		return
	}
	out := make([]serviceOut, 0, len(list.Items))
	for _, svc := range list.Items {
		so := serviceOut{Namespace: svc.Namespace, Name: svc.Name}
		for _, p := range svc.Spec.Ports {
			so.Ports = append(so.Ports, servicePortOut{Port: p.Port, Protocol: string(p.Protocol)})
		}
		out = append(out, so)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Services []serviceOut `json:"services"`
	}{out})
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
	r.Body = http.MaxBytesReader(w, r.Body, policyBodyLimit)
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
	// Lossy means Policy is NOT a faithful rendering of the pasted YAML (a
	// scoped deny, or an unmanaged ingress side, the editor model can't express). The
	// frontend must not replace the user's text with a regenerated policy
	// when this is set — see policyFitsEditorModel.
	Lossy bool `json:"lossy,omitempty"`
	// Documents is the number of policies in a multi-document paste
	// ("---"-separated). The editor holds one policy, so more than one is
	// always Lossy: Policy is only the first, and the frontend keeps the
	// user's text instead of silently dropping the rest.
	Documents int    `json:"documents,omitempty"`
	Error     string `json:"error,omitempty"`
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
	r.Body = http.MaxBytesReader(w, r.Body, policyBodyLimit)
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

	// A multi-document paste is judged as a whole by verdict
	// (parseCandidateYAML), so validate it the same way here, then build the
	// editor model from its first document only.
	docs, err := splitYAMLDocuments([]byte(req.CandidateYAML))
	if err != nil {
		_ = json.NewEncoder(w).Encode(policyParseResponse{Valid: false, Error: err.Error()})
		return
	}
	if len(docs) > 1 {
		if _, err := parseCandidateYAML(s.logger, []byte(req.CandidateYAML), req.Namespace); err != nil {
			_ = json.NewEncoder(w).Encode(policyParseResponse{Valid: false, Error: err.Error()})
			return
		}
	}
	first := []byte(req.CandidateYAML)
	if len(docs) > 0 {
		first = docs[0]
	}

	decoded, err := decodeCandidateYAML(first, req.Namespace)
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
	lossy := !policyFitsEditorModel(decoded.rule)

	if _, err := decoded.parse(s.logger); err != nil {
		_ = json.NewEncoder(w).Encode(policyParseResponse{
			Valid: false,
			Error: err.Error(),
		})
		return
	}

	resp := policyParseResponse{Valid: true, Policy: &model, Lossy: lossy}
	if len(docs) > 1 {
		resp.Lossy = true
		resp.Documents = len(docs)
	}
	_ = json.NewEncoder(w).Encode(resp)
}
