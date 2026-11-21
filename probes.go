package main

// Probes are the deliberately opt-in exception to GuardBee's read-only
// cluster access. Never exec into a workload: append one immutable, restricted
// ephemeral container, and leave both the workload and terminated entry alone.
import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	relaypb "github.com/cilium/cilium/api/v1/relay"
	"github.com/cilium/cilium/pkg/policy/api"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

const probeBodyLimit = 256 << 10

type connectionProbeRequest struct {
	nodeName string
	// service is set when Host names a Kubernetes Service GuardBee could read
	// (resolveProbeService): its ClusterIPs and ready backend addresses, and
	// the backend target ports the requested Service port maps to.
	service       *probeService
	Namespace     string `json:"namespace"`
	Pod           string `json:"pod"`
	UID           string `json:"uid"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Protocol      string `json:"protocol"`
	CandidateYAML string `json:"candidateYAML,omitempty"`
	// Candidate scope is independent of the source Pod namespace. Explicit
	// empty scope must not default a namespace-less CNP to the chosen source.
	CandidateNamespace *string `json:"candidateNamespace,omitempty"`
	ReplaceExisting    *bool   `json:"replaceExisting,omitempty"`
	// ImageID picks a catalog entry (probeimages.go); never an image
	// reference. Empty selects the catalog's default (first) entry.
	ImageID string `json:"imageId,omitempty"`
}

type probeService struct {
	name, namespace string
	addrs           map[netip.Addr]bool
	ports           map[uint32]bool
}

// probeFlowOut is one distinct observed flow. One TCP connection is several
// Hubble trace events (SYN, ACK, data, FIN, each seen at more than one
// observation point); identical rows are folded with a count so the evidence
// reads as "what happened", not as one card per packet.
type probeFlowOut struct {
	flowOut
	Count int `json:"count"`
}

func foldProbeFlows(flows []*flowpb.Flow) []probeFlowOut {
	out := []probeFlowOut{}
	index := map[string]int{}
	for _, f := range flows {
		row := toFlowOut(f)
		key, _ := json.Marshal(struct {
			flowOut
			Time string `json:"time"`
		}{flowOut: row})
		if i, ok := index[string(key)]; ok {
			out[i].Count++
			continue
		}
		index[string(key)] = len(out)
		out = append(out, probeFlowOut{flowOut: row, Count: 1})
	}
	return out
}

type connectionProbeResponse struct {
	UID           string           `json:"uid"`
	Context       string           `json:"context,omitempty"`
	APIServer     string           `json:"apiServer,omitempty"`
	Image         string           `json:"image"`
	ImageID       string           `json:"imageId,omitempty"`
	StartedAt     string           `json:"startedAt"`
	DurationMs    int64            `json:"durationMs"`
	Namespace     string           `json:"namespace"`
	Pod           string           `json:"pod"`
	Host          string           `json:"host"`
	Port          int              `json:"port"`
	Protocol      string           `json:"protocol"`
	Outcome       string           `json:"outcome"`
	Message       string           `json:"message"`
	ContainerName string           `json:"containerName,omitempty"`
	Flows         []probeFlowOut   `json:"flows"`
	Simulation    *verdictResponse `json:"simulation,omitempty"`
	// Warnings are problems with this particular attempt (lost capture,
	// skipped policies, no evidence…). Notes are the standing caveats every
	// attempt carries (ephemeral entry stays, simulation mode, best-effort
	// correlation), kept apart so the attempt's real problem isn't buried.
	Warnings []string    `json:"warnings"`
	Notes    []probeNote `json:"notes"`
}

// probeNote is one standing caveat. Code is stable (the UI picks its icon
// and short title from it, never by parsing Text); Text is the full,
// human-readable sentence, which may carry this attempt's specifics.
type probeNote struct {
	Code string `json:"code"`
	Text string `json:"text"`
}

const (
	noteUDPMarker             = "udp-marker"
	noteServiceMatch          = "service-match"
	noteEphemeralEntry        = "ephemeral-entry"
	noteRuntimeBound          = "runtime-bound"
	noteBestEffortCorrelation = "best-effort-correlation"
	noteNodesOffPath          = "nodes-off-path"
	noteReplaceMode           = "replace-mode"
	noteAdditiveMode          = "additive-mode"
	notePolicyReplaced        = "policy-replaced"
)

func (r *connectionProbeResponse) note(code, text string) {
	r.Notes = append(r.Notes, probeNote{code, text})
}

// Keep the legacy TCP boundary compatible while callers migrate to connection.
type tcpProbeRequest = connectionProbeRequest
type tcpProbeResponse = connectionProbeResponse

func probeProtocol(req connectionProbeRequest) string {
	if req.Protocol == "" {
		return "TCP"
	}
	return req.Protocol
}

// Hooks isolate the cluster boundary in tests, not the Cilium engine.
type probeBackend struct {
	// images is the catalog the browser may pick from, by id; the first
	// entry is the default for clients that send no imageId.
	images  []probeImage
	slots   chan struct{}
	mu      sync.Mutex
	active  map[string]bool
	timeout time.Duration
	poll    time.Duration
	drain   time.Duration
	capture func(context.Context, *uiServer, connectionProbeRequest) (*probeCapture, error)
	logs    func(context.Context, *uiServer, connectionProbeRequest, string) error
	dial    func(context.Context, *uiServer) (observerpb.ObserverClient, func(), error)
}

func newProbeBackend(enabled bool, image string) (*probeBackend, error) {
	if !enabled {
		return nil, nil
	}
	if !validProbeImage(image) {
		return nil, fmt.Errorf("--probe-image must be repository:tag or repository@sha256:<64 lowercase hex digits>")
	}
	return newProbeBackendCatalog([]probeImage{cliProbeImage(image)})
}

// newProbeBackendFromFlags resolves the image flags: --probe-image keeps its
// historical one-image meaning, --probe-images-file replaces the catalog,
// and neither uses the built-in vetted catalog. Probes stay off without
// --enable-probes either way.
func newProbeBackendFromFlags(enabled bool, image, imagesFile string) (*probeBackend, error) {
	if !enabled {
		if image != "" || imagesFile != "" {
			return nil, fmt.Errorf("--probe-image/--probe-images-file need --enable-probes")
		}
		return nil, nil
	}
	if image != "" && imagesFile != "" {
		return nil, fmt.Errorf("use either --probe-image or --probe-images-file, not both")
	}
	if image != "" {
		return newProbeBackend(true, image)
	}
	images, err := loadProbeImages(imagesFile)
	if err != nil {
		return nil, err
	}
	return newProbeBackendCatalog(images)
}

func newProbeBackendCatalog(images []probeImage) (*probeBackend, error) {
	if err := validateProbeImages(images); err != nil {
		return nil, err
	}
	return &probeBackend{images: images, slots: make(chan struct{}, 2), active: map[string]bool{}, timeout: 30 * time.Second, poll: 250 * time.Millisecond, drain: 2 * time.Second, capture: startProbeCapture, logs: readProbeLogs, dial: func(ctx context.Context, s *uiServer) (observerpb.ObserverClient, func(), error) {
		return dialHubbleContext(ctx, s.core, s.cfg)
	}}, nil
}

func validProbeImage(image string) bool {
	if image == "" || len(image) > 512 {
		return false
	}
	repository, digest, hasDigest := strings.Cut(image, "@")
	if hasDigest && !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(digest) {
		return false
	}
	colon, slash := strings.LastIndex(repository, ":"), strings.LastIndex(repository, "/")
	hasTag := colon > slash
	if hasTag {
		if !regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`).MatchString(repository[colon+1:]) {
			return false
		}
		repository = repository[:colon]
	}
	return (hasTag || hasDigest) && regexp.MustCompile(`^[a-z0-9]+(?:[._-]+[a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:[._-]+[a-z0-9]+)*)*$`).MatchString(repository)
}

// image resolves a request's imageId against the catalog; empty selects the
// default (first) entry so pre-catalog clients keep working.
func (b *probeBackend) image(id string) (probeImage, bool) {
	if id == "" {
		return b.images[0], true
	}
	for _, img := range b.images {
		if img.ID == id {
			return img, true
		}
	}
	return probeImage{}, false
}

func (s *uiServer) handleProbeCapabilities(w http.ResponseWriter, _ *http.Request) {
	type imageOut struct {
		probeImage
		Pinned bool `json:"pinned"`
	}
	capabilities := struct {
		Enabled   bool       `json:"enabled"`
		Protocols []string   `json:"protocols"`
		Context   string     `json:"context,omitempty"`
		APIServer string     `json:"apiServer,omitempty"`
		Image     string     `json:"image,omitempty"`
		Images    []imageOut `json:"images,omitempty"`
	}{Enabled: s.probes != nil, Protocols: []string{"TCP", "UDP"}, Context: s.target.context, APIServer: s.target.apiServer}
	if s.probes != nil {
		capabilities.Image = s.probes.images[0].Image
		for _, img := range s.probes.images {
			capabilities.Images = append(capabilities.Images, imageOut{img, img.pinned()})
		}
	}
	probeJSON(w, capabilities)
}

func normalProbePod(p *corev1.Pod) bool {
	return probePodIneligibility(p) == ""
}

func probePodIneligibility(p *corev1.Pod) string {
	switch {
	case p.UID == "" || p.Spec.NodeName == "":
		return "Pod identity or scheduled node is missing"
	case p.Status.Phase != corev1.PodRunning || p.DeletionTimestamp != nil || !probePodReady(p):
		return "Pod must be Running, Ready, and not terminating"
	case probeSystemNamespace(p.Namespace):
		return "System namespaces are excluded"
	case p.Spec.HostNetwork || p.Spec.HostPID || p.Spec.HostIPC:
		return "Host-network or host-process Pods are excluded"
	case p.Spec.ShareProcessNamespace != nil && *p.Spec.ShareProcessNamespace:
		return "Pods sharing the process namespace are excluded"
	case p.Annotations["kubernetes.io/config.mirror"] != "":
		return "Static/mirror Pods are excluded"
	case p.Spec.OS != nil && p.Spec.OS.Name != corev1.Linux:
		return "Only Linux Pods are supported"
	default:
		return ""
	}
}

func probePodReady(p *corev1.Pod) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
func probeSystemNamespace(ns string) bool {
	return strings.HasPrefix(ns, "kube-") || ns == "cilium-system" || ns == "hubble-system"
}

func validateProbeListenAddr(addr string) error {
	if !probeLoopbackHost(addr) {
		return fmt.Errorf("--enable-probes requires --addr with a numeric loopback IP and port (for example 127.0.0.1:4747)")
	}
	return nil
}

func probeLoopbackHost(host string) bool {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(h)
	if err != nil || !ip.IsLoopback() || ip.Zone() != "" {
		return false
	}
	port, err := strconv.Atoi(p)
	return err == nil && port > 0 && port <= 65535
}

func (s *uiServer) handleProbePods(w http.ResponseWriter, r *http.Request) {
	if s.probes == nil {
		http.Error(w, "Connectivity tests are disabled", http.StatusForbidden)
		return
	}
	ns := r.URL.Query().Get("namespace")
	if ns == "" || len(validation.IsDNS1123Label(ns)) > 0 {
		http.Error(w, "valid namespace is required", 400)
		return
	}
	if probeSystemNamespace(ns) {
		http.Error(w, "system namespaces are not eligible for connectivity tests", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := s.probeAccess(ctx, ns, "", "pods", "", "list"); err != nil {
		http.Error(w, err.Error(), 403)
		return
	}
	list, err := s.core.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{FieldSelector: "status.phase=Running"})
	if err != nil {
		http.Error(w, err.Error(), 403)
		return
	}
	type pod struct {
		Name string `json:"name"`
		UID  string `json:"uid"`
	}
	pods := []pod{}
	excluded := map[string]int{}
	for i := range list.Items {
		p := &list.Items[i]
		reason := probePodIneligibility(p)
		if reason == "" && pendingProbeContainer(p) != "" {
			reason = "A previous GuardBee test is pending or running"
		}
		if reason == "" {
			pods = append(pods, pod{p.Name, string(p.UID)})
		} else {
			excluded[reason]++
		}
	}
	sort.Slice(pods, func(i, j int) bool { return pods[i].Name < pods[j].Name })
	probeJSON(w, struct {
		Pods     []pod          `json:"pods"`
		Excluded map[string]int `json:"excluded,omitempty"`
	}{pods, excluded})
}

func probeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func validateTCPProbe(req tcpProbeRequest) error {
	req.Protocol = probeProtocol(req)
	return validateConnectionProbe(req)
}

func validateConnectionProbe(req connectionProbeRequest) error {
	if req.Protocol != "TCP" && req.Protocol != "UDP" {
		return fmt.Errorf("protocol must be exactly TCP or UDP")
	}
	if req.Namespace == "" || len(validation.IsDNS1123Label(req.Namespace)) > 0 || req.Pod == "" || len(validation.IsDNS1123Subdomain(req.Pod)) > 0 {
		return fmt.Errorf("valid namespace and pod are required")
	}
	if probeSystemNamespace(req.Namespace) {
		return fmt.Errorf("system namespaces are not eligible for connectivity tests")
	}
	if req.UID == "" || len(req.UID) > 128 || strings.ContainsAny(req.UID, " \t\r\n/") {
		return fmt.Errorf("pod uid is required")
	}
	if req.Port < 1 || req.Port > 65535 {
		return fmt.Errorf("port must be 1–65535")
	}
	ip, err := netip.ParseAddr(req.Host)
	if err != nil {
		host := normalizeProbeDNS(req.Host)
		// Legacy numeric address forms (127.1, 2130706433, 0177.0.0.1)
		// are accepted by some resolvers but bypass literal address checks.
		numeric := strings.Trim(host, "0123456789.") == ""
		if host == "" || numeric || len(validation.IsDNS1123Subdomain(host)) > 0 || host == "localhost" || strings.HasSuffix(host, ".localhost") {
			return fmt.Errorf("host must be a valid DNS hostname or unicast IP literal, not a URL or command option")
		}
		return nil
	}
	if ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.Unmap() == netip.MustParseAddr("255.255.255.255") {
		return fmt.Errorf("IP targets must be non-loopback, non-link-local unicast addresses")
	}
	return nil
}

// Shown when a hostname target is neither an IP literal nor a Service
// GuardBee can read: until Hubble DNS visibility (or the probe's own resolved
// address) is used for correlation, such a target can't produce evidence.
const probeExternalHostError = "External hostnames can't be matched to Hubble flows yet: target an IP address (resolve it inside the Pod, e.g. nslookup) or a Kubernetes Service name (svc, svc.namespace, svc.namespace.svc.cluster.local). Nothing was injected."

// With probes enabled the writable API only answers to a numeric loopback
// Host (DNS-rebinding defense, probeSameOrigin), so a browser opened on
// "localhost" would load the UI and then have every test refused. Send it to
// the numeric address the server listens on instead of relaxing that check.
func probeLocalhostRedirect(addr string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, _, err := net.SplitHostPort(r.Host); err == nil && strings.EqualFold(h, "localhost") && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			http.Redirect(w, r, "http://"+addr+r.URL.RequestURI(), http.StatusTemporaryRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func normalizeProbeDNS(host string) string { return strings.TrimSuffix(strings.ToLower(host), ".") }

// Require Origin even for non-browser clients. No CORS, forwarded-host trust,
// or missing-Origin exemption on this cluster-mutating endpoint.
func probeSameOrigin(r *http.Request) bool {
	u, err := url.Parse(r.Header.Get("Origin"))
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return err == nil && probeLoopbackHost(r.Host) && u.Scheme == scheme && u.Host == r.Host && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && r.Header.Get("Sec-Fetch-Site") != "cross-site"
}

func (s *uiServer) probeAccess(ctx context.Context, ns, name, resource, subresource, verb string) error {
	review, err := s.core.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authv1.SelfSubjectAccessReview{Spec: authv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authv1.ResourceAttributes{Namespace: ns, Name: name, Resource: resource, Subresource: subresource, Verb: verb}}}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("checking probe authorization: %w", err)
	}
	if !review.Status.Allowed {
		return fmt.Errorf("probe authorization denied: %s %s/%s in %s for %s", verb, resource, subresource, ns, name)
	}
	return nil
}

func (s *uiServer) handleTCPProbe(w http.ResponseWriter, r *http.Request) {
	s.handleProbe(w, r, true, false)
}

func (s *uiServer) handleConnectionProbe(w http.ResponseWriter, r *http.Request) {
	s.handleProbe(w, r, false, false)
}

// handleConnectionProbeStream is the same probe, reported as it happens: one
// NDJSON line per stage ({"stage":"capture"}), then exactly one terminal
// line, {"result":{…}} or {"error":"…","status":409}. Rejections before the
// first stage stay ordinary HTTP errors, so "nothing was injected" keeps its
// status-code meaning for both endpoints.
func (s *uiServer) handleConnectionProbeStream(w http.ResponseWriter, r *http.Request) {
	s.handleProbe(w, r, false, true)
}

// The probe stages, in order, as streamed and as the UI draws them.
const (
	probeStageAuthorize = "authorize"
	probeStageCapture   = "capture"
	probeStageInject    = "inject"
	probeStageRun       = "run"
	probeStageCollect   = "collect"
	probeStageSimulate  = "simulate"
)

type probeOutput struct {
	w         http.ResponseWriter
	stream    bool
	streaming bool
}

func (o *probeOutput) line(v any) {
	_ = json.NewEncoder(o.w).Encode(v)
	if f, ok := o.w.(http.Flusher); ok {
		f.Flush()
	}
}

func (o *probeOutput) stage(name string) {
	if !o.stream {
		return
	}
	if !o.streaming {
		o.streaming = true
		o.w.Header().Set("Content-Type", "application/x-ndjson")
		o.w.Header().Set("Cache-Control", "no-store")
		o.w.Header().Set("X-Content-Type-Options", "nosniff")
		o.w.WriteHeader(http.StatusOK)
	}
	o.line(struct {
		Stage string `json:"stage"`
	}{name})
}

func (o *probeOutput) fail(msg string, status int) {
	if !o.streaming {
		http.Error(o.w, msg, status)
		return
	}
	o.line(struct {
		Error  string `json:"error"`
		Status int    `json:"status"`
	}{msg, status})
}

func (o *probeOutput) result(resp connectionProbeResponse) {
	if !o.streaming {
		probeJSON(o.w, resp)
		return
	}
	o.line(struct {
		Result connectionProbeResponse `json:"result"`
	}{resp})
}

func (s *uiServer) handleProbe(w http.ResponseWriter, r *http.Request, legacyTCP, stream bool) {
	requestStart := time.Now()
	out := &probeOutput{w: w, stream: stream}
	if s.probes == nil {
		out.fail("Connectivity tests are disabled", 403)
		return
	}
	if r.Method != http.MethodPost {
		out.fail("method not allowed", 405)
		return
	}
	if !probeSameOrigin(r) {
		s.logger.Debug("probe request rejected: same-origin check failed",
			"host", r.Host,
			"origin", r.Header.Get("Origin"),
			"secFetchSite", r.Header.Get("Sec-Fetch-Site"),
			"loopbackHost", probeLoopbackHost(r.Host),
			"tls", r.TLS != nil,
		)
		out.fail("same-origin Origin is required", 403)
		return
	}
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		out.fail("application/json is required", 415)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, probeBodyLimit)
	var req connectionProbeRequest
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		out.fail("invalid or oversized JSON request", 400)
		return
	}
	if err := d.Decode(new(any)); err != io.EOF {
		out.fail("exactly one JSON object is required", 400)
		return
	}
	if legacyTCP {
		if req.Protocol == "" {
			req.Protocol = "TCP"
		}
		if req.Protocol != "TCP" {
			out.fail("legacy TCP endpoint only supports TCP", 400)
			return
		}
	}
	if err := validateConnectionProbe(req); err != nil {
		out.fail(err.Error(), 400)
		return
	}
	img, ok := s.probes.image(req.ImageID)
	if !ok {
		out.fail("unknown probe image; pick one the server offers", 400)
		return
	}
	if !img.supports(req.Protocol) {
		out.fail("probe image "+img.Name+" does not support "+req.Protocol, 400)
		return
	}
	var rules api.Rules
	var err error
	if req.CandidateYAML != "" {
		candidateNamespace := req.Namespace
		if req.CandidateNamespace != nil {
			candidateNamespace = *req.CandidateNamespace
		}
		rules, err = parseCandidateYAML(s.logger, []byte(req.CandidateYAML), candidateNamespace)
		if err != nil {
			out.fail(err.Error(), 400)
			return
		}
	}
	b := s.probes
	select {
	case b.slots <- struct{}{}:
		defer func() { <-b.slots }()
	default:
		out.fail("probe concurrency limit reached", 429)
		return
	}
	key := req.Namespace + "/" + req.Pod
	b.mu.Lock()
	busy := b.active[key]
	if !busy {
		b.active[key] = true
	}
	b.mu.Unlock()
	if busy {
		out.fail("a probe is already running for this Pod", 429)
		return
	}
	defer func() { b.mu.Lock(); delete(b.active, key); b.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(r.Context(), b.timeout)
	defer cancel()
	out.stage(probeStageAuthorize)
	for _, a := range []struct{ resource, sub, verb string }{{"pods", "", "get"}, {"pods", "ephemeralcontainers", "update"}, {"pods", "log", "get"}} {
		if err := s.probeAccess(ctx, req.Namespace, req.Pod, a.resource, a.sub, a.verb); err != nil {
			out.fail(err.Error(), 403)
			return
		}
	}
	p, err := s.core.CoreV1().Pods(req.Namespace).Get(ctx, req.Pod, metav1.GetOptions{})
	if err != nil {
		out.fail(err.Error(), 409)
		return
	}
	if string(p.UID) != req.UID || !normalProbePod(p) {
		out.fail("Pod changed or is not a normal running Linux Pod; select it again", 409)
		return
	}
	if name := pendingProbeContainer(p); name != "" {
		out.fail("Previous GuardBee container "+name+" is pending or running; inspect that attempt before starting another", http.StatusConflict)
		return
	}
	resp := connectionProbeResponse{UID: req.UID, Context: s.target.context, APIServer: s.target.apiServer, Image: img.Image, ImageID: img.ID, StartedAt: requestStart.UTC().Format(time.RFC3339Nano), Namespace: req.Namespace, Pod: req.Pod, Host: req.Host, Port: req.Port, Protocol: req.Protocol, Outcome: "inconclusive", Flows: []probeFlowOut{}, Warnings: []string{}, Notes: []probeNote{}}
	respond := func() {
		resp.DurationMs = time.Since(requestStart).Milliseconds()
		out.result(resp)
	}
	if req.Protocol == "UDP" {
		resp.note(noteUDPMarker, "UDP sends one fixed 27-byte guardbee-connectivity-probe marker to the selected target, with no reply wait or retry. Even a successful send does not prove delivery or policy allowance; the target may treat the unexpected payload as invalid application traffic.")
	}
	if _, err := netip.ParseAddr(req.Host); err != nil {
		svc, note := s.resolveProbeService(ctx, req)
		req.service = svc
		switch {
		case svc != nil:
			resp.note(noteServiceMatch, fmt.Sprintf("Hostname matched Service %s/%s: flows to its ClusterIPs or its %d current backend addresses on the mapped target port count as evidence. DNS resolves inside the Pod, not on the GuardBee server.", svc.namespace, svc.name, len(svc.addrs)))
		case note != "":
			resp.Warnings = append(resp.Warnings, note)
		default:
			// Nothing on a Hubble flow ties it to an external name unless the
			// agent's DNS proxy saw the lookup (DNS visibility), so every
			// captured flow would be rejected and the run could only end
			// inconclusive. Refuse before anything is injected instead.
			s.logger.Debug("probe rejected: hostname is not a Kubernetes Service", "host", req.Host)
			out.fail(probeExternalHostError, http.StatusUnprocessableEntity)
			return
		}
	}
	req.nodeName = p.Spec.NodeName
	s.logger.Debug("starting probe hubble capture",
		"namespace", req.Namespace,
		"pod", req.Pod,
		"node", req.nodeName,
		"protocol", req.Protocol,
		"host", req.Host,
		"port", req.Port,
	)
	out.stage(probeStageCapture)
	capture, err := b.capture(ctx, s, req)
	if err != nil {
		s.logger.Debug("probe hubble capture failed to start", "error", err)
		resp.Message = "Hubble capture could not start; no container injected"
		resp.Warnings = append(resp.Warnings, err.Error())
		respond()
		return
	}
	defer capture.stop()
	// Fresh resourceVersion and UID are sent on the subresource PUT: conflicts
	// are NOT retried against a possibly replacement Pod.
	p, err = s.core.CoreV1().Pods(req.Namespace).Get(ctx, req.Pod, metav1.GetOptions{})
	if err != nil || string(p.UID) != req.UID || !normalProbePod(p) {
		out.fail("Pod changed before injection; select it again", 409)
		return
	}
	if name := pendingProbeContainer(p); name != "" {
		out.fail("Previous GuardBee container "+name+" is pending or running; inspect that attempt before starting another", http.StatusConflict)
		return
	}
	if len(p.Spec.EphemeralContainers) >= 32 {
		out.fail("Pod already has 32 ephemeral entries; select another Pod", 409)
		return
	}
	priorProbes := 0
	for _, ec := range p.Spec.EphemeralContainers {
		if strings.HasPrefix(ec.Name, "guardbee-tcp-") || strings.HasPrefix(ec.Name, "guardbee-connection-") {
			priorProbes++
		}
	}
	if priorProbes >= 8 {
		out.fail("Pod already has 8 GuardBee probe entries; select another Pod", 409)
		return
	}
	name, err := probeContainerName()
	if err != nil {
		out.fail(err.Error(), 500)
		return
	}
	start := time.Now()
	p = p.DeepCopy()
	ec := secureProbeContainer(name, img.Image, req)
	s.logger.Debug("injecting probe ephemeral container",
		"namespace", req.Namespace,
		"pod", req.Pod,
		"container", name,
		"image", img.Image,
		"command", ec.Command,
	)
	out.stage(probeStageInject)
	p.Spec.EphemeralContainers = append(p.Spec.EphemeralContainers, ec)
	_, err = s.core.CoreV1().Pods(req.Namespace).UpdateEphemeralContainers(ctx, req.Pod, p, metav1.UpdateOptions{})
	if err != nil {
		s.logger.Debug("ephemeral container injection failed", "container", name, "error", err)
		resp.Message = "Ephemeral-container update failed or its result is unknown; inspect the Pod before retrying"
		resp.ContainerName = name
		resp.Warnings = append(resp.Warnings, err.Error())
		respond()
		return
	}
	resp.ContainerName = name
	resp.note(noteEphemeralEntry, "The terminated ephemeral-container entry cannot be removed or restarted and remains until the Pod is replaced. No Pod is removed or restarted.")
	resp.note(noteRuntimeBound, "HTTP cancellation cannot kill the injected container; the image's timeout bounds command runtime to 8 seconds (plus at most 1 second to force-kill).")
	resp.note(noteBestEffortCorrelation, "Hubble correlation is best-effort: concurrent workload traffic to the same destination/port in this window cannot be distinguished from the probe. Relay NODE_CONNECTED does not guarantee the source-node collector has subscribed before injection.")
	out.stage(probeStageRun)
	terminated, waitErr := s.waitProbe(ctx, req, name)
	if terminated != nil {
		s.logger.Debug("probe container terminated",
			"container", name,
			"reason", terminated.Reason,
			"exitCode", terminated.ExitCode,
			"message", terminated.Message,
		)
	} else if waitErr != nil {
		s.logger.Debug("waiting for probe container failed", "container", name, "error", waitErr)
	}
	resp.Message = "Probe status unavailable or deadline exceeded"
	if waitErr != nil {
		resp.Warnings = append(resp.Warnings, waitErr.Error())
	} else if terminated.Reason == "Completed" && terminated.ExitCode == 0 {
		if req.Protocol == "UDP" {
			resp.Outcome = "generated"
			resp.Message = "One fixed UDP marker datagram was sent (sendto returned); this does not establish delivery, reachability, or a policy allow"
		} else {
			resp.Outcome = "connected"
			resp.Message = "TCP connection established by nc (not an application health check)"
		}
	} else if terminated.Reason == "Error" && terminated.ExitCode == 1 {
		resp.Outcome = "failed"
		resp.Message = "Traffic generation failed; this alone does not establish a policy deny"
	} else {
		switch terminated.ExitCode {
		case 124, 137:
			resp.Message = "Traffic-generation runtime ended or exceeded its deadline; policy impact requires captured flow evidence"
		case 126, 127:
			resp.Message = "Probe runtime could not start; verify your image contains executable timeout, nc, and Python 3 for UDP"
		default:
			resp.Message = "Probe container did not produce a recognized traffic-generation result"
		}
	}
	if err := b.logs(ctx, s, req, name); err != nil {
		resp.Warnings = append(resp.Warnings, "Probe logs unavailable: "+err.Error())
	}
	end := time.Now()
	out.stage(probeStageCollect)
	// A short finite drain lets relay aggregation deliver the last packets.
	select {
	case <-time.After(b.drain):
	case <-ctx.Done():
	}
	capture.stop()
	raw, captureErr, overflow := capture.snapshot()
	if captureErr != nil {
		resp.Warnings = append(resp.Warnings, "Hubble capture incomplete: "+captureErr.Error())
	}
	if overflow {
		resp.Warnings = append(resp.Warnings, "Hubble capture reached its 256-flow bound; evidence is incomplete")
	}
	flows := correlateProbeFlows(raw, req, start, end)
	if down := capture.unavailableNodes(); len(down) > 0 {
		if onPath := probeDownOnPath(down, req.nodeName, flows); len(onPath) > 0 {
			if captureErr == nil {
				captureErr = fmt.Errorf("relay reports Hubble node(s) %s unavailable on this test's path", strings.Join(onPath, ", "))
				resp.Warnings = append(resp.Warnings, "Hubble capture incomplete: "+captureErr.Error())
			}
		} else {
			resp.note(noteNodesOffPath, "Hubble node(s) "+strings.Join(down, ", ")+" were unavailable during capture but are not on this test's path.")
		}
	}
	if debugLogging {
		for _, f := range raw {
			reason := probeFlowMismatch(f, req, start, end)
			if reason == "" {
				reason = "correlated"
			}
			s.logger.Debug("probe captured flow", "container", name, "result", reason, "flow", probeFlowSummary(f))
		}
	}
	s.logger.Debug("probe flow correlation complete",
		"container", name,
		"rawCaptured", len(raw),
		"correlated", len(flows),
		"overflow", overflow,
		"captureErr", captureErr,
	)
	resp.Flows = foldProbeFlows(flows)
	if len(flows) == 0 && len(raw) > 0 {
		resp.Warnings = append(resp.Warnings, fmt.Sprintf("Hubble captured %d flows from this Pod on the target port, but none could be tied to the requested host; no policy conclusion is available. Run with --debug to see why each was rejected, or target an IP literal or Service name.", len(raw)))
	} else if len(flows) == 0 {
		resp.Warnings = append(resp.Warnings, "No correlated Hubble flows observed; no policy conclusion is available")
	}
	// A Pod may emit unrelated application traffic even when the injected
	// runtime never started. Do not turn that traffic into a probe prediction.
	runtimeUnavailable := waitErr != nil || terminated == nil || terminated.ExitCode == 126 || terminated.ExitCode == 127
	if len(rules) > 0 && runtimeUnavailable {
		resp.Warnings = append(resp.Warnings, "Simulation inconclusive: the probe runtime could not be verified; captured workload traffic cannot establish the result of this attempt")
	} else if len(rules) > 0 && captureErr == nil && !overflow && ctx.Err() == nil {
		replaceExisting := req.ReplaceExisting == nil || *req.ReplaceExisting
		out.stage(probeStageSimulate)
		s.simulateProbeWithMode(ctx, rules, req.CandidateYAML, flows, &resp, replaceExisting)
	} else if len(rules) > 0 {
		resp.Warnings = append(resp.Warnings, "Simulation inconclusive: capture lost events, overflowed, failed, or exceeded its deadline; no reassuring simulation is produced")
	}
	respond()
}

// resolveProbeService looks up the Service a hostname names, read-only, so
// correlation has positive evidence when Hubble carries neither destination
// names (no DNS visibility) nor a destination Service (socket-level load
// balancing translates ClusterIP to a backend before any datapath event).
// Returns nil and no note when the host simply isn't a Service; a note when
// it looks like one that GuardBee couldn't read.
func (s *uiServer) resolveProbeService(ctx context.Context, req connectionProbeRequest) (*probeService, string) {
	name, namespace, ok := probeServiceRef(req.Host, req.Namespace)
	if !ok {
		return nil, ""
	}
	svc, err := s.core.CoreV1().Services(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		s.logger.Debug("probe hostname is not a readable Service", "service", namespace+"/"+name, "error", err)
		if apierrors.IsForbidden(err) {
			return nil, "Could not read Service " + namespace + "/" + name + " (forbidden): flows to its backends cannot be correlated, so the result will likely be inconclusive. Grant get on services and list on endpointslices, or target an IP literal."
		}
		return nil, ""
	}
	out := &probeService{name: name, namespace: namespace, addrs: map[netip.Addr]bool{}, ports: map[uint32]bool{uint32(req.Port): true}}
	for _, ip := range svc.Spec.ClusterIPs {
		if addr, err := netip.ParseAddr(ip); err == nil {
			out.addrs[addr] = true
		}
	}
	portName, found := "", false
	for _, p := range svc.Spec.Ports {
		if int(p.Port) == req.Port && string(p.Protocol) == probeProtocol(req) {
			portName, found = p.Name, true
			if p.TargetPort.IntValue() > 0 {
				out.ports[uint32(p.TargetPort.IntValue())] = true
			}
		}
	}
	epSlices, err := s.core.DiscoveryV1().EndpointSlices(namespace).List(ctx, metav1.ListOptions{LabelSelector: discoveryv1.LabelServiceName + "=" + name})
	if err != nil {
		s.logger.Debug("probe Service endpoints unreadable", "service", namespace+"/"+name, "error", err)
		return out, ""
	}
	for _, slice := range epSlices.Items {
		for _, p := range slice.Ports {
			// EndpointSlice ports carry the resolved (possibly named) target
			// port under the Service port's name.
			if found && p.Port != nil && (p.Name == nil && portName == "" || p.Name != nil && *p.Name == portName) {
				out.ports[uint32(*p.Port)] = true
			}
		}
		for _, ep := range slice.Endpoints {
			for _, a := range ep.Addresses {
				if addr, err := netip.ParseAddr(a); err == nil {
					out.addrs[addr] = true
				}
			}
		}
	}
	s.logger.Debug("probe hostname resolved to Service", "service", namespace+"/"+name, "addresses", len(out.addrs), "ports", sortedKeys(out.ports))
	return out, ""
}

// probeServiceRef maps the in-cluster DNS forms of a Service name to
// (name, namespace): "<svc>" (resolved in the Pod's own namespace first),
// "<svc>.<ns>", "<svc>.<ns>.svc" and "<svc>.<ns>.svc.<cluster-domain>".
func probeServiceRef(host, podNamespace string) (string, string, bool) {
	labels := strings.Split(normalizeProbeDNS(host), ".")
	switch {
	case len(labels) == 1:
		return labels[0], podNamespace, true
	case len(labels) == 2 || labels[2] == "svc":
		return labels[0], labels[1], true
	default:
		return "", "", false
	}
}

func sortedKeys[K cmp.Ordered](m map[K]bool) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// HTTP cancellation releases a process-local slot but cannot cancel Kubernetes
// container startup. Persisted Pod status prevents another attempt from racing
// a pending/running container, including one from a previous server process.
func pendingProbeContainer(p *corev1.Pod) string {
	terminated := map[string]bool{}
	for _, status := range p.Status.EphemeralContainerStatuses {
		terminated[status.Name] = status.State.Terminated != nil
	}
	for _, container := range p.Spec.EphemeralContainers {
		if (strings.HasPrefix(container.Name, "guardbee-tcp-") || strings.HasPrefix(container.Name, "guardbee-connection-")) && !terminated[container.Name] {
			return container.Name
		}
	}
	return ""
}

func probeContainerName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "guardbee-connection-" + hex.EncodeToString(b[:]), nil
}

func secureProbeContainer(name, image string, req connectionProbeRequest) corev1.EphemeralContainer {
	t, f, uid := true, false, int64(65532)
	pullPolicy := corev1.PullIfNotPresent
	if !strings.Contains(image, "@sha256:") {
		pullPolicy = corev1.PullAlways
	}
	command := []string{"timeout", "-k", "1s", "8s", "nc"}
	host := req.Host
	if _, err := netip.ParseAddr(host); err == nil {
		command = append(command, "-n")
	} else {
		host = strings.ToLower(host)
	}
	command = append(command, "-z", "-v", "-w", "5", host, strconv.Itoa(req.Port))
	if probeProtocol(req) == "UDP" {
		command = []string{"timeout", "-k", "1s", "8s", "python3", "-I", "-c", udpProbeScript, host, strconv.Itoa(req.Port)}
	}
	return corev1.EphemeralContainer{EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: name, Image: image, ImagePullPolicy: pullPolicy, Command: command, SecurityContext: &corev1.SecurityContext{RunAsNonRoot: &t, RunAsUser: &uid, RunAsGroup: &uid, Privileged: &f, AllowPrivilegeEscalation: &f, ReadOnlyRootFilesystem: &t, Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}, SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}}}}
}

// A UDP nc zero-I/O scan can report success without sending a packet. This
// fixed stdlib program sends exactly one marker, never reads a reply or retries,
// and never interpolates operator arguments into executable code. timeout also
// bounds getaddrinfo, which socket.settimeout alone cannot bound.
const udpProbeScript = `import ipaddress, socket, sys
address = socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), socket.AF_UNSPEC, socket.SOCK_DGRAM)[0]
ip = ipaddress.ip_address(address[4][0].split('%')[0])
ip = getattr(ip, 'ipv4_mapped', None) or ip
if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or str(ip) == '255.255.255.255' or '%' in address[4][0] or (address[0] == socket.AF_INET6 and address[4][3]):
    raise ValueError('UDP target must resolve to a non-loopback, non-link-local unicast address')
with socket.socket(address[0], address[1], address[2]) as sock:
    sock.settimeout(5)
    sock.sendto(b'guardbee-connectivity-probe', address[4])
`

func (s *uiServer) waitProbe(ctx context.Context, req connectionProbeRequest, name string) (*corev1.ContainerStateTerminated, error) {
	ticker := time.NewTicker(s.probes.poll)
	defer ticker.Stop()
	for {
		p, err := s.core.CoreV1().Pods(req.Namespace).Get(ctx, req.Pod, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if string(p.UID) != req.UID {
			return nil, fmt.Errorf("Pod UID changed while waiting")
		}
		for _, st := range p.Status.EphemeralContainerStatuses {
			if st.Name == name {
				if st.State.Terminated != nil {
					return st.State.Terminated, nil
				}
				if waiting := st.State.Waiting; waiting != nil {
					switch waiting.Reason {
					case "ErrImagePull", "ImagePullBackOff", "InvalidImageName", "CreateContainerConfigError", "CreateContainerError", "RunContainerError":
						return nil, fmt.Errorf("probe container waiting: %s; inspect image availability and admission/runtime settings (the container may still start later)", waiting.Reason)
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func readProbeLogs(ctx context.Context, s *uiServer, req connectionProbeRequest, name string) error {
	limit := int64(4096)
	stream, err := s.core.CoreV1().Pods(req.Namespace).GetLogs(req.Pod, &corev1.PodLogOptions{Container: name, LimitBytes: &limit}).Stream(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	// Do not echo image-controlled text into the verdict/message or infer
	// success from it; bounded read only, exit status is the signal. --debug
	// only copies it to the operator's own stderr, as a quoted string.
	if !debugLogging {
		_, err = io.Copy(io.Discard, io.LimitReader(stream, limit))
		return err
	}
	out, err := io.ReadAll(io.LimitReader(stream, limit))
	s.logger.Debug("probe container output", "container", name, "output", strings.TrimSpace(string(out)))
	return err
}

type probeCapture struct {
	mu       sync.Mutex
	flows    []*flowpb.Flow
	err      error
	overflow bool
	// unavailable holds relay node names whose latest state is not
	// NODE_CONNECTED. Not an error by itself: a down node only makes the
	// evidence incomplete when it is on this test's path (probeDownOnPath).
	unavailable map[string]bool
	stop        func()
}

func (c *probeCapture) unavailableNodes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return sortedKeys(c.unavailable)
}

func probeNodeMatches(relayName, nodeName string) bool {
	return relayName == nodeName || strings.HasSuffix(relayName, "/"+nodeName)
}

// probeDownOnPath returns the unavailable relay nodes that could hold this
// test's evidence: the source Pod's node always; any other node only when
// the destination is a Pod and no destination-side event (one observed on a
// node other than the source's, or delivered to the endpoint) arrived, since
// then the destination's node, and an ingress drop it saw, may be the one
// missing. A node that is neither can't have seen the probe's packets.
func probeDownOnPath(down []string, sourceNode string, flows []*flowpb.Flow) []string {
	destinationSeen, destinationPod := false, false
	for _, f := range flows {
		if f.GetDestination().GetPodName() != "" {
			destinationPod = true
		}
		if f.GetTraceObservationPoint() == flowpb.TraceObservationPoint_TO_ENDPOINT || f.GetNodeName() != "" && !probeNodeMatches(f.GetNodeName(), sourceNode) {
			destinationSeen = true
		}
	}
	out := []string{}
	for _, n := range down {
		if probeNodeMatches(n, sourceNode) || destinationPod && !destinationSeen || len(flows) == 0 {
			out = append(out, n)
		}
	}
	return out
}

func (c *probeCapture) snapshot() ([]*flowpb.Flow, error, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]*flowpb.Flow(nil), c.flows...), c.err, c.overflow
}

func startProbeCapture(ctx context.Context, s *uiServer, req connectionProbeRequest) (*probeCapture, error) {
	client, closeFn, err := s.probes.dial(ctx, s)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithCancel(ctx)
	ports := []string{strconv.Itoa(req.Port)}
	if req.service != nil {
		ports = ports[:0]
		for _, p := range sortedKeys(req.service.ports) {
			ports = append(ports, strconv.FormatUint(uint64(p), 10))
		}
	}
	filter := &flowpb.FlowFilter{SourcePod: []string{req.Namespace + "/" + req.Pod}, DestinationPort: ports, Protocol: []string{probeProtocol(req)}}
	if _, err := netip.ParseAddr(req.Host); err == nil {
		filter.DestinationIp = []string{req.Host}
	}
	s.logger.Debug("probe hubble filter", "filter", filter.String())
	stream, err := client.GetFlows(cctx, &observerpb.GetFlowsRequest{Follow: true, Whitelist: []*flowpb.FlowFilter{filter}})
	if err != nil {
		cancel()
		closeFn()
		return nil, err
	}
	// Headers alone can accompany NODE_UNAVAILABLE. NODE_CONNECTED is a relay
	// source-availability health gate, not acknowledgement of node collector
	// subscription: fc.collect marks connected before its GetFlows goroutine.
	// Capture starts first, but that remaining readiness race is best-effort;
	// absent correlated evidence is always explicitly inconclusive.
	if _, err := stream.Header(); err != nil {
		cancel()
		closeFn()
		return nil, err
	}
	for {
		first, err := stream.Recv()
		if err != nil {
			cancel()
			closeFn()
			return nil, fmt.Errorf("waiting for Hubble source-node readiness: %w", err)
		}
		if lost := first.GetLostEvents(); lost != nil {
			cancel()
			closeFn()
			return nil, fmt.Errorf("Hubble reports lost events before source availability: %v", lost)
		}
		status := first.GetNodeStatus()
		if status == nil {
			continue
		}
		matches := false
		for _, name := range status.GetNodeNames() {
			if req.nodeName == "" || name == req.nodeName || strings.HasSuffix(name, "/"+req.nodeName) {
				matches = true
			}
		}
		if !matches {
			continue
		}
		if status.GetStateChange() != relaypb.NodeState_NODE_CONNECTED {
			cancel()
			closeFn()
			return nil, fmt.Errorf("Hubble source node is not connected: %s", status.GetStateChange())
		}
		break
	}
	c := &probeCapture{}
	done := make(chan struct{})
	var once sync.Once
	c.stop = func() { once.Do(func() { cancel(); closeFn(); <-done }) }
	go func() {
		defer close(done)
		for {
			resp, err := stream.Recv()
			if err != nil {
				if cctx.Err() == nil {
					c.mu.Lock()
					c.err = err
					c.mu.Unlock()
				}
				return
			}
			if f := resp.GetFlow(); f != nil {
				c.mu.Lock()
				if len(c.flows) < 256 {
					c.flows = append(c.flows, f)
				} else {
					c.overflow = true
				}
				c.mu.Unlock()
			}
			if status := resp.GetNodeStatus(); status != nil {
				c.mu.Lock()
				if c.unavailable == nil {
					c.unavailable = map[string]bool{}
				}
				for _, n := range status.GetNodeNames() {
					if status.GetStateChange() == relaypb.NodeState_NODE_CONNECTED {
						delete(c.unavailable, n)
					} else {
						c.unavailable[n] = true
					}
				}
				c.mu.Unlock()
				s.logger.Debug("probe relay node status", "state", status.GetStateChange(), "nodes", status.GetNodeNames())
			}
			if lost := resp.GetLostEvents(); lost != nil {
				c.mu.Lock()
				c.err = fmt.Errorf("Hubble reports lost events: %v", lost)
				c.mu.Unlock()
			}
		}
	}()
	return c, nil
}

func correlateProbeFlows(flows []*flowpb.Flow, req connectionProbeRequest, start, end time.Time) []*flowpb.Flow {
	out := []*flowpb.Flow{}
	for _, f := range flows {
		if probeFlowMismatch(f, req, start, end) == "" {
			out = append(out, f)
		}
	}
	return out
}

// probeFlowMismatch names the first correlation check a captured flow fails,
// or "" when it is evidence for this attempt. Kept as one function so the
// --debug trace and the correlation itself can never disagree.
func probeFlowMismatch(f *flowpb.Flow, req connectionProbeRequest, start, end time.Time) string {
	src := f.GetSource()
	if src.GetNamespace() != req.Namespace || src.GetPodName() != req.Pod {
		return "source is not the probed Pod"
	}
	ts := f.GetTime()
	if ts == nil || ts.CheckValid() != nil {
		return "flow has no valid timestamp"
	}
	if ts.AsTime().Before(start) || ts.AsTime().After(end) {
		return "outside the probe container's run window"
	}
	if f.GetIsReply().GetValue() {
		return "reply direction"
	}
	l4 := f.GetL4()
	var dport uint32
	switch {
	case probeProtocol(req) == "TCP" && l4.GetTCP() != nil:
		dport = l4.GetTCP().GetDestinationPort()
	case probeProtocol(req) == "UDP" && l4.GetUDP() != nil:
		dport = l4.GetUDP().GetDestinationPort()
	default:
		return "protocol differs"
	}
	// A Service target is the only case where the packet's port may differ
	// from the requested one: its port maps to the backends' targetPort.
	if dport != uint32(req.Port) {
		dstIP, err := netip.ParseAddr(f.GetIP().GetDestination())
		if req.service == nil || !req.service.ports[dport] || err != nil || !req.service.addrs[dstIP.Unmap()] {
			return "destination port differs"
		}
	}
	if ip, err := netip.ParseAddr(req.Host); err == nil {
		dstIP, err := netip.ParseAddr(f.GetIP().GetDestination())
		if err != nil || dstIP.Unmap() != ip.Unmap() {
			return "destination IP differs (a ClusterIP target is usually translated to a backend Pod IP before Hubble sees it)"
		}
		return ""
	}
	for _, name := range f.GetDestinationNames() {
		if normalizeProbeDNS(name) == normalizeProbeDNS(req.Host) {
			return ""
		}
	}
	if svc := f.GetDestinationService(); svc.GetName() != "" && probeHostIsService(req.Host, req.Namespace, svc.GetName(), svc.GetNamespace()) {
		return ""
	}
	if req.service != nil {
		if dstIP, err := netip.ParseAddr(f.GetIP().GetDestination()); err == nil && req.service.addrs[dstIP.Unmap()] {
			return ""
		}
		return "destination is not one of Service " + req.service.namespace + "/" + req.service.name + "'s ClusterIPs or backends"
	}
	return "hostname matches neither a Hubble destination name nor a readable Service"
}

// Hubble only carries DestinationNames when DNS visibility (the agent's DNS
// proxy) observed the lookup, and DestinationService only when the datapath
// translated a ClusterIP itself; either is positive evidence of the Service.
func probeHostIsService(host, podNamespace, svcName, svcNamespace string) bool {
	name, namespace, ok := probeServiceRef(host, podNamespace)
	return ok && name == svcName && namespace == svcNamespace
}

// probeFlowSummary is a compact one-line description of a captured flow for
// --debug traces, enough to see why correlation accepted or rejected it.
func probeFlowSummary(f *flowpb.Flow) string {
	port, proto := uint32(0), "?"
	if t := f.GetL4().GetTCP(); t != nil {
		port, proto = t.GetDestinationPort(), "TCP"
	} else if u := f.GetL4().GetUDP(); u != nil {
		port, proto = u.GetDestinationPort(), "UDP"
	}
	ts := ""
	if f.GetTime() != nil {
		ts = f.GetTime().AsTime().UTC().Format("15:04:05.000")
	}
	return fmt.Sprintf("%s %s/%s -> %s:%d/%s svc=%s names=%v verdict=%s type=%s reply=%v obs=%s",
		ts, f.GetSource().GetNamespace(), f.GetSource().GetPodName(), f.GetIP().GetDestination(), port, proto,
		serviceString(f.GetDestinationService()), f.GetDestinationNames(), f.GetVerdict(), f.GetType(),
		f.GetIsReply().GetValue(), f.GetTraceObservationPoint())
}

// Inspect raw inventory, before Parse() can drop unsupported fields. CIDR
// groups need agent-side expansion; this backend has not verified that path.
func hasCIDRGroupRef(v any) bool {
	b, err := json.Marshal(v)
	if err != nil {
		return true
	}
	var obj any
	if json.Unmarshal(b, &obj) != nil {
		return true
	}
	var walk func(any) bool
	walk = func(x any) bool {
		switch v := x.(type) {
		case map[string]any:
			for k, val := range v {
				if k == "cidrGroupSelector" {
					return true
				}
				if k == "cidrGroupRef" {
					if str, ok := val.(string); !ok || str != "" {
						return true
					}
				}
				if walk(val) {
					return true
				}
			}
		case []any:
			for _, val := range v {
				if walk(val) {
					return true
				}
			}
		}
		return false
	}
	return walk(obj)
}

func (s *uiServer) simulateProbe(ctx context.Context, rules api.Rules, rawCandidate string, flows []*flowpb.Flow, resp *connectionProbeResponse) {
	s.simulateProbeWithMode(ctx, rules, rawCandidate, flows, resp, true)
}

func (s *uiServer) simulateProbeWithMode(ctx context.Context, rules api.Rules, rawCandidate string, flows []*flowpb.Flow, resp *connectionProbeResponse, replaceExisting bool) {
	if replaceExisting {
		resp.note(noteReplaceMode, "Candidate simulation replaces live policies with the same kind/namespace/name; baseline remains original. Nothing is applied to the cluster; this sample is not policy sign-off.")
	} else {
		resp.note(noteAdditiveMode, "Additive simulation keeps matching live policies alongside the candidate; removed permissions can remain allowed. Nothing is applied to the cluster; this sample is not policy sign-off.")
	}
	if len(flows) == 0 {
		return
	}
	// A Kubernetes NetworkPolicy's podSelector only ever selects Pods in its
	// own namespace, so only policies in a correlated flow's source or
	// destination namespace can enforce on it. Gating on every NetworkPolicy
	// cluster-wide made the simulation permanently inconclusive on any
	// cluster where some unrelated app (Argo CD, Longhorn…) ships one.
	namespaces := map[string]bool{}
	for _, f := range flows {
		for _, ns := range []string{f.GetSource().GetNamespace(), f.GetDestination().GetNamespace()} {
			if ns != "" {
				namespaces[ns] = true
			}
		}
	}
	for _, ns := range sortedKeys(namespaces) {
		networkPolicies, err := s.core.NetworkingV1().NetworkPolicies(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			resp.Warnings = append(resp.Warnings, "Simulation inconclusive: Kubernetes NetworkPolicy inventory unavailable: "+err.Error())
			return
		}
		if len(networkPolicies.Items) > 0 {
			s.logger.Debug("probe simulation gated by Kubernetes NetworkPolicy", "namespace", ns, "count", len(networkPolicies.Items))
			resp.Warnings = append(resp.Warnings, "Simulation inconclusive: Kubernetes NetworkPolicy objects in namespace "+ns+" are not included in this probe engine baseline")
			return
		}
	}
	cnps, err := s.cilium.CiliumV2().CiliumNetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		resp.Warnings = append(resp.Warnings, "Simulation inconclusive: full baseline inventory unavailable: "+err.Error())
		return
	}
	ccnps, err := s.cilium.CiliumV2().CiliumClusterwideNetworkPolicies().List(ctx, metav1.ListOptions{})
	if err != nil {
		resp.Warnings = append(resp.Warnings, "Simulation inconclusive: full baseline inventory unavailable: "+err.Error())
		return
	}
	var candidateObject any
	docs, _ := splitYAMLDocuments([]byte(rawCandidate))
	for _, doc := range docs {
		if e := probeRawSemantics(doc); e != nil {
			resp.Warnings = append(resp.Warnings, "Simulation inconclusive: "+e.Error())
			return
		}
		if yaml.Unmarshal(doc, &candidateObject) != nil || hasCIDRGroupRef(candidateObject) {
			resp.Warnings = append(resp.Warnings, "Simulation inconclusive: cidrGroupRef/cidrGroupSelector membership/identity injection is unverified; no reassuring simulation is produced")
			return
		}
	}
	if hasCIDRGroupRef(rules) || hasCIDRGroupRef(cnps) || hasCIDRGroupRef(ccnps) {
		resp.Warnings = append(resp.Warnings, "Simulation inconclusive: cidrGroupRef/cidrGroupSelector membership/identity injection is unverified; no reassuring simulation is produced")
		return
	}
	// Build from the very inventory checked above, not a second live List
	// whose changed policies could bypass the conservative simulation gates.
	// A CNP's endpointSelector only ever selects endpoints in its own
	// namespace, so its agent-side semantics (proxy redirects, toServices,
	// named ports, auth) can only matter here when it lives in a correlated
	// flow's source or destination namespace. Out-of-scope CNPs still go to
	// the engine, which does the real matching; CCNPs and the candidate are
	// always gated, conservatively.
	baselineRules, proxyRelevant := api.Rules{}, api.Rules{}
	for i := range cnps.Items {
		inScope := namespaces[cnps.Items[i].Namespace]
		raw, _ := json.Marshal(cnps.Items[i])
		if e := probeRawSemantics(raw); e != nil && inScope {
			resp.Warnings = append(resp.Warnings, "Simulation inconclusive: "+cnps.Items[i].Namespace+"/"+cnps.Items[i].Name+": "+e.Error())
			return
		}
		if e := probeBaselineGates(cnps.Items[i], rawRules(cnps.Items[i].Spec, cnps.Items[i].Specs)); e != nil {
			resp.Warnings = append(resp.Warnings, "Simulation inconclusive: baseline compatibility: "+e.Error())
			return
		}
		parsed, e := cnps.Items[i].Parse(s.logger, "")
		if e != nil {
			resp.Warnings = append(resp.Warnings, "Simulation inconclusive: baseline parsing: "+e.Error())
			return
		}
		baselineRules = append(baselineRules, parsed...)
		if inScope {
			proxyRelevant = append(proxyRelevant, parsed...)
		}
	}
	for i := range ccnps.Items {
		raw, _ := json.Marshal(ccnps.Items[i])
		if e := probeRawSemantics(raw); e != nil {
			resp.Warnings = append(resp.Warnings, "Simulation inconclusive: "+e.Error())
			return
		}
		if e := probeBaselineGates(ccnps.Items[i], rawRules(ccnps.Items[i].Spec, ccnps.Items[i].Specs)); e != nil {
			resp.Warnings = append(resp.Warnings, "Simulation inconclusive: baseline compatibility: "+e.Error())
			return
		}
		parsed, e := ccnps.Items[i].Parse(s.logger, "")
		if e != nil {
			resp.Warnings = append(resp.Warnings, "Simulation inconclusive: baseline parsing: "+e.Error())
			return
		}
		baselineRules = append(baselineRules, parsed...)
		proxyRelevant = append(proxyRelevant, parsed...)
	}
	if probeProxyRules(append(proxyRelevant, rules...)) {
		resp.Warnings = append(resp.Warnings, "Simulation inconclusive: a policy in "+strings.Join(sortedKeys(namespaces), ", ")+", a clusterwide policy, or the candidate uses FQDN or L7 proxy semantics not reproduced by this connectivity simulation")
		return
	}
	n, skipped, replaced, base, candidate, err := buildVerdictEnginesFromRules(s.logger, baselineRules, nil, rules, replaceExisting)
	if err != nil {
		resp.Warnings = append(resp.Warnings, "Simulation inconclusive: "+err.Error())
		return
	}
	defer base.close(s.logger)
	defer candidate.close(s.logger)
	for _, name := range replaced {
		resp.note(notePolicyReplaced, "Simulation replaces live "+name+" with the candidate")
	}
	if len(skipped) > 0 {
		resp.Warnings = append(resp.Warnings, "Simulation inconclusive: baseline policies were skipped: "+strings.Join(skipped, ", "))
		return
	}
	// Same judging and same row folding as the verdict command, so the trace
	// events of one connection become one row with a count.
	comp := judgeFetchedFlows(s.logger, base, candidate, flows, resp.Namespace, flowFilter{}, uint64(len(flows)), true)
	comp.candidateRuleCount, comp.baselineRuleCount, comp.target = len(rules), n, s.target
	out := toVerdictResponse(comp)
	resp.Simulation = &out
	if comp.counts.notSimulated > 0 {
		resp.Warnings = append(resp.Warnings, "Some correlated flows could not be simulated; no conclusion is available for those flows")
	}
}

func probeBaselineGates(object any, rules api.Rules) error {
	raw, err := json.Marshal(object)
	if err != nil {
		return err
	}
	if err = checkRawFieldGates(raw, pinnedCiliumVersion); err != nil {
		return err
	}
	return checkFeatureGates(rules, pinnedCiliumVersion)
}

// These require agent-side auth, service resolution, or endpoint named-port
// maps that verdictOwner does not supply. Inspect raw data before Parse can
// discard it, including deny rules; never guess their policy semantics.
func probeRawSemantics(raw []byte) error {
	var obj any
	if err := yaml.Unmarshal(raw, &obj); err != nil {
		return err
	}
	var walk func(any) error
	walk = func(v any) error {
		switch x := v.(type) {
		case map[string]any:
			for k, val := range x {
				switch k {
				case "authentication":
					if m, ok := val.(map[string]any); ok {
						if mode, _ := m["mode"].(string); mode != "" && mode != "disabled" {
							return fmt.Errorf("authentication requirements are not reproduced by the probe engine")
						}
					}
				case "toServices":
					if a, ok := val.([]any); ok && len(a) > 0 {
						return fmt.Errorf("toServices agent-side resolution is not reproduced by the probe engine")
					}
				case "ports":
					if ports, ok := val.([]any); ok {
						for _, port := range ports {
							if m, ok := port.(map[string]any); ok {
								if name, ok := m["port"].(string); ok && name != "" {
									if _, err := strconv.ParseUint(name, 10, 16); err != nil {
										return fmt.Errorf("named ports are not reproduced by the probe engine")
									}
								}
							}
						}
					}
				}
				if err := walk(val); err != nil {
					return err
				}
			}
		case []any:
			for _, val := range x {
				if err := walk(val); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(obj)
}

func probeProxyRules(rules api.Rules) bool {
	for _, r := range rules {
		for _, eg := range r.Egress {
			if len(eg.ToFQDNs) > 0 {
				return true
			}
			for _, p := range eg.ToPorts {
				if p.Rules != nil {
					return true
				}
			}
		}
		for _, in := range r.Ingress {
			for _, p := range in.ToPorts {
				if p.Rules != nil {
					return true
				}
			}
		}
	}
	return false
}
