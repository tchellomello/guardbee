package main

// Probes are the deliberately opt-in exception to GuardBee's read-only
// cluster access. Never exec into a workload: append one immutable, restricted
// ephemeral container, and leave both the workload and terminated entry alone.
import (
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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

const probeBodyLimit = 256 << 10

type connectionProbeRequest struct {
	nodeName      string
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
}

type connectionProbeResponse struct {
	UID           string           `json:"uid"`
	Context       string           `json:"context,omitempty"`
	APIServer     string           `json:"apiServer,omitempty"`
	Image         string           `json:"image"`
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
	Flows         []flowOut        `json:"flows"`
	Simulation    *verdictResponse `json:"simulation,omitempty"`
	Warnings      []string         `json:"warnings"`
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
	image   string
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
		return nil, fmt.Errorf("--enable-probes requires --probe-image repository:tag or repository@sha256:<64 lowercase hex digits>")
	}
	return &probeBackend{image: image, slots: make(chan struct{}, 2), active: map[string]bool{}, timeout: 30 * time.Second, poll: 250 * time.Millisecond, drain: 2 * time.Second, capture: startProbeCapture, logs: readProbeLogs, dial: func(ctx context.Context, s *uiServer) (observerpb.ObserverClient, func(), error) {
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

func (s *uiServer) handleProbeCapabilities(w http.ResponseWriter, _ *http.Request) {
	capabilities := struct {
		Enabled   bool     `json:"enabled"`
		Protocols []string `json:"protocols"`
		Context   string   `json:"context,omitempty"`
		APIServer string   `json:"apiServer,omitempty"`
		Image     string   `json:"image,omitempty"`
	}{Enabled: s.probes != nil, Protocols: []string{"TCP", "UDP"}, Context: s.target.context, APIServer: s.target.apiServer}
	if s.probes != nil {
		capabilities.Image = s.probes.image
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
	s.handleProbe(w, r, true)
}

func (s *uiServer) handleConnectionProbe(w http.ResponseWriter, r *http.Request) {
	s.handleProbe(w, r, false)
}

func (s *uiServer) handleProbe(w http.ResponseWriter, r *http.Request, legacyTCP bool) {
	requestStart := time.Now()
	if s.probes == nil {
		http.Error(w, "Connectivity tests are disabled", 403)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
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
		http.Error(w, "same-origin Origin is required", 403)
		return
	}
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		http.Error(w, "application/json is required", 415)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, probeBodyLimit)
	var req connectionProbeRequest
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&req); err != nil {
		http.Error(w, "invalid or oversized JSON request", 400)
		return
	}
	if err := d.Decode(new(any)); err != io.EOF {
		http.Error(w, "exactly one JSON object is required", 400)
		return
	}
	if legacyTCP {
		if req.Protocol == "" {
			req.Protocol = "TCP"
		}
		if req.Protocol != "TCP" {
			http.Error(w, "legacy TCP endpoint only supports TCP", 400)
			return
		}
	}
	if err := validateConnectionProbe(req); err != nil {
		http.Error(w, err.Error(), 400)
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
			http.Error(w, err.Error(), 400)
			return
		}
	}
	b := s.probes
	select {
	case b.slots <- struct{}{}:
		defer func() { <-b.slots }()
	default:
		http.Error(w, "probe concurrency limit reached", 429)
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
		http.Error(w, "a probe is already running for this Pod", 429)
		return
	}
	defer func() { b.mu.Lock(); delete(b.active, key); b.mu.Unlock() }()
	ctx, cancel := context.WithTimeout(r.Context(), b.timeout)
	defer cancel()
	for _, a := range []struct{ resource, sub, verb string }{{"pods", "", "get"}, {"pods", "ephemeralcontainers", "update"}, {"pods", "log", "get"}} {
		if err := s.probeAccess(ctx, req.Namespace, req.Pod, a.resource, a.sub, a.verb); err != nil {
			http.Error(w, err.Error(), 403)
			return
		}
	}
	p, err := s.core.CoreV1().Pods(req.Namespace).Get(ctx, req.Pod, metav1.GetOptions{})
	if err != nil {
		http.Error(w, err.Error(), 409)
		return
	}
	if string(p.UID) != req.UID || !normalProbePod(p) {
		http.Error(w, "Pod changed or is not a normal running Linux Pod; select it again", 409)
		return
	}
	if name := pendingProbeContainer(p); name != "" {
		http.Error(w, "Previous GuardBee container "+name+" is pending or running; inspect that attempt before starting another", http.StatusConflict)
		return
	}
	resp := connectionProbeResponse{UID: req.UID, Context: s.target.context, APIServer: s.target.apiServer, Image: b.image, StartedAt: requestStart.UTC().Format(time.RFC3339Nano), Namespace: req.Namespace, Pod: req.Pod, Host: req.Host, Port: req.Port, Protocol: req.Protocol, Outcome: "inconclusive", Flows: []flowOut{}, Warnings: []string{}}
	respond := func() {
		resp.DurationMs = time.Since(requestStart).Milliseconds()
		probeJSON(w, resp)
	}
	if req.Protocol == "UDP" {
		resp.Warnings = append(resp.Warnings, "UDP sends one fixed 27-byte guardbee-connectivity-probe marker to the selected target, with no reply wait or retry. Even a successful send does not prove delivery or policy allowance; the target may treat the unexpected payload as invalid application traffic.")
	}
	if _, err := netip.ParseAddr(req.Host); err != nil {
		resp.Warnings = append(resp.Warnings, "Hostname capture is best-effort: DNS aliases, mesh interception, or absent Hubble destination names make policy evidence inconclusive; DNS resolves inside the Pod, not on the GuardBee server. Resolved address safety must be enforced by operator admission/network controls.")
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
		http.Error(w, "Pod changed before injection; select it again", 409)
		return
	}
	if name := pendingProbeContainer(p); name != "" {
		http.Error(w, "Previous GuardBee container "+name+" is pending or running; inspect that attempt before starting another", http.StatusConflict)
		return
	}
	if len(p.Spec.EphemeralContainers) >= 32 {
		http.Error(w, "Pod already has 32 ephemeral entries; select another Pod", 409)
		return
	}
	priorProbes := 0
	for _, ec := range p.Spec.EphemeralContainers {
		if strings.HasPrefix(ec.Name, "guardbee-tcp-") || strings.HasPrefix(ec.Name, "guardbee-connection-") {
			priorProbes++
		}
	}
	if priorProbes >= 8 {
		http.Error(w, "Pod already has 8 GuardBee probe entries; select another Pod", 409)
		return
	}
	name, err := probeContainerName()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	start := time.Now()
	p = p.DeepCopy()
	ec := secureProbeContainer(name, b.image, req)
	s.logger.Debug("injecting probe ephemeral container",
		"namespace", req.Namespace,
		"pod", req.Pod,
		"container", name,
		"image", b.image,
		"command", ec.Command,
	)
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
	resp.Warnings = append(resp.Warnings, "The terminated ephemeral-container entry cannot be removed or restarted and remains until the Pod is replaced. No Pod is removed or restarted.", "HTTP cancellation cannot kill the injected container; the image's timeout bounds command runtime to 8 seconds (plus at most 1 second to force-kill).", "Hubble correlation is best-effort: concurrent workload traffic to the same destination/port in this window cannot be distinguished from the probe. Relay NODE_CONNECTED does not guarantee the source-node collector has subscribed before injection.")
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
	s.logger.Debug("probe flow correlation complete",
		"container", name,
		"rawCaptured", len(raw),
		"correlated", len(flows),
		"overflow", overflow,
		"captureErr", captureErr,
	)
	for _, f := range flows {
		resp.Flows = append(resp.Flows, toFlowOut(f))
	}
	if len(flows) == 0 {
		resp.Warnings = append(resp.Warnings, "No correlated Hubble flows observed; no policy conclusion is available")
	}
	// A Pod may emit unrelated application traffic even when the injected
	// runtime never started. Do not turn that traffic into a probe prediction.
	runtimeUnavailable := waitErr != nil || terminated == nil || terminated.ExitCode == 126 || terminated.ExitCode == 127
	if len(rules) > 0 && runtimeUnavailable {
		resp.Warnings = append(resp.Warnings, "Simulation inconclusive: the probe runtime could not be verified; captured workload traffic cannot establish the result of this attempt")
	} else if len(rules) > 0 && captureErr == nil && !overflow && ctx.Err() == nil {
		replaceExisting := req.ReplaceExisting == nil || *req.ReplaceExisting
		s.simulateProbeWithMode(ctx, rules, req.CandidateYAML, flows, &resp, replaceExisting)
	} else if len(rules) > 0 {
		resp.Warnings = append(resp.Warnings, "Simulation inconclusive: capture lost events, overflowed, failed, or exceeded its deadline; no reassuring simulation is produced")
	}
	respond()
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
	// success from it; bounded read only, exit status is the signal.
	_, err = io.Copy(io.Discard, io.LimitReader(stream, limit))
	return err
}

type probeCapture struct {
	mu       sync.Mutex
	flows    []*flowpb.Flow
	err      error
	overflow bool
	stop     func()
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
	filter := &flowpb.FlowFilter{SourcePod: []string{req.Namespace + "/" + req.Pod}, DestinationPort: []string{strconv.Itoa(req.Port)}, Protocol: []string{probeProtocol(req)}}
	if _, err := netip.ParseAddr(req.Host); err == nil {
		filter.DestinationIp = []string{req.Host}
	}
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
			if status := resp.GetNodeStatus(); status != nil && status.GetStateChange() != relaypb.NodeState_NODE_CONNECTED {
				c.mu.Lock()
				c.err = fmt.Errorf("relay reports %s: %v", status.GetStateChange(), status.GetNodeNames())
				c.mu.Unlock()
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
	ip, ipErr := netip.ParseAddr(req.Host)
	for _, f := range flows {
		src := f.GetSource()
		ts := f.GetTime()
		matched := false
		if ipErr == nil {
			dstIP, err := netip.ParseAddr(f.GetIP().GetDestination())
			matched = err == nil && dstIP.Unmap() == ip.Unmap()
		} else {
			for _, name := range f.GetDestinationNames() {
				if normalizeProbeDNS(name) == normalizeProbeDNS(req.Host) {
					matched = true
					break
				}
			}
		}
		l4 := f.GetL4()
		protocolMatch := probeProtocol(req) == "TCP" && l4.GetTCP() != nil && l4.GetTCP().GetDestinationPort() == uint32(req.Port) || probeProtocol(req) == "UDP" && l4.GetUDP() != nil && l4.GetUDP().GetDestinationPort() == uint32(req.Port)
		if src.GetNamespace() != req.Namespace || src.GetPodName() != req.Pod || ts == nil || ts.CheckValid() != nil || ts.AsTime().Before(start) || ts.AsTime().After(end) || !matched || !protocolMatch || f.GetIsReply().GetValue() {
			continue
		}
		out = append(out, f)
	}
	return out
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
		resp.Warnings = append(resp.Warnings, "Candidate simulation replaces live policies with the same kind/namespace/name; baseline remains original. Nothing is applied to the cluster; this sample is not policy sign-off.")
	} else {
		resp.Warnings = append(resp.Warnings, "Additive simulation keeps matching live policies alongside the candidate; removed permissions can remain allowed. Nothing is applied to the cluster; this sample is not policy sign-off.")
	}
	if len(flows) == 0 {
		return
	}
	networkPolicies, err := s.core.NetworkingV1().NetworkPolicies("").List(ctx, metav1.ListOptions{})
	if err != nil {
		resp.Warnings = append(resp.Warnings, "Simulation inconclusive: Kubernetes NetworkPolicy inventory unavailable: "+err.Error())
		return
	}
	if len(networkPolicies.Items) > 0 {
		resp.Warnings = append(resp.Warnings, "Simulation inconclusive: Kubernetes NetworkPolicy objects are present but are not included in this probe engine baseline")
		return
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
	baselineRules := api.Rules{}
	for i := range cnps.Items {
		raw, _ := json.Marshal(cnps.Items[i])
		if e := probeRawSemantics(raw); e != nil {
			resp.Warnings = append(resp.Warnings, "Simulation inconclusive: "+e.Error())
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
	}
	if probeProxyRules(append(append(api.Rules{}, baselineRules...), rules...)) {
		resp.Warnings = append(resp.Warnings, "Simulation inconclusive: baseline/candidate uses FQDN or L7 proxy semantics not reproduced by this connectivity simulation")
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
		resp.Warnings = append(resp.Warnings, "Simulation replaces live "+name+" with the candidate")
	}
	if len(skipped) > 0 {
		resp.Warnings = append(resp.Warnings, "Simulation inconclusive: baseline policies were skipped: "+strings.Join(skipped, ", "))
		return
	}
	comp := &verdictComputation{namespace: resp.Namespace, candidateRuleCount: len(rules), baselineRuleCount: n, flowsRequested: uint64(len(flows)), flowsSampled: len(flows), counts: &verdictCounts{total: len(flows)}, target: s.target}
	for _, f := range flows {
		if row := judgeFlow(s.logger, base, candidate, f, comp.counts, true); row != nil {
			comp.rows = append(comp.rows, row)
			comp.rowCounts = append(comp.rowCounts, 1)
		}
	}
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
