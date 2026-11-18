package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	observerpb "github.com/cilium/cilium/api/v1/observer"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

const (
	hubbleNamespace  = "cilium-system"
	hubbleLabel      = "k8s-app=hubble-relay"
	hubbleRemotePort = 4245 // hubble-relay's grpc containerPort; confirmed live via the K8s API 2026-10-11
)

// runFlows streams the most recent real Hubble flows for a namespace, proving the
// RBAC + port-forward path to hubble-relay works end to end. It does not yet judge
// the flows against any policy — that's the verdict engine, still to be built.
func runFlows(args []string) {
	fs := pflag.NewFlagSet("flows", pflag.ExitOnError)
	flags := registerCommonFlags(fs)
	filterFlags := registerFlowFilterFlags(fs)
	var last uint64
	var follow bool
	fs.Uint64Var(&last, "last", 20, "number of recent flows to print")
	fs.BoolVarP(&follow, "follow", "f", false, "keep streaming new flows until Ctrl+C, instead of stopping after --last")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %[1]s flows [-n <namespace>|-A] [--pod|--from-*|--to-*|--verdict|--drop-reason-desc|--type ...] [--last N] [-f]

Port-forwards to the cluster's hubble-relay pod (cilium-system) and streams
real flows touching that namespace (or every namespace, with
--all-namespaces or by omitting --namespace), via Hubble's Observer.GetFlows
gRPC API. The --pod/--from-*/--to-*/--verdict/--drop-reason-desc/--type flags narrow that,
with hubble observe's own names and semantics, inside Hubble itself — so
--last N means N matching flows.

%[2]s

Flags:
`, binName, numberFlagHelp)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n  %[1]s flows -n testing --last 50\n  %[1]s flows -n myapp --follow\n  %[1]s flows -n myapp --verdict DROPPED --drop-reason-desc POLICY_DENIED\n  %[1]s flows -n myapp --from-label reserved:world --to-port 443\n  %[1]s flows --all-namespaces --last 100\n", binName)
	}
	_ = fs.Parse(args)
	namespace := flags.resolveNamespace()
	filter, err := filterFlags.parse()
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" flows: %v\n", err)
		os.Exit(1)
	}

	core, _, cfg, err := newClientsets(flags.kubeconfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" flows: building clients: %v\n", err)
		os.Exit(1)
	}
	warnOnVersionSkew(core, cfg)

	print := func(f *flowpb.Flow) {
		verdict := f.GetVerdict().String()
		// The drop reason is what --drop-reason-desc filters on, so show it
		// (only on drops; every forwarded flow would just say UNKNOWN).
		reason := ""
		if r := f.GetDropReasonDesc(); r != flowpb.DropReason_DROP_REASON_UNKNOWN {
			reason = "  (" + r.String() + ")"
		}
		fmt.Printf("%s  %s  %s -> %s  %s%s\n",
			f.GetTime().AsTime().Format(time.RFC3339),
			colorizePadded(flowVerdictColor(verdict), verdict, 8),
			endpointString(f.GetSource()),
			endpointString(f.GetDestination()),
			l4String(f.GetL4()),
			reason,
		)
	}

	if follow {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		count, err := streamFlows(ctx, core, cfg, namespace, filter, last, print)
		fmt.Printf("\n%d flows\n", count)
		if err != nil {
			fmt.Fprintf(os.Stderr, binName+" flows: %v\n", err)
			os.Exit(1)
		}
		return
	}

	flows, err := fetchFlows(core, cfg, namespace, filter, last)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" flows: %v\n", err)
		os.Exit(1)
	}
	for _, f := range flows {
		print(f)
	}
	fmt.Printf("\n%d flows\n", len(flows))
}

// fetchFlows taps the most recent flows Hubble has observed touching the
// given namespace (as source or destination), via a port-forward to
// hubble-relay. Shared by the "flows" subcommand (prints them) and "verdict"
// (judges them against a candidate policy). Bounded: returns once hubble-relay
// has sent `number` flows and closed the stream.
func fetchFlows(core kubernetes.Interface, cfg *rest.Config, namespace string, filter flowFilter, number uint64) ([]*flowpb.Flow, error) {
	whitelist, err := flowWhitelist(namespace, filter)
	if err != nil {
		return nil, err
	}
	client, closeFn, err := dialHubble(core, cfg)
	if err != nil {
		return nil, err
	}
	defer closeFn()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream, err := client.GetFlows(ctx, &observerpb.GetFlowsRequest{
		Number:    number,
		Whitelist: whitelist,
	})
	if err != nil {
		return nil, fmt.Errorf("GetFlows: %w", err)
	}

	var flows []*flowpb.Flow
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("stream: %w", err)
		}
		if f := resp.GetFlow(); f != nil {
			flows = append(flows, f)
		}
	}
	return newestFlows(flows, number), nil
}

// newestFlows keeps the `number` most recent flows, in time order.
// hubble-relay forwards GetFlowsRequest.Number to every node and merges the
// replies (pkg/hubble/relay/observer/server.go), so a 4-node cluster
// answers --last 50 with up to 200 flows. Each node's reply is its own
// newest N, so the newest N of the merged set is exactly the cluster-wide
// last N that --last promises. Sorted here rather than trusting the relay's
// merge order, which is only best-effort within its drain timeout.
func newestFlows(flows []*flowpb.Flow, number uint64) []*flowpb.Flow {
	sort.SliceStable(flows, func(i, j int) bool {
		return flows[i].GetTime().AsTime().Before(flows[j].GetTime().AsTime())
	})
	if uint64(len(flows)) > number {
		flows = flows[uint64(len(flows))-number:]
	}
	return flows
}

// streamFlows taps `number` recent flows and then keeps streaming new ones
// as they arrive, calling onFlow for each, until ctx is canceled or the
// stream ends on its own. Returns the number of flows delivered. The caller
// owns ctx's cancellation policy — the CLI cancels on Ctrl+C
// (signal.NotifyContext), the "ui" subcommand's SSE handler cancels on
// client disconnect (the request's own context) — streamFlows itself has no
// opinion on why it was asked to stop. Unlike fetchFlows, the initial
// backlog isn't trimmed to `number`: hubble-relay asks every node for
// `number` (see newestFlows), and a stream can't tell where the backlog
// ends and live flows begin, so up to `number` per node arrive first.
func streamFlows(ctx context.Context, core kubernetes.Interface, cfg *rest.Config, namespace string, filter flowFilter, number uint64, onFlow func(*flowpb.Flow)) (int, error) {
	whitelist, err := flowWhitelist(namespace, filter)
	if err != nil {
		return 0, err
	}
	client, closeFn, err := dialHubble(core, cfg)
	if err != nil {
		return 0, err
	}
	defer closeFn()

	stream, err := client.GetFlows(ctx, &observerpb.GetFlowsRequest{
		Number:    number,
		Follow:    true,
		Whitelist: whitelist,
	})
	if err != nil {
		return 0, fmt.Errorf("GetFlows: %w", err)
	}

	count := 0
	for {
		resp, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil || err == io.EOF {
				return count, nil
			}
			return count, fmt.Errorf("stream: %w", err)
		}
		if f := resp.GetFlow(); f != nil {
			onFlow(f)
			count++
		}
	}
}

// flowFilter narrows which flows are fetched, using hubble CLI's own flag
// names and semantics (--from-*/--to-* peers, --verdict, --drop-reason-desc).
// It's applied server-side, in hubble-relay's GetFlows, not to rows
// afterwards: Hubble's buffer is one small cluster-wide ring (see --last), so
// filtering afterwards would leave a quiet peer or a rare drop reason with
// almost no flows, whereas filtering the query makes every one of the --last
// flows a matching one. Values within one field are ORed, the fields are
// ANDed, as in hubble observe. Shared by flows and verdict (CLI and UI), so
// both can only ever narrow a sample the same way.
//
// pods is hubble's --pod: the pod on *either* side (source OR destination),
// the workload-centric question "blame" asks. types is hubble's --type,
// restricted to its event type names (policy-verdict, drop, trace, …);
// "blame" defaults it to policy-verdict, the only event Hubble attaches
// policy attribution to (see flowAttribution).
type flowFilter struct {
	pods                                         []string
	fromPods, fromLabels, fromIPs                []string
	toPods, toServices, toLabels, toIPs, toPorts []string
	verdicts                                     []flowpb.Verdict
	dropReasons                                  []flowpb.DropReason
	types                                        []string
}

func (f flowFilter) empty() bool {
	return len(f.pods) == 0 && len(f.fromPods) == 0 && len(f.fromLabels) == 0 && len(f.fromIPs) == 0 &&
		len(f.toPods) == 0 && len(f.toServices) == 0 && len(f.toLabels) == 0 && len(f.toIPs) == 0 &&
		len(f.toPorts) == 0 && len(f.verdicts) == 0 && len(f.dropReasons) == 0 && len(f.types) == 0
}

// flags pairs every flag name with its values, in display order — the single
// list String() and the UI's describe step both render from.
func (f flowFilter) flags() []struct {
	flag string
	vals []string
} {
	names := func(vals any) []string {
		var out []string
		switch v := vals.(type) {
		case []flowpb.Verdict:
			for _, x := range v {
				out = append(out, x.String())
			}
		case []flowpb.DropReason:
			for _, x := range v {
				out = append(out, x.String())
			}
		}
		return out
	}
	return []struct {
		flag string
		vals []string
	}{
		{"pod", f.pods},
		{"from-pod", f.fromPods}, {"from-label", f.fromLabels}, {"from-ip", f.fromIPs},
		{"to-pod", f.toPods}, {"to-service", f.toServices}, {"to-label", f.toLabels}, {"to-ip", f.toIPs}, {"to-port", f.toPorts},
		{"verdict", names(f.verdicts)}, {"drop-reason-desc", names(f.dropReasons)}, {"type", f.types},
	}
}

// String renders the filter as the equivalent flags, for the CLI's
// "Judging …" line, so output pasted into a ticket says what was narrowed.
func (f flowFilter) String() string {
	var parts []string
	for _, fl := range f.flags() {
		for _, v := range fl.vals {
			parts = append(parts, "--"+fl.flag+" "+v)
		}
	}
	return strings.Join(parts, " ")
}

// flowFilterFlags holds the raw flag values until parse() validates the
// enum ones (--verdict, --drop-reason-desc) the way hubble does.
type flowFilterFlags struct {
	f                     flowFilter
	verdicts, dropReasons []string
}

// registerFlowFilterFlags adds the filter flags to fs, for the subcommands
// that fetch flows (flows, verdict).
func registerFlowFilterFlags(fs *pflag.FlagSet) *flowFilterFlags {
	r := &flowFilterFlags{}
	fs.StringArrayVar(&r.f.pods, "pod", nil, "only flows where a pod with this name prefix is the source OR the destination ([namespace/]<pod-name>, same defaulting as --from-pod). Repeatable")
	fs.StringArrayVar(&r.f.fromPods, "from-pod", nil, "only flows from pods with this name prefix ([namespace/]<pod-name>; a bare name uses --namespace, or 'default' with -A, like hubble). Repeatable")
	fs.StringArrayVar(&r.f.fromLabels, "from-label", nil, `only flows from endpoints matching this label selector (e.g. "k8s:app=web", "reserved:world"). Repeatable`)
	fs.StringArrayVar(&r.f.fromIPs, "from-ip", nil, "only flows from this IP address or CIDR (e.g. 10.0.0.5, 10.0.0.0/8). Repeatable")
	fs.StringArrayVar(&r.f.toPods, "to-pod", nil, "only flows to pods with this name prefix (same form and defaulting as --from-pod). Repeatable")
	fs.StringArrayVar(&r.f.toServices, "to-service", nil, "only flows to this Service's ClusterIP ([namespace/]<svc-name> prefix, same defaulting as --to-pod). Repeatable")
	fs.StringArrayVar(&r.f.toLabels, "to-label", nil, `only flows to endpoints matching this label selector (e.g. "k8s:app=db", "reserved:kube-apiserver"). Repeatable`)
	fs.StringArrayVar(&r.f.toIPs, "to-ip", nil, "only flows to this IP address or CIDR. Repeatable")
	fs.StringArrayVar(&r.f.toPorts, "to-port", nil, "only flows to this destination port (e.g. 443). Repeatable")
	fs.StringArrayVar(&r.verdicts, "verdict", nil, "only flows with this verdict: "+strings.Join(verdictNames(), ", ")+". Repeatable")
	fs.StringArrayVar(&r.dropReasons, "drop-reason-desc", nil, "only flows dropped for this reason (e.g. POLICY_DENIED, POLICY_DENY); see Cilium's flow.DropReason for the full list. Repeatable")
	fs.StringArrayVar(&r.f.types, "type", nil, "only events of this Hubble type: "+strings.Join(eventTypeNames(), ", ")+". Repeatable")
	return r
}

// parse validates the enum flags and returns the filter. Names must match
// Cilium's flow.Verdict/flow.DropReason exactly — hubble observe rejects
// anything else the same way (hubble/cmd/observe/flows_filter.go).
func (r *flowFilterFlags) parse() (flowFilter, error) {
	f := r.f
	var err error
	if f.verdicts, err = parseVerdicts(r.verdicts); err != nil {
		return flowFilter{}, err
	}
	if f.dropReasons, err = parseDropReasons(r.dropReasons); err != nil {
		return flowFilter{}, err
	}
	if err = validateEventTypes(f.types); err != nil {
		return flowFilter{}, err
	}
	return f, nil
}

// validateEventTypes accepts Hubble's own event type names
// (monitorAPI.MessageTypeNames, what hubble observe --type takes). Hubble
// also takes numeric types and "type:subtype"; those aren't needed for
// anything this tool shows, so they're rejected rather than half-supported.
func validateEventTypes(vals []string) error {
	for _, v := range vals {
		if _, ok := monitorAPI.MessageTypeNames[v]; !ok {
			return fmt.Errorf("invalid --type value %q (want one of %s)", v, strings.Join(eventTypeNames(), ", "))
		}
	}
	return nil
}

func eventTypeFilters(vals []string) []*flowpb.EventTypeFilter {
	var out []*flowpb.EventTypeFilter
	for _, v := range vals {
		out = append(out, &flowpb.EventTypeFilter{Type: int32(monitorAPI.MessageTypeNames[v])})
	}
	return out
}

// eventTypeNames lists --type's accepted values in Cilium's own order.
func eventTypeNames() []string { return monitorAPI.AllMessageTypeNames() }

func parseVerdicts(vals []string) ([]flowpb.Verdict, error) {
	var out []flowpb.Verdict
	for _, v := range vals {
		n, ok := flowpb.Verdict_value[v]
		if !ok || n == int32(flowpb.Verdict_VERDICT_UNKNOWN) {
			return nil, fmt.Errorf("invalid --verdict value %q (want one of %s)", v, strings.Join(verdictNames(), ", "))
		}
		out = append(out, flowpb.Verdict(n))
	}
	return out, nil
}

func parseDropReasons(vals []string) ([]flowpb.DropReason, error) {
	var out []flowpb.DropReason
	for _, v := range vals {
		n, ok := flowpb.DropReason_value[v]
		if !ok || n == int32(flowpb.DropReason_DROP_REASON_UNKNOWN) {
			return nil, fmt.Errorf("invalid --drop-reason-desc value %q (see Cilium's flow.DropReason, e.g. POLICY_DENIED)", v)
		}
		out = append(out, flowpb.DropReason(n))
	}
	return out, nil
}

// verdictNames/dropReasonNames list every filterable value, sorted, for help
// text and the UI's pickers (GET /api/flow-filter-options) — taken from the
// pinned Cilium's own enums so they can't drift from what Hubble accepts.
func verdictNames() []string { return enumNames(flowpb.Verdict_value, "VERDICT_UNKNOWN") }

func dropReasonNames() []string { return enumNames(flowpb.DropReason_value, "DROP_REASON_UNKNOWN") }

func enumNames(values map[string]int32, unknown string) []string {
	out := make([]string, 0, len(values))
	for name := range values {
		if name != unknown {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// qualifyNames prefixes bare pod/service names with the scope namespace.
// Hubble itself defaults a bare name to "default" (k8s.ParseNamespaceName),
// which in a -n myapp run would silently match nothing; with -A there's no
// better namespace to pick, so bare names are left to hubble's default.
func qualifyNames(names []string, namespace string) []string {
	if namespace == "" || len(names) == 0 {
		return names
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if !strings.Contains(n, "/") {
			n = namespace + "/" + n
		}
		out = append(out, n)
	}
	return out
}

// flowWhitelist builds Hubble's Whitelist for a namespace scope plus an
// optional filter, or nil (no filter at all, matching hubble CLI's own "omit
// --namespace" behavior) for an unfiltered cluster-wide query. Whitelist
// entries are ORed and fields within one entry ANDed.
//
// Two constraints can hold on either side of a flow: the namespace scope
// ("touches the namespace") and --pod ("this pod is the source or the
// destination"). Each is written as one entry per choice of side — 2 entries
// for one, 4 for both — so (from ns AND filter) OR (to ns AND filter), etc.
// Pods need care on each entry: the side a constraint is pinned to and
// --from-pod/--to-pod both live in SourcePod (or DestinationPod), whose
// values are ORed, so that side's list is narrowed to the prefixes satisfying
// both (narrowPodPrefixes) — and the entry is dropped entirely when none do.
// If every entry drops, no flow can match; that's an error, not an empty
// Whitelist, which Hubble would read as "everything".
//
// Unlike hubble observe, --pod may be combined with --from-pod/--to-pod and
// --to-ip (hubble rejects those pairs as conflicting): every field is simply
// ANDed, so "--pod web --to-ip 10.0.0.1" means web's own traffic to that IP.
func flowWhitelist(namespace string, f flowFilter) ([]*flowpb.FlowFilter, error) {
	with := func(ff *flowpb.FlowFilter) *flowpb.FlowFilter {
		ff.SourceLabel = f.fromLabels
		ff.SourceIp = f.fromIPs
		ff.DestinationService = qualifyNames(f.toServices, namespace)
		ff.DestinationLabel = f.toLabels
		ff.DestinationIp = f.toIPs
		ff.DestinationPort = f.toPorts
		ff.Verdict = f.verdicts
		ff.DropReasonDesc = f.dropReasons
		ff.EventType = eventTypeFilters(f.types)
		return ff
	}

	if namespace == "" && f.empty() {
		return nil, nil
	}

	// Pod lists are intersected below, which only works on fully qualified
	// names; with -A a bare name gets "default/", exactly what Hubble itself
	// would read it as (see qualifyNames).
	podScope := namespace
	if podScope == "" {
		podScope = "default"
	}
	from := qualifyNames(f.fromPods, podScope)
	to := qualifyNames(f.toPods, podScope)
	var eitherSide [][]string
	if namespace != "" {
		eitherSide = append(eitherSide, []string{namespace + "/"})
	}
	if len(f.pods) > 0 {
		eitherSide = append(eitherSide, qualifyNames(f.pods, podScope))
	}

	var out []*flowpb.FlowFilter
	// Bit i of sides picks where eitherSide[i] holds: 0 source, 1 destination.
	for sides := 0; sides < 1<<len(eitherSide); sides++ {
		src, dst, ok := from, to, true
		for i, prefixes := range eitherSide {
			if sides&(1<<i) == 0 {
				src, ok = narrowPodPrefixes(src, prefixes)
			} else {
				dst, ok = narrowPodPrefixes(dst, prefixes)
			}
			if !ok {
				break
			}
		}
		if ok {
			out = append(out, with(&flowpb.FlowFilter{SourcePod: src, DestinationPod: dst}))
		}
	}
	if len(out) == 0 {
		if len(f.pods) == 0 {
			return nil, fmt.Errorf("--from-pod and --to-pod are both outside namespace %q, so no flow in it can match; drop one, or use --all-namespaces", namespace)
		}
		return nil, fmt.Errorf("--pod, --from-pod, --to-pod and the namespace scope contradict each other, so no flow can match")
	}
	return out, nil
}

// narrowPodPrefixes returns the pod prefixes matching both lists (each a set
// of ORed "ns/pod-prefix" alternatives, as Hubble reads SourcePod/
// DestinationPod), or ok=false if nothing can. An empty list means "any pod".
// Two prefixes overlap only when one extends the other, and then the longer
// one is the intersection.
func narrowPodPrefixes(a, b []string) (out []string, ok bool) {
	if len(a) == 0 {
		return b, true
	}
	if len(b) == 0 {
		return a, true
	}
	for _, x := range a {
		for _, y := range b {
			switch {
			case strings.HasPrefix(x, y):
				out = append(out, x)
			case strings.HasPrefix(y, x):
				out = append(out, y)
			}
		}
	}
	return out, len(out) > 0
}

// dialHubble finds the hubble-relay pod, port-forwards to it, and dials it
// over gRPC. The returned close function tears down both the gRPC connection
// and the port-forward.
func dialHubble(core kubernetes.Interface, cfg *rest.Config) (observerpb.ObserverClient, func(), error) {
	return dialHubbleContext(context.Background(), core, cfg)
}

func dialHubbleContext(ctx context.Context, core kubernetes.Interface, cfg *rest.Config) (observerpb.ObserverClient, func(), error) {
	podName, err := findHubbleRelayPodContext(ctx, core)
	if err != nil {
		return nil, nil, fmt.Errorf("finding hubble-relay pod: %w", err)
	}

	localPort, stopFwd, err := startPortForwardContext(ctx, core, cfg, podName)
	if err != nil {
		return nil, nil, fmt.Errorf("port-forwarding to %s: %w", podName, err)
	}

	conn, err := grpc.NewClient(fmt.Sprintf("127.0.0.1:%d", localPort), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		stopFwd()
		return nil, nil, fmt.Errorf("dialing hubble-relay: %w", err)
	}

	return observerpb.NewObserverClient(conn), func() {
		conn.Close()
		stopFwd()
	}, nil
}

func findHubbleRelayPod(core kubernetes.Interface) (string, error) {
	return findHubbleRelayPodContext(context.Background(), core)
}

func findHubbleRelayPodContext(ctx context.Context, core kubernetes.Interface) (string, error) {
	pods, err := core.CoreV1().Pods(hubbleNamespace).List(ctx, metav1.ListOptions{LabelSelector: hubbleLabel})
	if err != nil {
		return "", err
	}
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning {
			return p.Name, nil
		}
	}
	return "", fmt.Errorf("no running hubble-relay pod found in namespace %s", hubbleNamespace)
}

// startPortForward opens a local port tunneled to the hubble-relay pod's grpc port
// and returns the local port plus a function to tear the tunnel down.
func startPortForward(core kubernetes.Interface, cfg *rest.Config, podName string) (int, func(), error) {
	return startPortForwardContext(context.Background(), core, cfg, podName)
}

func startPortForwardContext(ctx context.Context, core kubernetes.Interface, cfg *rest.Config, podName string) (int, func(), error) {
	req := core.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(hubbleNamespace).
		Name(podName).
		SubResource("portforward")

	transport, upgrader, err := spdy.RoundTripperFor(cfg)
	if err != nil {
		return 0, nil, err
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport, Timeout: 10 * time.Second}, http.MethodPost, &url.URL{
		Scheme: "https",
		Path:   req.URL().Path,
		Host:   req.URL().Host,
	})

	stopCh := make(chan struct{})
	var stopOnce sync.Once
	stop := func() { stopOnce.Do(func() { close(stopCh) }) }
	readyCh := make(chan struct{})
	fw, err := portforward.New(dialer, []string{fmt.Sprintf("0:%d", hubbleRemotePort)}, stopCh, readyCh, io.Discard, os.Stderr)
	if err != nil {
		return 0, nil, err
	}

	errCh := make(chan error, 1)
	go func() { errCh <- fw.ForwardPorts() }()

	select {
	case <-readyCh:
	case err := <-errCh:
		stop()
		return 0, nil, err
	case <-ctx.Done():
		stop()
		return 0, nil, ctx.Err()
	}

	ports, err := fw.GetPorts()
	if err != nil || len(ports) == 0 {
		stop()
		return 0, nil, fmt.Errorf("could not determine forwarded local port: %w", err)
	}

	return int(ports[0].Local), stop, nil
}

// endpointString renders an identifiable label for a flow endpoint. Pods
// render as "namespace/pod-name". Endpoints with no namespace/pod — reserved
// identities like "reserved:host" (kubelet probes), "reserved:world"
// (outside the cluster), etc. — fall back to that reserved label, or the
// bare numeric identity if even that's missing, rather than printing nothing.
func endpointString(e *flowpb.Endpoint) string {
	if e == nil {
		return "-"
	}
	ns := e.GetNamespace()
	if ns != "" && e.GetPodName() != "" {
		return ns + "/" + e.GetPodName()
	}
	if ns != "" {
		return ns
	}
	if e.GetPodName() != "" {
		return e.GetPodName()
	}
	for _, l := range e.GetLabels() {
		if strings.HasPrefix(l, "reserved:") {
			return l
		}
	}
	if len(e.GetLabels()) > 0 {
		return e.GetLabels()[0]
	}
	if e.GetIdentity() != 0 {
		return fmt.Sprintf("identity:%d", e.GetIdentity())
	}
	return "-"
}

func l4String(l4 *flowpb.Layer4) string {
	if l4 == nil {
		return "-"
	}
	switch {
	case l4.GetTCP() != nil:
		return fmt.Sprintf("TCP:%d", l4.GetTCP().GetDestinationPort())
	case l4.GetUDP() != nil:
		return fmt.Sprintf("UDP:%d", l4.GetUDP().GetDestinationPort())
	default:
		return "-"
	}
}
