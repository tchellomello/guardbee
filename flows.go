package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	flowpb "github.com/cilium/cilium/api/v1/flow"
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
	var last uint64
	var follow bool
	fs.Uint64Var(&last, "last", 20, "number of recent flows to print")
	fs.BoolVarP(&follow, "follow", "f", false, "keep streaming new flows until Ctrl+C, instead of stopping after --last")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: %[1]s flows [-n <namespace>|-A] [--last N] [-f]

Port-forwards to the cluster's hubble-relay pod (cilium-system) and streams
real flows touching that namespace (or every namespace, with
--all-namespaces or by omitting --namespace), via Hubble's Observer.GetFlows
gRPC API.

%[2]s

Flags:
`, binName, numberFlagHelp)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n  %[1]s flows -n testing --last 50\n  %[1]s flows -n myapp --follow\n  %[1]s flows --all-namespaces --last 100\n", binName)
	}
	_ = fs.Parse(args)
	namespace := flags.resolveNamespace()

	core, _, cfg, err := newClientsets(flags.kubeconfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, binName+" flows: building clients: %v\n", err)
		os.Exit(1)
	}

	print := func(f *flowpb.Flow) {
		verdict := f.GetVerdict().String()
		fmt.Printf("%s  %s  %s -> %s  %s\n",
			f.GetTime().AsTime().Format(time.RFC3339),
			colorizePadded(flowVerdictColor(verdict), verdict, 8),
			endpointString(f.GetSource()),
			endpointString(f.GetDestination()),
			l4String(f.GetL4()),
		)
	}

	if follow {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		count, err := streamFlows(ctx, core, cfg, namespace, last, print)
		fmt.Printf("\n%d flows\n", count)
		if err != nil {
			fmt.Fprintf(os.Stderr, binName+" flows: %v\n", err)
			os.Exit(1)
		}
		return
	}

	flows, err := fetchFlows(core, cfg, namespace, last)
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
func fetchFlows(core kubernetes.Interface, cfg *rest.Config, namespace string, number uint64) ([]*flowpb.Flow, error) {
	client, closeFn, err := dialHubble(core, cfg)
	if err != nil {
		return nil, err
	}
	defer closeFn()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stream, err := client.GetFlows(ctx, &observerpb.GetFlowsRequest{
		Number:    number,
		Whitelist: namespaceFilter(namespace),
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
	return flows, nil
}

// streamFlows taps `number` recent flows and then keeps streaming new ones
// as they arrive, calling onFlow for each, until ctx is canceled or the
// stream ends on its own. Returns the number of flows delivered. The caller
// owns ctx's cancellation policy — the CLI cancels on Ctrl+C
// (signal.NotifyContext), the "ui" subcommand's SSE handler cancels on
// client disconnect (the request's own context) — streamFlows itself has no
// opinion on why it was asked to stop.
func streamFlows(ctx context.Context, core kubernetes.Interface, cfg *rest.Config, namespace string, number uint64, onFlow func(*flowpb.Flow)) (int, error) {
	client, closeFn, err := dialHubble(core, cfg)
	if err != nil {
		return 0, err
	}
	defer closeFn()

	stream, err := client.GetFlows(ctx, &observerpb.GetFlowsRequest{
		Number:    number,
		Follow:    true,
		Whitelist: namespaceFilter(namespace),
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

// namespaceFilter builds Hubble's Whitelist filter for one namespace, or nil
// (no filter at all, matching hubble CLI's own "omit --namespace" behavior)
// for the cluster-wide case.
func namespaceFilter(namespace string) []*flowpb.FlowFilter {
	if namespace == "" {
		return nil
	}
	return []*flowpb.FlowFilter{
		{SourcePod: []string{namespace + "/"}},
		{DestinationPod: []string{namespace + "/"}},
	}
}

// dialHubble finds the hubble-relay pod, port-forwards to it, and dials it
// over gRPC. The returned close function tears down both the gRPC connection
// and the port-forward.
func dialHubble(core kubernetes.Interface, cfg *rest.Config) (observerpb.ObserverClient, func(), error) {
	podName, err := findHubbleRelayPod(core)
	if err != nil {
		return nil, nil, fmt.Errorf("finding hubble-relay pod: %w", err)
	}

	localPort, stopFwd, err := startPortForward(core, cfg, podName)
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
	pods, err := core.CoreV1().Pods(hubbleNamespace).List(context.Background(), metav1.ListOptions{LabelSelector: hubbleLabel})
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
	req := core.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(hubbleNamespace).
		Name(podName).
		SubResource("portforward")

	transport, upgrader, err := spdy.RoundTripperFor(cfg)
	if err != nil {
		return 0, nil, err
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, &url.URL{
		Scheme: "https",
		Path:   req.URL().Path,
		Host:   req.URL().Host,
	})

	stopCh := make(chan struct{})
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
		return 0, nil, err
	}

	ports, err := fw.GetPorts()
	if err != nil || len(ports) == 0 {
		close(stopCh)
		return 0, nil, fmt.Errorf("could not determine forwarded local port: %w", err)
	}

	return int(ports[0].Local), func() { close(stopCh) }, nil
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
