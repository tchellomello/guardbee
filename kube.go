package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	ciliumclient "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// debugLogging holds whether --debug / -D was passed anywhere on the command
// line. Set by stripDebugFlag / initDebugLogging so Cilium's PolicyDebug and
// slog.Default() emit debug-level diagnostics to stderr.
var debugLogging bool

// registerDebugFlag adds --debug/-D to a FlagSet so --help lists it and pflag
// accepts it if parsed directly without stripDebugFlag.
func registerDebugFlag(fs *pflag.FlagSet) {
	fs.BoolVarP(&debugLogging, "debug", "D", debugLogging, "enable debug logging to stderr")
}

// initDebugLogging configures slog's default logger to emit LevelDebug records
// to stderr when enabled.
func initDebugLogging(enabled bool) {
	debugLogging = enabled
	if enabled {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}
}

// stripDebugFlag extracts --debug / -D before subcommand dispatch so both
// `guardbee --debug ui` and `guardbee ui --debug` work identically. Stops
// stripping at `--` so positional arguments after `--` are untouched.
func stripDebugFlag(args []string) []string {
	out := make([]string, 0, len(args))
	endOfFlags := false
	enabled := false
	for _, a := range args {
		if endOfFlags {
			out = append(out, a)
			continue
		}
		if a == "--" {
			endOfFlags = true
			out = append(out, a)
			continue
		}
		if a == "--debug" || a == "-D" || a == "--debug=true" {
			enabled = true
			continue
		}
		if strings.HasPrefix(a, "--debug=") {
			if a == "--debug=false" || a == "--debug=0" {
				enabled = false
			}
			continue
		}
		out = append(out, a)
	}
	if enabled {
		initDebugLogging(true)
	}
	return out
}

// commonFlags holds the flags shared by every subcommand, matching hubble
// CLI's own --namespace/-n and --all-namespaces/-A conventions (confirmed
// against github.com/cilium/cilium/hubble/cmd/observe) so this tool's flags
// read the same way to anyone who already knows hubble.
type commonFlags struct {
	kubeconfig    string
	namespace     string
	allNamespaces bool
}

// registerCommonFlags wires the shared flags into fs. Callers register any
// subcommand-specific flags too, then call fs.Parse(args) exactly once.
func registerCommonFlags(fs *pflag.FlagSet) *commonFlags {
	f := &commonFlags{}
	registerDebugFlag(fs)
	fs.StringVar(&f.kubeconfig, "kubeconfig", "", "path to kubeconfig (default: KUBECONFIG env or ~/.kube/config)")
	fs.StringVarP(&f.namespace, "namespace", "n", "", "namespace to scope the query to; omit (or pass --all-namespaces) to query cluster-wide — needed to see the full blast radius of a CiliumClusterwideNetworkPolicy that spans more than one namespace")
	fs.BoolVarP(&f.allNamespaces, "all-namespaces", "A", false, "query cluster-wide instead of one namespace — same effect as omitting --namespace, kept as an explicit flag for clarity (matches hubble CLI)")
	return f
}

// resolveNamespace reconciles --namespace and --all-namespaces into the
// single namespace value callers act on, where "" means cluster-wide.
// Passing both together is accepted (matches hubble, which doesn't treat it
// as a conflict either) — --all-namespaces simply wins.
func (f *commonFlags) resolveNamespace() string {
	if f.allNamespaces {
		if f.namespace != "" {
			fmt.Fprintf(os.Stderr, binName+": both --namespace and --all-namespaces given — --all-namespaces wins, querying cluster-wide\n")
		}
		return ""
	}
	return f.namespace
}

func restConfig(kubeconfigPath string) (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, err
	}
	if debugLogging {
		cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper {
			return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				start := time.Now()
				resp, err := rt.RoundTrip(req)
				if err != nil {
					slog.Default().Debug("k8s api request failed",
						"method", req.Method,
						"url", req.URL.Path,
						"duration", time.Since(start).Round(time.Millisecond),
						"error", err,
					)
					return nil, err
				}
				slog.Default().Debug("k8s api request",
					"method", req.Method,
					"url", req.URL.Path,
					"status", resp.StatusCode,
					"duration", time.Since(start).Round(time.Millisecond),
				)
				return resp, nil
			})
		})
	}
	return cfg, nil
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// kubeTarget names the cluster a run's clients actually talk to, so a
// verdict can say which cluster it judged: the kubeconfig context name, plus
// the API server URL since names like "default" or "admin@cluster" are often
// ambiguous across kubeconfigs.
type kubeTarget struct {
	context   string
	apiServer string
}

// resolveKubeTarget reads the context from the same loading rules restConfig
// uses, and the server from the rest.Config the clients were built with.
// Called once, next to newClientsets: clients are built once per process, so
// a later "kubectl config use-context" doesn't change where this process
// talks to and must not change what it reports either. Best effort — an
// in-cluster or otherwise context-less config just reports no context.
func resolveKubeTarget(kubeconfigPath string, cfg *rest.Config) kubeTarget {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	t := kubeTarget{apiServer: cfg.Host}
	if raw, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).RawConfig(); err == nil {
		t.context = raw.CurrentContext
	}
	return t
}

func newClientsets(kubeconfigPath string) (kubernetes.Interface, ciliumclient.Interface, *rest.Config, error) {
	cfg, err := restConfig(kubeconfigPath)
	if err != nil {
		return nil, nil, nil, err
	}
	core, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	cilium, err := ciliumclient.NewForConfig(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	return core, cilium, cfg, nil
}
