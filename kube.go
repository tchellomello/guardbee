package main

import (
	"fmt"
	"os"

	ciliumclient "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

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
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
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
