package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Every subcommand that reaches hubble-relay must take --hubble-addr, or
// kubernetes/rbac.yaml's advice to drop the pod rules and dial relay's
// Service instead leaves that subcommand with no way in: policies and
// version reach relay through the version-skew check, ui for everything.
// A malformed value must be refused up front, before any cluster access,
// so the test needs no kubeconfig. Each case runs the real dispatch in a
// child process because the commands exit via os.Exit.
func TestHubbleAddrOnEveryRelayCommand(t *testing.T) {
	if args := os.Getenv("GUARDBEE_TEST_MAIN_ARGS"); args != "" {
		os.Args = append([]string{binName}, strings.Split(args, "\x1f")...)
		main()
		os.Exit(0)
	}
	for _, cmd := range []string{"policies", "flows", "blame", "verdict", "ui", "version"} {
		t.Run(cmd, func(t *testing.T) {
			child := exec.Command(os.Args[0], "-test.run=^TestHubbleAddrOnEveryRelayCommand$")
			child.Env = append(os.Environ(),
				"GUARDBEE_TEST_MAIN_ARGS="+strings.Join([]string{cmd, "--hubble-addr", "no-port-here"}, "\x1f"),
				"KUBECONFIG=/nonexistent/guardbee-test-kubeconfig",
			)
			out, err := child.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 {
				t.Fatalf("%s --hubble-addr no-port-here: want exit 1, got %v\n%s", cmd, err, out)
			}
			if !strings.Contains(string(out), "--hubble-addr must be host:port") {
				t.Fatalf("%s: want the --hubble-addr validation error, got:\n%s", cmd, out)
			}
		})
	}
}
