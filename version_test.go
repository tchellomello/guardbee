package main

import (
	"strings"
	"testing"
)

func TestClusterVersionLine(t *testing.T) {
	ctxTarget := kubeTarget{context: "kind-guardbee-lab", apiServer: "https://127.0.0.1:6443"}
	cases := []struct {
		name   string
		status clusterVersionStatus
		target kubeTarget
		want   []string // substrings that must all appear
		reject []string // substrings that must not appear
	}{
		{"match", clusterVersionStatus{state: clusterVersionMatch, detected: "1.20.4", nodeVersions: []string{"1.20.4"}}, ctxTarget,
			[]string{"cilium cluster 1.20.4", "(context: kind-guardbee-lab)"}, []string{"differs", "unknown"}},
		{"skewed", clusterVersionStatus{state: clusterVersionSkewed, detected: "1.18.16+g4dd7ec81", nodeVersions: []string{"1.18.16+g4dd7ec81"}}, ctxTarget,
			[]string{"cilium cluster 1.18.16+g4dd7ec81", "differs from the pinned engine", pinnedCiliumVersion}, nil},
		{"node skew lists every version", clusterVersionStatus{state: clusterVersionNodeSkew, nodeVersions: []string{"1.20.3", "1.20.4"}}, ctxTarget,
			[]string{"1.20.3, 1.20.4", "nodes disagree"}, nil},
		{"unknown", clusterVersionStatus{state: clusterVersionUnknown}, ctxTarget,
			[]string{"cilium cluster unknown", "(context: kind-guardbee-lab)"}, nil},
		// An in-cluster or context-less config still has to say which
		// cluster it asked — "(context: )" would name nothing.
		{"no context falls back to API server", clusterVersionStatus{state: clusterVersionMatch, detected: "1.20.4"}, kubeTarget{apiServer: "https://10.0.0.1:443"},
			[]string{"(context: https://10.0.0.1:443)"}, []string{"(context: )"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := clusterVersionLine(&c.status, c.target)
			for _, w := range c.want {
				if !strings.Contains(got, w) {
					t.Errorf("missing %q in %q", w, got)
				}
			}
			for _, r := range c.reject {
				if strings.Contains(got, r) {
					t.Errorf("unexpected %q in %q", r, got)
				}
			}
		})
	}
}
