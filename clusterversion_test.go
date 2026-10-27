package main

// Regression tests for Phase 0's version-comparison logic (see
// clusterversion.go). No live cluster is reachable from this environment —
// detectClusterCiliumVersion's own hubble-relay dial path isn't exercised
// here, only the pure functions it builds on, against synthetic version
// strings, matching this project's existing engine_spike_test.go/
// verdict_test.go style of testing the real logic standalone rather than
// against a live agent.

import (
	"context"
	"testing"

	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
)

func TestLeadingSemver(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"real cilium version string", "1.20.2 abcdef1 2026-01-01T00:00:00Z go version go1.24.0 linux/amd64", "1.20.2"},
		{"bare semver", "1.19.1", "1.19.1"},
		{"v-prefixed", "v1.20.2", "1.20.2"}, // leadingSemver normalizes via semver.Version.String()
		// Real GetNodes().Node.version shape confirmed live against a
		// hubble-relay v1.18.16 — "cilium" first, then a "v"-prefixed,
		// build-metadata-suffixed token, not the bare leading semver
		// pkg/version.Version's own string form uses.
		{"real GetNodes version string", "cilium v1.18.16+g4dd7ec81", "1.18.16+g4dd7ec81"},
		{"empty", "", ""},
		{"garbage", "not-a-version", ""},
		{"whitespace only", "   ", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := leadingSemver(c.raw); got != c.want {
				t.Errorf("leadingSemver(%q) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

func TestVersionsSkewed(t *testing.T) {
	cases := []struct {
		name             string
		detected, pinned string
		want             bool
	}{
		{"exact match", "1.20.2", "1.20.2", false},
		{"patch-only difference is not skew", "1.20.9", "1.20.2", false},
		{"minor difference is skew", "1.19.1", "1.20.2", true},
		{"major difference is skew", "2.0.0", "1.20.2", true},
		{"unparseable detected side never false-positives", "garbage", "1.20.2", false},
		{"unparseable pinned side never false-positives", "1.20.2", "garbage", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := versionsSkewed(c.detected, c.pinned); got != c.want {
				t.Errorf("versionsSkewed(%q, %q) = %v, want %v", c.detected, c.pinned, got, c.want)
			}
		})
	}
}

// TestDetectClusterCiliumVersionUnreachable exercises
// detectClusterCiliumVersion's no-live-cluster path without needing one: a
// fake clientset with no hubble-relay pod makes findHubbleRelayPod (called
// through dialHubble) fail exactly the way it would against a real cluster
// where hubble-relay isn't running or isn't reachable yet. Must degrade to
// clusterVersionUnknown, never an error or a panic — the same contract
// every other subcommand already relies on when hubble-relay can't be
// reached (see flows.go's fetchFlows/streamFlows).
func TestDetectClusterCiliumVersionUnreachable(t *testing.T) {
	core := fake.NewSimpleClientset() // no pods at all, so no hubble-relay pod to find
	cfg := &rest.Config{}

	status := detectClusterCiliumVersion(context.Background(), core, cfg)
	if status.state != clusterVersionUnknown {
		t.Errorf("state = %v, want clusterVersionUnknown", status.state)
	}
	if status.detected != "" || len(status.nodeVersions) != 0 {
		t.Errorf("expected no detected version or node versions, got detected=%q nodeVersions=%v", status.detected, status.nodeVersions)
	}
}
