package main

import (
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/rest"
)

func TestResolveKubeTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kubeconfig")
	const kubeconfig = `apiVersion: v1
kind: Config
current-context: lab
contexts:
- name: lab
  context: {cluster: lab, user: lab}
- name: prod
  context: {cluster: prod, user: lab}
clusters:
- name: lab
  cluster: {server: "https://lab.example:6443"}
- name: prod
  cluster: {server: "https://prod.example:6443"}
users:
- name: lab
  user: {token: x}
`
	if err := os.WriteFile(path, []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := restConfig(path)
	if err != nil {
		t.Fatalf("restConfig: %v", err)
	}
	got := resolveKubeTarget(path, cfg)
	if got.context != "lab" || got.apiServer != "https://lab.example:6443" {
		t.Errorf("want lab @ https://lab.example:6443, got %q @ %q", got.context, got.apiServer)
	}
}

func TestResolveKubeTargetWithoutKubeconfig(t *testing.T) {
	got := resolveKubeTarget(filepath.Join(t.TempDir(), "missing"), &rest.Config{Host: "https://10.0.0.1:443"})
	if got.context != "" || got.apiServer != "https://10.0.0.1:443" {
		t.Errorf("want no context and the rest.Config host, got %+v", got)
	}
}

func TestContextLabel(t *testing.T) {
	if got := contextLabel(kubeTarget{context: "lab"}); got != " on context lab" {
		t.Errorf("got %q", got)
	}
	if got := contextLabel(kubeTarget{}); got != "" {
		t.Errorf("empty context should add nothing, got %q", got)
	}
}
