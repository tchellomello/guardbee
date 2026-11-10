package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// workloadMatch is one live pod and whether the candidate policy's own
// endpointSelector selects it, as decided by Cilium's engine (never by
// matching label maps here — matchExpressions, namespace-label keys and
// reserved prefixes all have engine-specific semantics).
type workloadMatch struct {
	Namespace      string `json:"namespace"`
	Name           string `json:"name"`
	ServiceAccount string `json:"serviceAccount"`
	Selected       bool   `json:"selected"`
	Ingress        bool   `json:"ingress"`
	Egress         bool   `json:"egress"`
}

type workloadsRequest struct {
	Namespace     string `json:"namespace"`
	CandidateYAML string `json:"candidateYAML"`
}

type workloadsResponse struct {
	Valid     bool            `json:"valid"`
	Error     string          `json:"error,omitempty"`
	Workloads []workloadMatch `json:"workloads"`
}

// podIdentityLabels reproduces the label set Cilium's agent derives for a
// pod's security identity (pod labels, namespace, service account, cluster
// and the io.cilium.k8s.namespace.labels.* copy of the namespace's own
// labels). Without the last two, a selector like the apiserver-egress CCNP
// (matchExpressions on a namespace label and the service account) could never
// match — that is a real production pattern, not an edge case.
func podIdentityLabels(p *corev1.Pod, nsLabels map[string]string) labels.LabelArray {
	lbls := []string{
		"k8s:io.kubernetes.pod.namespace=" + p.Namespace,
		"k8s:io.cilium.k8s.policy.cluster=default",
		"k8s:io.cilium.k8s.policy.serviceaccount=" + serviceAccountOf(p),
	}
	for k, v := range p.Labels {
		lbls = append(lbls, "k8s:"+k+"="+v)
	}
	for k, v := range nsLabels {
		lbls = append(lbls, "k8s:io.cilium.k8s.namespace.labels."+k+"="+v)
	}
	sort.Strings(lbls)
	return labels.ParseLabelArray(lbls...)
}

func serviceAccountOf(p *corev1.Pod) string {
	if p.Spec.ServiceAccountName != "" {
		return p.Spec.ServiceAccountName
	}
	return "default"
}

func (s *uiServer) handlePolicyWorkloads(w http.ResponseWriter, r *http.Request) {
	var req workloadsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fail := func(msg string) {
		_ = json.NewEncoder(w).Encode(workloadsResponse{Error: msg, Workloads: []workloadMatch{}})
	}
	if strings.TrimSpace(req.CandidateYAML) == "" {
		fail("candidate policy is empty")
		return
	}
	rules, err := parseCandidateYAML(s.logger, []byte(req.CandidateYAML), req.Namespace)
	if err != nil {
		fail(err.Error())
		return
	}

	// A CNP can only ever select pods in its own namespace; a CCNP can select
	// anywhere, so an empty namespace deliberately means every namespace.
	nsList, err := s.core.CoreV1().Namespaces().List(r.Context(), metav1.ListOptions{})
	if err != nil {
		http.Error(w, fmt.Sprintf("listing namespaces: %v", err), http.StatusInternalServerError)
		return
	}
	nsLabels := map[string]map[string]string{}
	for _, n := range nsList.Items {
		nsLabels[n.Name] = n.Labels
	}
	pods, err := s.core.CoreV1().Pods(req.Namespace).List(r.Context(), metav1.ListOptions{})
	if err != nil {
		http.Error(w, fmt.Sprintf("listing pods: %v", err), http.StatusInternalServerError)
		return
	}

	out, err := matchWorkloads(s.logger, rules, pods.Items, nsLabels)
	if err != nil {
		fail(err.Error())
		return
	}
	_ = json.NewEncoder(w).Encode(workloadsResponse{Valid: true, Workloads: out})
}

// matchWorkloads gives each non-hostNetwork pod its own synthetic identity
// (>= identity.MinimalNumericIdentity, see CLAUDE.md gotchas) in a fresh
// engine holding only the candidate, then reads the engine's own verdict on
// whether any rule selects it. Pods sharing a label set would share a real
// identity, but one-per-pod is simpler and equivalent for selection.
func matchWorkloads(logger *slog.Logger, rules api.Rules, pods []corev1.Pod, nsLabels map[string]map[string]string) ([]workloadMatch, error) {
	ids := identity.IdentityMap{}
	byID := map[identity.NumericIdentity]*corev1.Pod{}
	next := identity.MinimalNumericIdentity
	for i := range pods {
		p := &pods[i]
		// hostNetwork pods carry the host identity, which pod labels don't select.
		if p.Spec.HostNetwork || p.Status.Phase != corev1.PodRunning {
			continue
		}
		ids[next] = podIdentityLabels(p, nsLabels[p.Namespace])
		byID[next] = p
		next++
	}

	engine, err := newVerdictEngine(logger, rules, ids)
	if err != nil {
		return nil, err
	}
	defer engine.close(logger)

	out := make([]workloadMatch, 0, len(byID))
	for nid, p := range byID {
		epp, err := engine.distillFor(logger, nid)
		if err != nil {
			return nil, err
		}
		in, eg := epp.SelectorPolicy.IngressPolicyEnabled, epp.SelectorPolicy.EgressPolicyEnabled
		out = append(out, workloadMatch{
			Namespace: p.Namespace, Name: p.Name, ServiceAccount: serviceAccountOf(p),
			Selected: in || eg, Ingress: in, Egress: eg,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Selected != out[j].Selected {
			return out[i].Selected
		}
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}
