package main

// Policy Editor "preset" templates (see ui/src/policy.ts's old
// PRESET_TEMPLATES/INGRESS_RULE_PRESETS/EGRESS_RULE_PRESETS, now removed in
// favor of this): rather than hardcoding presets as Go or TS data, they're
// read from a directory tree of real CiliumNetworkPolicy YAML files —
// templates/{generic,ingress,egress}/*.yaml, either the built-in defaultTemplatesFS
// (embedded into the binary) or an external directory passed via "ui
// --templates-dir". Each file is a valid, standalone CNP, so it can be
// copy-pasted straight off a real cluster: "generic" templates are loaded as
// a full starting policy, "ingress"/"egress" templates contribute just their
// first ingress/egress rule as a one-click rule preset in the graph editor.

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"sort"
	"strings"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/policy/api"
	"sigs.k8s.io/yaml"
)

//go:embed all:templates
var defaultTemplatesFS embed.FS

// templateDisplayNameAnnotation lets a template file's UI label hold
// characters a k8s resource name can't (parens, slashes, spaces) without
// giving up on being valid, loadable CiliumNetworkPolicy YAML.
const (
	guardbeeDisplayNameAnnotation = "guardbee.io/display-name"
	templateDisplayNameAnnotation = "policy-simulator.cilium.io/display-name"
	// guardbeeCategoryAnnotation groups generic templates for the Policy
	// Editor's "Presets & Starters" menu (see ui/src/components/PresetMenu.tsx)
	// — a free-text label rather than an enum so a new category needs no Go
	// change, just a new annotation value on the template file.
	guardbeeCategoryAnnotation = "guardbee.io/category"
)

// templateNamespaceLabelKey is the same bare-key convention
// generateCiliumNetworkPolicyYAML (ui/src/policy.ts) already emits for a
// peer's namespace — see its "io.kubernetes.pod.namespace" matchLabels
// entries — so templates round-trip through the same convention the rest of
// the app uses, not a second one.
const templateNamespaceLabelKey = "io.kubernetes.pod.namespace"

// JSON-friendly mirrors of ui/src/policy.ts's IngressRule/EgressRule/
// PolicyModel, minus the "id" field — the frontend assigns a fresh id
// whenever a template is loaded or a rule preset is added to the canvas, so
// templates never need to carry one.
type templatePortRule struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol"`
}

type templateEndpointSelector struct {
	MatchLabels map[string]string `json:"matchLabels"`
	Namespace   string            `json:"namespace,omitempty"`
}

// templateServiceRef mirrors ui/src/policy.ts's K8sServiceRef — the simple
// Service{K8sService{serviceName, namespace}} form only. api.Service's
// other form (K8sServiceSelector, selecting a whole set of Services by
// label) is a deliberate v1 omission, same as every other scope decision
// already documented in policy.ts's generator.
type templateServiceRef struct {
	ServiceName string `json:"serviceName"`
	Namespace   string `json:"namespace"`
}

type templateIngressRule struct {
	FromEndpoints []templateEndpointSelector `json:"fromEndpoints"`
	FromCIDRs     []string                   `json:"fromCIDRs"`
	FromEntities  []string                   `json:"fromEntities"`
	ToPorts       []templatePortRule         `json:"toPorts"`
}

type templateEgressRule struct {
	ToEndpoints []templateEndpointSelector `json:"toEndpoints"`
	ToCIDRs     []string                   `json:"toCIDRs"`
	ToEntities  []string                   `json:"toEntities"`
	ToServices  []templateServiceRef       `json:"toServices"`
	ToPorts     []templatePortRule         `json:"toPorts"`
}

type templatePolicyModel struct {
	// Kind mirrors the template file's own apiVersion/kind — "CiliumNetworkPolicy"
	// or "CiliumClusterwideNetworkPolicy" — so the frontend knows which one to
	// regenerate (see ui/src/policy.ts's generateCiliumNetworkPolicyYAML). A CNP
	// template that omits kind: entirely defaults here, matching every existing
	// template file, which all set it explicitly.
	Kind         string                `json:"kind"`
	Name         string                `json:"name"`
	Namespace    string                `json:"namespace"`
	Description  string                `json:"description"`
	TargetLabels map[string]string     `json:"targetLabels"`
	IngressRules []templateIngressRule `json:"ingressRules"`
	EgressRules  []templateEgressRule  `json:"egressRules"`
	// EgressDenyAll mirrors spec.egressDeny being present (always as the one
	// empty-match catchall rule the editor itself ever emits — see policy.ts).
	// Needed because, unlike ingress, an empty egressRules list means
	// "default allow" in this editor's model (and in real Cilium semantics —
	// enforcement is per-direction, keyed on whether that direction's rule
	// key exists at all): there'd be no other way to tell "egress not
	// configured yet" apart from "egress deliberately denied" once both
	// round-trip through this JSON shape as an empty array.
	EgressDenyAll bool `json:"egressDenyAll"`
}

type genericTemplateOut struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Category    string              `json:"category"`
	Policy      templatePolicyModel `json:"policy"`
}

type ingressTemplateOut struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Rule        templateIngressRule `json:"rule"`
}

type egressTemplateOut struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Rule        templateEgressRule `json:"rule"`
}

type templatesResponse struct {
	Generic []genericTemplateOut `json:"generic"`
	Ingress []ingressTemplateOut `json:"ingress"`
	Egress  []egressTemplateOut  `json:"egress"`
}

// templatesFS resolves the directory tree loadTemplates reads from: an
// external directory if templatesDir is non-empty, else the built-in
// defaults embedded at build time.
func templatesFS(templatesDir string) (fs.FS, error) {
	if templatesDir == "" {
		sub, err := fs.Sub(defaultTemplatesFS, "templates")
		if err != nil {
			return nil, fmt.Errorf("embedded default templates: %w", err)
		}
		return sub, nil
	}
	fsys := os.DirFS(templatesDir)
	if _, err := fs.Stat(fsys, "."); err != nil {
		return nil, fmt.Errorf("templates dir %q: %w", templatesDir, err)
	}
	return fsys, nil
}

// loadTemplates reads every *.yaml/*.yml file under dirFS's "generic/",
// "ingress/" and "egress/" subdirectories and converts each from real
// CiliumNetworkPolicy YAML into the JSON shape the UI's templates.ts
// consumes. A single malformed file is logged and skipped rather than
// failing the whole load — one bad preset shouldn't take down every other
// one.
func loadTemplates(logger *slog.Logger, dirFS fs.FS) templatesResponse {
	// Pre-initialized to empty slices, never nil: encoding/json renders a
	// nil slice as JSON null, and the frontend always treats these as
	// arrays (.map, .length) without a null check.
	out := templatesResponse{
		Generic: []genericTemplateOut{},
		Ingress: []ingressTemplateOut{},
		Egress:  []egressTemplateOut{},
	}

	for _, f := range loadYAMLFiles(logger, dirFS, "generic") {
		cnp, err := parseTemplateCNP(f.data)
		if err != nil {
			logger.Warn("skipping invalid generic template", "file", f.name, "error", err)
			continue
		}
		out.Generic = append(out.Generic, genericTemplateOut{
			ID:          f.id,
			Name:        templateDisplayName(cnp, f.id),
			Description: cnp.Spec.Description,
			Category:    cnp.ObjectMeta.Annotations[guardbeeCategoryAnnotation],
			Policy:      convertPolicy(cnp),
		})
	}

	for _, f := range loadYAMLFiles(logger, dirFS, "ingress") {
		cnp, err := parseTemplateCNP(f.data)
		if err != nil {
			logger.Warn("skipping invalid ingress rule template", "file", f.name, "error", err)
			continue
		}
		if len(cnp.Spec.Ingress) == 0 {
			logger.Warn("skipping ingress rule template with no spec.ingress rules", "file", f.name)
			continue
		}
		out.Ingress = append(out.Ingress, ingressTemplateOut{
			ID:          f.id,
			Name:        templateDisplayName(cnp, f.id),
			Description: cnp.Spec.Description,
			Rule:        convertIngressRule(cnp.Spec.Ingress[0]),
		})
	}

	for _, f := range loadYAMLFiles(logger, dirFS, "egress") {
		cnp, err := parseTemplateCNP(f.data)
		if err != nil {
			logger.Warn("skipping invalid egress rule template", "file", f.name, "error", err)
			continue
		}
		if len(cnp.Spec.Egress) == 0 {
			logger.Warn("skipping egress rule template with no spec.egress rules", "file", f.name)
			continue
		}
		out.Egress = append(out.Egress, egressTemplateOut{
			ID:          f.id,
			Name:        templateDisplayName(cnp, f.id),
			Description: cnp.Spec.Description,
			Rule:        convertEgressRule(cnp.Spec.Egress[0]),
		})
	}

	return out
}

type templateFile struct {
	id   string // filename without extension, used as the preset's stable id
	name string // filename, for log messages
	data []byte
}

// loadYAMLFiles reads every *.yaml/*.yml file directly under dirFS/subdir,
// sorted by filename for a stable, predictable order in the UI. A missing
// subdirectory is not an error — an external --templates-dir need not define
// all three categories.
func loadYAMLFiles(logger *slog.Logger, dirFS fs.FS, subdir string) []templateFile {
	entries, err := fs.ReadDir(dirFS, subdir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			logger.Warn("reading templates subdirectory", "subdir", subdir, "error", err)
		}
		return nil
	}

	var files []templateFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := path.Ext(e.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		data, err := fs.ReadFile(dirFS, path.Join(subdir, e.Name()))
		if err != nil {
			logger.Warn("reading template file", "subdir", subdir, "file", e.Name(), "error", err)
			continue
		}
		files = append(files, templateFile{
			id:   strings.TrimSuffix(e.Name(), ext),
			name: e.Name(),
			data: data,
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].id < files[j].id })
	return files
}

func parseTemplateCNP(data []byte) (*ciliumv2.CiliumNetworkPolicy, error) {
	var cnp ciliumv2.CiliumNetworkPolicy
	if err := yaml.Unmarshal(data, &cnp); err != nil {
		return nil, err
	}
	if cnp.Spec == nil {
		return nil, fmt.Errorf("missing spec")
	}
	return &cnp, nil
}

func templateDisplayName(cnp *ciliumv2.CiliumNetworkPolicy, fallbackID string) string {
	if name := cnp.ObjectMeta.Annotations[guardbeeDisplayNameAnnotation]; name != "" {
		return name
	}
	if name := cnp.ObjectMeta.Annotations[templateDisplayNameAnnotation]; name != "" {
		return name
	}
	if cnp.ObjectMeta.Name != "" {
		return cnp.ObjectMeta.Name
	}
	return fallbackID
}

func convertPolicy(cnp *ciliumv2.CiliumNetworkPolicy) templatePolicyModel {
	m := templatePolicyModel{
		Kind:          templateKind(cnp),
		Name:          cnp.ObjectMeta.Name,
		Namespace:     cnp.ObjectMeta.Namespace,
		Description:   cnp.Spec.Description,
		TargetLabels:  map[string]string{},
		IngressRules:  []templateIngressRule{},
		EgressRules:   []templateEgressRule{},
		EgressDenyAll: len(cnp.Spec.EgressDeny) > 0,
	}
	if cnp.Spec.EndpointSelector.LabelSelector != nil {
		for k, v := range cnp.Spec.EndpointSelector.MatchLabels {
			if k == templateNamespaceLabelKey {
				// A CiliumClusterwideNetworkPolicy has no metadata.namespace
				// of its own, so a template that pins one explicit namespace
				// (see generic/ccnp-*.yaml) has to say so via this label on
				// the target selector instead. Folding it into the same
				// Namespace field a CNP's metadata.namespace already
				// produces gives the frontend one consistent "which
				// namespace is this scoped to" field regardless of kind.
				m.Namespace = v
				continue
			}
			m.TargetLabels[k] = v
		}
	}
	for _, r := range cnp.Spec.Ingress {
		m.IngressRules = append(m.IngressRules, convertIngressRule(r))
	}
	for _, r := range cnp.Spec.Egress {
		m.EgressRules = append(m.EgressRules, convertEgressRule(r))
	}
	return m
}

// convertRuleToPolicyModel builds the same templatePolicyModel shape
// convertPolicy produces, but from a bare api.Rule plus the name/namespace/
// kind a live CNP/CCNP carries outside that Rule — used by ui.go's
// handlePolicyForEdit ("Edit in Policy Editor" from the Policies tab) via
// policies.go's firstRuleSpec, which picks one api.Rule out of a live
// policy's Spec/Specs pair. Reuses convertIngressRule/convertEgressRule
// directly rather than duplicating their field-by-field conversion, the same
// "one real conversion path" convertPolicy itself already relies on.
func convertRuleToPolicyModel(kind, name, namespace string, rule *api.Rule) templatePolicyModel {
	m := templatePolicyModel{
		Kind:          kind,
		Name:          name,
		Namespace:     namespace,
		Description:   rule.Description,
		TargetLabels:  map[string]string{},
		IngressRules:  []templateIngressRule{},
		EgressRules:   []templateEgressRule{},
		EgressDenyAll: len(rule.EgressDeny) > 0,
	}
	if rule.EndpointSelector.LabelSelector != nil {
		for k, v := range rule.EndpointSelector.MatchLabels {
			if k == templateNamespaceLabelKey {
				m.Namespace = v
				continue
			}
			m.TargetLabels[k] = v
		}
	}
	for _, r := range rule.Ingress {
		m.IngressRules = append(m.IngressRules, convertIngressRule(r))
	}
	for _, r := range rule.Egress {
		m.EgressRules = append(m.EgressRules, convertEgressRule(r))
	}
	return m
}

// templateKind returns the template file's own apiVersion/kind, defaulting
// to the namespaced CiliumNetworkPolicy — every template file in this repo
// sets kind: explicitly, so the default only matters for a hand-added file
// under an external --templates-dir that omits it.
func templateKind(cnp *ciliumv2.CiliumNetworkPolicy) string {
	if cnp.TypeMeta.Kind != "" {
		return cnp.TypeMeta.Kind
	}
	return "CiliumNetworkPolicy"
}

func convertEndpointSelector(es api.EndpointSelector) templateEndpointSelector {
	out := templateEndpointSelector{MatchLabels: map[string]string{}}
	if es.LabelSelector == nil {
		return out
	}
	for k, v := range es.MatchLabels {
		if k == templateNamespaceLabelKey {
			out.Namespace = v
			continue
		}
		out.MatchLabels[k] = v
	}
	return out
}

func convertPortRules(prs []api.PortRule) []templatePortRule {
	out := []templatePortRule{}
	for _, pr := range prs {
		for _, p := range pr.Ports {
			proto := string(p.Protocol)
			if proto == "" {
				proto = "ANY"
			}
			out = append(out, templatePortRule{Port: p.Port, Protocol: proto})
		}
	}
	return out
}

func convertIngressRule(r api.IngressRule) templateIngressRule {
	out := templateIngressRule{
		FromEndpoints: []templateEndpointSelector{},
		FromCIDRs:     []string{},
		FromEntities:  []string{},
		ToPorts:       convertPortRules(r.ToPorts),
	}
	for _, es := range r.FromEndpoints {
		out.FromEndpoints = append(out.FromEndpoints, convertEndpointSelector(es))
	}
	for _, c := range r.FromCIDR {
		out.FromCIDRs = append(out.FromCIDRs, string(c))
	}
	for _, e := range r.FromEntities {
		out.FromEntities = append(out.FromEntities, string(e))
	}
	return out
}

func convertEgressRule(r api.EgressRule) templateEgressRule {
	out := templateEgressRule{
		ToEndpoints: []templateEndpointSelector{},
		ToCIDRs:     []string{},
		ToEntities:  []string{},
		ToServices:  []templateServiceRef{},
		ToPorts:     convertPortRules(r.ToPorts),
	}
	for _, es := range r.ToEndpoints {
		out.ToEndpoints = append(out.ToEndpoints, convertEndpointSelector(es))
	}
	for _, c := range r.ToCIDR {
		out.ToCIDRs = append(out.ToCIDRs, string(c))
	}
	for _, e := range r.ToEntities {
		out.ToEntities = append(out.ToEntities, string(e))
	}
	for _, svc := range r.ToServices {
		// Only the K8sService{name, namespace} form round-trips — a
		// K8sServiceSelector-based entry (selecting a whole set of Services
		// by label) is silently dropped here rather than erroring, same
		// "skip what this editor doesn't support yet" posture as an
		// unparseable template file elsewhere in this file.
		if svc.K8sService != nil {
			out.ToServices = append(out.ToServices, templateServiceRef{
				ServiceName: svc.K8sService.ServiceName,
				Namespace:   svc.K8sService.Namespace,
			})
		}
	}
	return out
}
