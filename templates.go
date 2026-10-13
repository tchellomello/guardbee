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
	ToPorts     []templatePortRule         `json:"toPorts"`
}

type templatePolicyModel struct {
	Name         string                `json:"name"`
	Namespace    string                `json:"namespace"`
	Description  string                `json:"description"`
	TargetLabels map[string]string     `json:"targetLabels"`
	IngressRules []templateIngressRule `json:"ingressRules"`
	EgressRules  []templateEgressRule  `json:"egressRules"`
}

type genericTemplateOut struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
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
		Name:         cnp.ObjectMeta.Name,
		Namespace:    cnp.ObjectMeta.Namespace,
		Description:  cnp.Spec.Description,
		TargetLabels: map[string]string{},
		IngressRules: []templateIngressRule{},
		EgressRules:  []templateEgressRule{},
	}
	if cnp.Spec.EndpointSelector.LabelSelector != nil {
		for k, v := range cnp.Spec.EndpointSelector.MatchLabels {
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
	return out
}
