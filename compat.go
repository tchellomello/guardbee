package main

// Phase 2 of GitHub issue #2: real adaptive gating, not just the Phase 1
// warning. A small, growable table of version-gated policy constructs,
// checked at the real decision point — verdict.go's decodeCandidateYAML,
// shared by every caller (the CLI's parseCandidateYAML wrapper and ui.go's
// handlePolicyParse) — against an effective version — pinnedCiliumVersion
// today, since the gate's one real entry below needs
// no live cluster to evaluate and threading a Phase 0 detection call
// through parseCandidateYAML would mean a hubble port-forward on every
// candidate parse, including the UI's keystroke-debounced
// POST /api/policy/validate. A gate that genuinely needs the live detected
// version instead of the pinned fallback can take an explicit version
// parameter when it's added — checkFeatureGate already accepts one rather
// than hardcoding pinnedCiliumVersion internally.
//
// Today's one real entry: FromRequires/ToRequires. Confirmed by hand
// against this project's actual vendored source before writing this gate
// (not assumed): the vendored pkg/policy/api (ingress.go/egress.go) marks
// both Deprecated with `+kubebuilder:validation:MaxItems=0` in pinned
// v1.20.2 — a real cluster's CRD schema rejects any non-empty value at
// admission. More importantly for this tool specifically: Parse() does
// NOT reject, error, or panic on a non-empty value (verified with a
// throwaway test against parseCandidateYAML) — it succeeds silently, and
// pkg/k8s/apis/cilium.io/utils.ParseToCiliumRule, the function Parse()
// calls to build the real api.Rule the policy engine resolves, rebuilds
// every IngressRule/EgressRule field by field and simply never copies
// FromRequires/ToRequires across. The result: a candidate that names
// FromRequires/ToRequires parses clean, and ResolvePolicy/DistillPolicy
// never see the constraint at all — the verdict GuardBee would print is
// silently computed as if the author's peer-narrowing never existed. That
// is exactly the "silently misbehave" failure mode this feature exists to
// close off: gating it before Parse() turns it into an explicit, typed
// rejection naming the construct, instead.

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/blang/semver/v4"
	"github.com/cilium/cilium/pkg/policy/api"
	"sigs.k8s.io/yaml"
)

// featureGateKind distinguishes the two ways a gate's construct can be
// detected, because they need genuinely different code to look for them —
// see checkFeatureGates/checkRawFieldGates below.
type featureGateKind int

const (
	// typedFieldGateKind: the construct is deprecated but still has a live
	// Go struct field in the vendored api.Rule (e.g. FromRequires/
	// ToRequires, blocked at CRD admission via
	// +kubebuilder:validation:MaxItems=0 but still populated by Parse()) —
	// detectable by inspecting the already-unmarshaled api.Rules.
	typedFieldGateKind featureGateKind = iota
	// rawFieldGateKind: the construct's Go struct field is gone entirely as
	// of the gate's minVersion — there's nothing left in api.Rule to
	// inspect, so it must be caught in the candidate's raw YAML before
	// unmarshal silently discards it.
	rawFieldGateKind
)

// featureGate is one version-gated policy construct. minVersion/maxVersion
// are inclusive major.minor bounds ("" means unbounded on that side) —
// major.minor only, matching versionsSkewed's own granularity in
// clusterversion.go, since a patch release is never where a CRD schema's
// validation markers change.
type featureGate struct {
	name                   string // identifies the gate in rejection errors
	minVersion, maxVersion string
	reason                 string // why it's gated, surfaced verbatim in the rejection error
	kind                   featureGateKind
	// detectTyped is set (and used) only when kind == typedFieldGateKind.
	detectTyped func(*api.Rule) bool
	// rawKeys is set (and used) only when kind == rawFieldGateKind — the
	// toPorts[].rules map keys this gate watches for in the raw YAML.
	rawKeys []string
}

// featureGates is the table itself. Grown by adding entries here, not by
// adding new gating code paths — checkFeatureGates/checkRawFieldGates read
// this table generically rather than special-casing a field name, so a new
// gate needs no new plumbing beyond picking the right kind. Also the single
// source of truth for GET /api/compat (ui.go's handleCompat) — the UI's
// Compatibility page and the CLI's `guardbee compat` both list these
// entries verbatim, so "why was my candidate rejected" never has to be
// reverse-engineered from an error string alone. Proactively disabling a
// gated field in the editor before submit is a real follow-up, not done
// here — moot for the current entries, since the editor never generates
// any of them in the first place (see ui/src/policy.ts).
//
// New entries are found by diffing the vendored pkg/policy/api between
// Cilium versions — see scripts/compat-scan.sh, which automates that diff
// but deliberately stops at a human-readable report: it finds candidates,
// it doesn't write the "why" explanation or edit this table itself.
var featureGates = []featureGate{
	{
		name:       "fromRequires/toRequires",
		minVersion: "1.20",
		reason: "FromRequires/ToRequires are deprecated from Cilium 1.20 onward and silently dropped by " +
			"ParseToCiliumRule before the real policy engine ever sees them (Parse() itself never errors on " +
			"them) — a verdict computed against a candidate using them would misrepresent what it actually does",
		kind:        typedFieldGateKind,
		detectTyped: hasRequires,
	},
	{
		name:       "toPorts[].rules.l7 (generic L7 rules)",
		minVersion: "1.20",
		reason: "The generic key-value L7 rule type (PortRuleL7, L7Rules.L7) was removed from " +
			"pkg/policy/api entirely by Cilium 1.20 — confirmed by diffing the vendored source against " +
			"1.19.1, where the type and field still existed. Unlike FromRequires/ToRequires there's no Go " +
			"struct field left to detect this on once Parse() runs, so this is checked on the raw YAML",
		kind:    rawFieldGateKind,
		rawKeys: []string{"l7"},
	},
	{
		name:       "toPorts[].rules.kafka",
		minVersion: "1.20",
		reason: "Kafka-aware L7 rules (L7Rules.Kafka, kafka.PortRule) were removed from pkg/policy/api " +
			"entirely by Cilium 1.20 — confirmed by diffing the vendored source against 1.19.1, where the " +
			"field still existed. Same silent-drop risk and raw-YAML detection as the generic l7 gate above",
		kind:    rawFieldGateKind,
		rawKeys: []string{"kafka"},
	},
}

// gateApplies reports whether version (major.minor only) falls inside
// gate's [minVersion, maxVersion] bound. version failing to parse is
// treated as "applies" — the conservative choice, since callers only ever
// pass pinnedCiliumVersion (a hand-maintained constant) or a
// detectClusterCiliumVersion-validated string, so a parse failure here
// would mean one of those invariants broke, not a real "this version is
// exempt."
func gateApplies(version string, gate featureGate) bool {
	v, err := semver.ParseTolerant(version)
	if err != nil {
		return true
	}
	if gate.minVersion != "" {
		min, err := semver.ParseTolerant(gate.minVersion)
		if err == nil && versionLess(v, min) {
			return false
		}
	}
	if gate.maxVersion != "" {
		max, err := semver.ParseTolerant(gate.maxVersion)
		if err == nil && versionLess(max, v) {
			return false
		}
	}
	return true
}

func versionLess(a, b semver.Version) bool {
	if a.Major != b.Major {
		return a.Major < b.Major
	}
	return a.Minor < b.Minor
}

// gateRejectionError names the gate and the version that triggered it, so
// a rejected candidate's error message is actionable rather than a bare
// "invalid policy" — matching this project's other typed parse errors
// (see k8s.io/apis/cilium.io/v2's ErrParse).
type gateRejectionError struct {
	gate    string
	version string
	reason  string
}

func (e *gateRejectionError) Error() string {
	return fmt.Sprintf("candidate uses %s, gated on Cilium %s: %s", e.gate, e.version, e.reason)
}

// checkFeatureGates rejects a candidate that sets a version-gated
// construct the effective version doesn't support, checked directly
// against the raw api.Rules (before Parse()'s own downstream handling —
// ParseToCiliumRule silently drops FromRequires/ToRequires rather than
// erroring, so this must run against the parsed-but-not-yet-stripped rule
// the CRD type's Parse() builds, not after). version is the effective
// Cilium version to gate against — pinnedCiliumVersion from every call
// site today (see this file's doc comment), but left as a parameter
// rather than hardcoded so a future caller with a real detected version in
// hand can pass that instead.
func checkFeatureGates(rules api.Rules, version string) error {
	for _, gate := range featureGates {
		if gate.kind != typedFieldGateKind || !gateApplies(version, gate) {
			continue
		}
		for _, r := range rules {
			if gate.detectTyped(r) {
				return &gateRejectionError{gate: gate.name, version: version, reason: gate.reason}
			}
		}
	}
	return nil
}

// checkRawFieldGates is checkFeatureGates' counterpart for rawFieldGateKind
// entries — constructs removed entirely from the vendored api.Rule/L7Rules,
// not just deprecated-but-present like FromRequires/ToRequires. Operates on
// the candidate's raw bytes directly, decoded into rawCandidateSpec's
// deliberately minimal shape, because by the time the real typed unmarshal
// has populated api.Rule, a field like toPorts[].rules.l7 or .kafka that no
// longer exists in that struct has already been silently dropped — this is
// the only point it's still visible at all. Kind-agnostic on purpose: a
// CiliumNetworkPolicy and a CiliumClusterwideNetworkPolicy candidate share
// the same spec/specs shape, so one check covers both decodeCandidateYAML
// branches without duplicating it per kind.
func checkRawFieldGates(raw []byte, version string) error {
	var spec rawCandidateSpec
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		// A real parse error here is decodeCandidateYAML's own typed
		// unmarshal's job to catch and report properly — this check is
		// best-effort only, never the source of truth for "is this valid
		// YAML," so a decode failure here just means "nothing to gate."
		return nil
	}
	for _, gate := range featureGates {
		if gate.kind != rawFieldGateKind || !gateApplies(version, gate) {
			continue
		}
		for _, key := range gate.rawKeys {
			if spec.usesRawKey(key) {
				return &gateRejectionError{gate: gate.name, version: version, reason: gate.reason}
			}
		}
	}
	return nil
}

// rawCandidateSpec is a minimal, deliberately incomplete mirror of a
// CNP/CCNP's spec/specs shape — just enough structure to see whether a
// toPorts rule sets a key checkRawFieldGates' table cares about. This is
// NOT a second policy parser: it never builds an api.Rule, never feeds the
// real engine, and exists only because some deprecated-and-now-removed
// fields have no Go struct field left in the vendored types to inspect
// once Parse() has run.
type rawCandidateSpec struct {
	Spec  *rawRule   `json:"spec,omitempty"`
	Specs []*rawRule `json:"specs,omitempty"`
}

type rawRule struct {
	Ingress []rawPortRuleHolder `json:"ingress,omitempty"`
	Egress  []rawPortRuleHolder `json:"egress,omitempty"`
}

type rawPortRuleHolder struct {
	ToPorts []struct {
		Rules map[string]json.RawMessage `json:"rules,omitempty"`
	} `json:"toPorts,omitempty"`
}

// usesRawKey reports whether any ingress/egress toPorts rule across spec
// and specs sets the given rules.<key>.
func (s *rawCandidateSpec) usesRawKey(key string) bool {
	all := s.Specs
	if s.Spec != nil {
		all = append([]*rawRule{s.Spec}, all...)
	}
	for _, spec := range all {
		if spec == nil {
			continue
		}
		for _, holder := range spec.Ingress {
			if holderUsesRawKey(holder, key) {
				return true
			}
		}
		for _, holder := range spec.Egress {
			if holderUsesRawKey(holder, key) {
				return true
			}
		}
	}
	return false
}

func holderUsesRawKey(holder rawPortRuleHolder, key string) bool {
	for _, tp := range holder.ToPorts {
		if _, ok := tp.Rules[key]; ok {
			return true
		}
	}
	return false
}

// rawRules combines a CNP/CCNP's Spec (singular, may be nil) and Specs
// (plural, may be nil) into one api.Rules slice — the same optional-either-
// or-both shape policies.go's summarizeRuleSpecs already reduces, needed
// here so checkFeatureGates can be called once per candidate instead of
// once per Spec/Specs combination at each parseCandidateYAML call site.
func rawRules(spec *api.Rule, specs api.Rules) api.Rules {
	var all api.Rules
	if spec != nil {
		all = append(all, spec)
	}
	return append(all, specs...)
}

// hasRequires reports whether r sets FromRequires on any ingress rule or
// ToRequires on any egress rule — the one gated construct featureGates
// currently knows about.
func hasRequires(r *api.Rule) bool {
	for _, ing := range r.Ingress {
		if len(ing.FromRequires) > 0 {
			return true
		}
	}
	for _, egr := range r.Egress {
		if len(egr.ToRequires) > 0 {
			return true
		}
	}
	return false
}

// runCompat is the CLI's counterpart to GET /api/compat (ui.go's
// handleCompat) / the UI's Compatibility tab (CompatPanel.tsx) — same
// featureGates table, no cluster connection needed since it's static data,
// so unlike every other subcommand this one takes no --kubeconfig/
// --namespace flags at all.
func runCompat(args []string) {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			fmt.Printf("Usage: %s compat\n\nList the version-gated policy constructs GuardBee knows about: what's\ngated, which Cilium versions it applies to, and why. The engine is always\npinned to Cilium %s — a candidate using one of these is rejected rather\nthan parsed into a verdict that would misrepresent what it actually does.\n", binName, pinnedCiliumVersion)
			return
		}
	}

	fmt.Printf("%s: engine pinned to Cilium %s\n\n", binName, pinnedCiliumVersion)
	for i, g := range featureGates {
		if i > 0 {
			fmt.Println()
		}
		fmt.Fprintf(os.Stdout, "%s\n", g.name)
		switch {
		case g.minVersion != "" && g.maxVersion != "":
			fmt.Printf("  gated: Cilium %s through %s\n", g.minVersion, g.maxVersion)
		case g.minVersion != "":
			fmt.Printf("  gated: Cilium %s onward\n", g.minVersion)
		case g.maxVersion != "":
			fmt.Printf("  gated: up to Cilium %s\n", g.maxVersion)
		}
		fmt.Printf("  why:   %s\n", g.reason)
	}
}
