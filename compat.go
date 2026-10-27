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
	"fmt"

	"github.com/blang/semver/v4"
	"github.com/cilium/cilium/pkg/policy/api"
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
}

// featureGates is the table itself. Grown by adding entries here, not by
// adding new gating code paths — checkFeatureGates reads this table
// generically rather than special-casing a field name, so a second gate
// needs no new plumbing. Not yet surfaced to the frontend over its own
// endpoint (e.g. a GET /api/compat) — today the UI only learns about a
// gate the same way the CLI does, via the rejection error text coming back
// from POST /api/policy/validate/parse. Proactively disabling a gated
// field in the editor before submit is a real follow-up, not done here —
// moot for this table's one entry today, since the editor never generates
// FromRequires/ToRequires in the first place (see ui/src/policy.ts).
var featureGates = []featureGate{
	{
		name:       "fromRequires/toRequires",
		minVersion: "1.20",
		reason: "FromRequires/ToRequires are deprecated from Cilium 1.20 onward and silently dropped by " +
			"ParseToCiliumRule before the real policy engine ever sees them (Parse() itself never errors on " +
			"them) — a verdict computed against a candidate using them would misrepresent what it actually does",
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
		if !gateApplies(version, gate) {
			continue
		}
		for _, r := range rules {
			if hasRequires(r) {
				return &gateRejectionError{gate: gate.name, version: version, reason: gate.reason}
			}
		}
	}
	return nil
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
