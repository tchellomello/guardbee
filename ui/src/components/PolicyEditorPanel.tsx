import { useEffect, useMemo, useState, type Dispatch, type SetStateAction } from 'react'
import { fetchNamespaces, validatePolicy, type PolicyValidationResult } from '../api'
import { BLANK_POLICY, generateCiliumNetworkPolicyYAML, type EgressRule, type IngressRule, type PolicyKind, type PolicyModel } from '../policy'
import { useTemplates } from '../shared/useTemplates'
import { PolicyGraph } from './PolicyGraph'
import { PresetMenu, type PresetMenuItem } from './PresetMenu'
import { PolicyTextModal } from './PolicyTextModal'

// The "Blank Policy"/"Reset form" option is always available locally (no
// fetch needed) — every other generic template comes from useTemplates().
const BLANK_PRESET = {
  id: 'blank',
  name: 'Blank Policy',
  description: 'Start from scratch with target workload and custom rules',
  category: 'Starters',
  policy: BLANK_POLICY,
}

// Rule presets that rely on a CiliumNetworkPolicy-only implicit namespace
// scoping (see templates/ingress/same-namespace.yaml's own comment, and
// ccnp-namespace-isolation.yaml's for why it doesn't carry over): applying
// one of these to a CiliumClusterwideNetworkPolicy would silently produce
// "allow from/to any namespace" instead of "same namespace," so they're
// hidden from the preset list while editing a CCNP rather than left in to
// trap someone. The generic/ccnp-namespace-isolation.yaml starter is the
// CCNP-safe way to get the same intent.
const CNP_ONLY_RULE_PRESET_IDS = new Set(['same-namespace'])

interface PolicyEditorPanelProps {
  model: PolicyModel
  setModel: Dispatch<SetStateAction<PolicyModel>>
  autoSelectNodeId: string | null
  onConsumeAutoSelect: () => void
  onSendToVerdict: (namespace: string, yaml: string) => void
  // Set only while the draft is editing a policy loaded via "Edit in Policy
  // Editor" (Policies tab) — the snapshot of what's actually live, so a
  // real diff can be shown instead of only ever comparing against nothing.
  originalLiveModel: PolicyModel | null
  onClearOriginalLiveModel: () => void
}

// Diffs the current draft's rule ids against the live snapshot it was
// loaded from. Comparing by id (not content) works because loading a live
// policy assigns each of its rules a fresh, stable id once (App.tsx's
// toPolicyModel) that then survives edits — so "a rule id present now but
// not in the snapshot" means added, "present in the snapshot but gone now"
// means removed, and "present in both but with different content" means
// modified. Deliberately a rule-count-level diff, not a full
// NEWLY_DROPPED/NEWLY_ALLOWED-style flow diff — that would need re-running
// the verdict engine against two candidates, a heavier feature than "did my
// edits actually touch this live policy."
function diffAgainstOriginal(current: PolicyModel, original: PolicyModel) {
  function diffRules<T extends { id: string }>(currentRules: T[], originalRules: T[]) {
    const originalById = new Map(originalRules.map((r) => [r.id, r]))
    const currentById = new Map(currentRules.map((r) => [r.id, r]))
    let added = 0
    let modified = 0
    for (const [id, rule] of currentById) {
      const orig = originalById.get(id)
      if (!orig) added++
      else if (JSON.stringify(rule) !== JSON.stringify(orig)) modified++
    }
    let removed = 0
    for (const id of originalById.keys()) {
      if (!currentById.has(id)) removed++
    }
    return { added, removed, modified }
  }
  return {
    ingress: diffRules(current.ingressRules, original.ingressRules),
    egress: diffRules(current.egressRules, original.egressRules),
  }
}

export function PolicyEditorPanel({
  model,
  setModel,
  autoSelectNodeId,
  onConsumeAutoSelect,
  onSendToVerdict,
  originalLiveModel,
  onClearOriginalLiveModel,
}: PolicyEditorPanelProps) {
  const [availableNamespaces, setAvailableNamespaces] = useState<string[]>([])
  const [copied, setCopied] = useState(false)
  const [validation, setValidation] = useState<PolicyValidationResult | null>(null)
  // The YAML that `validation` is actually a result for. Comparing this to
  // the current generatedYAML (every render, not just inside the effect)
  // is what lets us know a check is stale/in-flight on the very first
  // render after an edit — an isValidating flag toggled only from inside
  // the effect would lag one paint behind the model change, letting the
  // previous (now-stale) valid/invalid banner flash before it.
  const [validatedYAML, setValidatedYAML] = useState<string | null>(null)
  const [yamlModalOpen, setYamlModalOpen] = useState(false)
  const { templates } = useTemplates()
  const genericPresets = useMemo(() => [BLANK_PRESET, ...templates.generic], [templates.generic])
  const presetMenuItems: PresetMenuItem[] = useMemo(
    () =>
      genericPresets.map((p) => ({
        id: p.id,
        name: p.name,
        description: p.description,
        category: p.category,
        isClusterwide: p.policy.kind === 'CiliumClusterwideNetworkPolicy',
      })),
    [genericPresets]
  )
  const ingressPresets = useMemo(
    () =>
      model.kind === 'CiliumClusterwideNetworkPolicy'
        ? templates.ingress.filter((t) => !CNP_ONLY_RULE_PRESET_IDS.has(t.id))
        : templates.ingress,
    [templates.ingress, model.kind]
  )
  const egressPresets = useMemo(
    () =>
      model.kind === 'CiliumClusterwideNetworkPolicy'
        ? templates.egress.filter((t) => !CNP_ONLY_RULE_PRESET_IDS.has(t.id))
        : templates.egress,
    [templates.egress, model.kind]
  )

  useEffect(() => {
    fetchNamespaces()
      .then((res) => setAvailableNamespaces(res.namespaces))
      .catch(() => {})
  }, [])

  const generatedYAML = useMemo(() => generateCiliumNetworkPolicyYAML(model), [model])
  const isValidating = validatedYAML !== generatedYAML

  // Real-time validation against Cilium's native engine
  useEffect(() => {
    let cancelled = false
    const timer = setTimeout(() => {
      validatePolicy(model.namespace, generatedYAML)
        .then((res) => {
          if (!cancelled) {
            setValidation(res)
            setValidatedYAML(generatedYAML)
          }
        })
        .catch((err) => {
          if (!cancelled) {
            setValidation({ valid: false, error: err instanceof Error ? err.message : String(err) })
            setValidatedYAML(generatedYAML)
          }
        })
    }, 150)

    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [model.namespace, generatedYAML])

  function handleLoadPreset(id: string) {
    const preset = genericPresets.find((p) => p.id === id)
    if (!preset) return

    const cloned: PolicyModel = JSON.parse(JSON.stringify(preset.policy))
    cloned.ingressRules = cloned.ingressRules.map((r, i) => ({ ...r, id: `ingress-${Date.now()}-${i}` }))
    cloned.egressRules = cloned.egressRules.map((r, i) => ({ ...r, id: `egress-${Date.now()}-${i}` }))
    if (model.namespace && preset.id !== 'homeassistant-iot') {
      cloned.namespace = model.namespace
    }
    setModel(cloned)
    // Loading any preset (including "Reset form") abandons whatever live
    // policy the previous draft was tracking — the diff below would
    // otherwise keep comparing an unrelated draft against it.
    onClearOriginalLiveModel()
  }

  const liveDiff = useMemo(
    () => (originalLiveModel ? diffAgainstOriginal(model, originalLiveModel) : null),
    [model, originalLiveModel]
  )
  const liveDiffIsEmpty =
    !liveDiff ||
    (liveDiff.ingress.added === 0 &&
      liveDiff.ingress.removed === 0 &&
      liveDiff.ingress.modified === 0 &&
      liveDiff.egress.added === 0 &&
      liveDiff.egress.removed === 0 &&
      liveDiff.egress.modified === 0)

  function handleCopyYAML() {
    navigator.clipboard.writeText(generatedYAML)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  function handleUpdateTargetLabels(labels: Record<string, string>) {
    setModel((prev) => ({ ...prev, targetLabels: labels }))
  }

  function handleSetKind(kind: PolicyKind) {
    setModel((prev) => ({ ...prev, kind }))
  }

  function handleToggleEgressDenyAll() {
    // Mutually exclusive with egressRules: the toggle button is only shown
    // when egressRules is already empty (see PolicyGraph.tsx), but clearing
    // it here too keeps this safe to call from anywhere in the future.
    setModel((prev) => ({ ...prev, egressDenyAll: !prev.egressDenyAll, egressRules: [] }))
  }

  // Ingress Rules helpers — return the new/removed rule's id so the graph
  // can auto-select the node it corresponds to right after the change.
  function handleAddIngressRule(rule?: IngressRule): string {
    // A blank rule (no preset) starts with nothing pre-selected — no
    // placeholder peer, no guessed port — so the only way to actually
    // allow traffic is to deliberately pick entities/labels/ports in the
    // rule editor. A previous version pre-filled an empty-key peer and
    // port 80/TCP "to get you started," but that meant a user who clicked
    // + Add Rule and moved on without looking closely could ship a rule
    // that silently matched every pod in every namespace on port 80.
    const newRule: IngressRule = rule ?? {
      id: `ingress-${Date.now()}`,
      fromEndpoints: [],
      fromCIDRs: [],
      fromEntities: [],
      toPorts: [],
    }
    setModel((prev) => ({
      ...prev,
      ingressRules: [...prev.ingressRules, newRule],
    }))
    return newRule.id
  }

  function handleUpdateIngressRule(id: string, updated: IngressRule) {
    setModel((prev) => ({
      ...prev,
      ingressRules: prev.ingressRules.map((r) => (r.id === id ? updated : r)),
    }))
  }

  function handleRemoveIngressRule(id: string) {
    setModel((prev) => ({
      ...prev,
      ingressRules: prev.ingressRules.filter((r) => r.id !== id),
    }))
  }

  // Egress Rules helpers
  function handleAddEgressRule(rule?: EgressRule): string {
    // Same reasoning as handleAddIngressRule: a blank rule starts fully
    // empty rather than pre-filled with an empty-key peer and a guessed
    // port (53/UDP), so nothing is allowed until the user deliberately
    // selects entities/labels/ports.
    const newRule: EgressRule = rule ?? {
      id: `egress-${Date.now()}`,
      toEndpoints: [],
      toCIDRs: [],
      toEntities: [],
      toServices: [],
      toPorts: [],
    }
    setModel((prev) => ({
      ...prev,
      egressRules: [...prev.egressRules, newRule],
    }))
    return newRule.id
  }

  function handleUpdateEgressRule(id: string, updated: EgressRule) {
    setModel((prev) => ({
      ...prev,
      egressRules: prev.egressRules.map((r) => (r.id === id ? updated : r)),
    }))
  }

  function handleRemoveEgressRule(id: string) {
    setModel((prev) => ({
      ...prev,
      egressRules: prev.egressRules.filter((r) => r.id !== id),
    }))
  }

  return (
    <div className="space-y-6">
      {/* Left column: metadata, then the topology map (the editor for
          everything else) stacked below it. Right column: the YAML output,
          sticky, spanning the full height of the left column instead of
          sitting next to just the metadata card and leaving empty space
          beside the graph. */}
      <div className="grid grid-cols-1 items-start gap-6 2xl:grid-cols-[1fr_560px]">
        <div className="space-y-6">
          <div className="border border-line bg-panel p-5 space-y-4 rise-in">
            {/* Presets & Starters used to be its own full-width row above
                this card — on its own it was mostly empty space either side
                of one dropdown button, so it's folded into this card's own
                header instead: still a one-click dropdown, just not
                claiming a whole row for it. */}
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line pb-2">
              <span className="font-display text-xs font-bold uppercase tracking-wider text-signal">
                Policy Metadata & Scope
              </span>
              <div className="flex items-center gap-3">
                <PresetMenu presets={presetMenuItems} onSelect={handleLoadPreset} />
                <button
                  type="button"
                  onClick={() => handleLoadPreset('blank')}
                  className="font-display text-[0.65rem] font-bold uppercase tracking-wider text-ink-dim hover:text-drop transition-colors cursor-pointer"
                >
                  Reset form
                </button>
              </div>
            </div>
            <div>
              <label className="block mb-1 text-[0.65rem] font-semibold uppercase tracking-wider text-ink-dim">
                Policy Kind
              </label>
              <div className="inline-flex border border-line">
                {(['CiliumNetworkPolicy', 'CiliumClusterwideNetworkPolicy'] as const).map((kind, idx) => (
                  <button
                    key={kind}
                    type="button"
                    onClick={() => handleSetKind(kind)}
                    className={
                      (idx > 0 ? 'border-l border-line ' : '') +
                      'px-3 py-1.5 text-xs font-semibold transition-colors cursor-pointer ' +
                      (model.kind === kind ? 'bg-signal text-void' : 'bg-void text-ink-dim hover:text-ink')
                    }
                  >
                    {kind}
                  </button>
                ))}
              </div>
              <p className="mt-1 text-[0.65rem] text-ink-faint">
                {model.kind === 'CiliumClusterwideNetworkPolicy'
                  ? 'Cluster-scoped — no metadata.namespace. "Target Namespace" below becomes an explicit io.kubernetes.pod.namespace match instead, and needs setting on each peer selector too.'
                  : 'Namespace-scoped — applies only within the namespace below.'}
              </p>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block mb-1 text-[0.65rem] font-semibold uppercase tracking-wider text-ink-dim">
                  Policy Name
                </label>
                <input
                  type="text"
                  value={model.name}
                  onChange={(e) => setModel({ ...model, name: e.target.value })}
                  placeholder="allow-mosquitto-ingress"
                  className="w-full border border-line bg-void px-3 py-2 text-sm text-ink focus:border-signal focus:outline-none"
                />
              </div>
              <div>
                <label className="block mb-1 text-[0.65rem] font-semibold uppercase tracking-wider text-ink-dim">
                  {model.kind === 'CiliumClusterwideNetworkPolicy' ? 'Target Namespace (optional)' : 'Namespace'}
                </label>
                <input
                  type="text"
                  list="policy-namespaces"
                  value={model.namespace}
                  onChange={(e) => setModel({ ...model, namespace: e.target.value })}
                  placeholder="homeassistant"
                  className="w-full border border-line bg-void px-3 py-2 text-sm text-ink focus:border-signal focus:outline-none"
                />
                <datalist id="policy-namespaces">
                  {availableNamespaces.map((ns) => (
                    <option key={ns} value={ns} />
                  ))}
                </datalist>
              </div>
            </div>
            <div>
              <label className="block mb-1 text-[0.65rem] font-semibold uppercase tracking-wider text-ink-dim">
                Description (Optional)
              </label>
              <input
                type="text"
                value={model.description}
                onChange={(e) => setModel({ ...model, description: e.target.value })}
                placeholder="Allows telemetry and command ingest from Mosquitto broker"
                className="w-full border border-line bg-void px-3 py-2 text-sm text-ink focus:border-signal focus:outline-none"
              />
            </div>
          </div>

          {/* Policy Topology Map — the primary editor for the target
              selector and every ingress/egress rule. Click a node to edit
              it in place. */}
          <div className="border border-line bg-panel p-5 rise-in">
            <PolicyGraph
              policy={model}
              availableNamespaces={availableNamespaces}
              ingressPresets={ingressPresets}
              egressPresets={egressPresets}
              autoSelectNodeId={autoSelectNodeId}
              onConsumeAutoSelect={onConsumeAutoSelect}
              onUpdateTargetLabels={handleUpdateTargetLabels}
              onAddIngressRule={handleAddIngressRule}
              onUpdateIngressRule={handleUpdateIngressRule}
              onRemoveIngressRule={handleRemoveIngressRule}
              onAddEgressRule={handleAddEgressRule}
              onUpdateEgressRule={handleUpdateEgressRule}
              onRemoveEgressRule={handleRemoveEgressRule}
              onToggleEgressDenyAll={handleToggleEgressDenyAll}
            />
          </div>
        </div>

        {/* Live YAML Output & Action Buttons */}
        <div className="space-y-4 2xl:sticky 2xl:top-6">
          <div className="border border-line bg-panel p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="font-display text-xs font-bold uppercase tracking-wider text-ink">
                Candidate Policy Output
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setYamlModalOpen(true)}
                  title="Open a wider, read-only view of this YAML"
                  className="font-display text-[0.65rem] font-bold uppercase tracking-wider text-ink-dim hover:text-signal cursor-pointer"
                >
                  ⤢ Expand
                </button>
                <button
                  type="button"
                  onClick={handleCopyYAML}
                  className="border border-line bg-void px-2.5 py-1 text-[0.7rem] font-bold uppercase tracking-wider text-ink-dim hover:text-ink transition-colors cursor-pointer"
                >
                  {copied ? '✓ Copied!' : 'Copy YAML'}
                </button>
              </div>
            </div>

            {/* Diff against the live policy this draft was loaded from
                (see diffAgainstOriginal above) — only present while editing
                a policy loaded via the Policies tab's "Edit in Policy
                Editor," not for a blank/preset draft. */}
            {originalLiveModel && liveDiff && (
              <div
                className={`flex items-center justify-between gap-2 border px-3 py-2 text-xs ${
                  liveDiffIsEmpty
                    ? 'border-line bg-void text-ink-dim'
                    : 'border-signal/40 bg-signal/5 text-ink'
                }`}
              >
                <span>
                  Editing live policy <span className="font-mono text-ink">{originalLiveModel.name}</span>
                  {liveDiffIsEmpty ? (
                    ' — no changes yet.'
                  ) : (
                    <>
                      {' — '}
                      {[
                        liveDiff.ingress.added || liveDiff.egress.added
                          ? `+${liveDiff.ingress.added + liveDiff.egress.added} added`
                          : '',
                        liveDiff.ingress.removed || liveDiff.egress.removed
                          ? `-${liveDiff.ingress.removed + liveDiff.egress.removed} removed`
                          : '',
                        liveDiff.ingress.modified || liveDiff.egress.modified
                          ? `${liveDiff.ingress.modified + liveDiff.egress.modified} modified`
                          : '',
                      ]
                        .filter(Boolean)
                        .join(', ')}{' '}
                      rule(s) since it was loaded.
                    </>
                  )}
                </span>
                <button
                  type="button"
                  onClick={onClearOriginalLiveModel}
                  title="Stop tracking this as an edit of a live policy"
                  className="shrink-0 text-ink-faint hover:text-drop cursor-pointer"
                >
                  ✕
                </button>
              </div>
            )}

            {/* Real-time validation status banner */}
            {isValidating && (
              <div className="flex items-center gap-2 border border-line bg-void px-3 py-2 text-xs text-ink-dim">
                <span className="glow-pulse h-2 w-2 rounded-full bg-signal" />
                <span>Validating spec with Cilium engine…</span>
              </div>
            )}

            {!isValidating && validation && validation.valid && (
              <div className="flex items-center gap-2 border border-unchanged/40 bg-unchanged/10 px-3 py-2 text-xs text-unchanged font-semibold">
                <span>✓</span>
                <span>Valid {model.kind} spec ({validation.ruleCount} rule(s) parsed)</span>
              </div>
            )}

            {!isValidating && validation && !validation.valid && (
              <div className="border border-drop/40 bg-drop/10 p-3 text-xs text-drop space-y-1">
                <div className="flex items-center gap-1.5 font-bold">
                  <span>⚠️</span>
                  <span>Invalid Policy Spec</span>
                </div>
                <p className="font-mono text-[11px] leading-relaxed break-words">{validation.error}</p>
              </div>
            )}

            {/* CCNP blast-radius warning — a CiliumClusterwideNetworkPolicy
                with no target namespace matches its target labels in every
                namespace on the cluster, not just the one the author had in
                mind (see ccnp-namespace-isolation.yaml's own comment on this
                exact gotcha). Surfaced here, right above "Test in Verdict,"
                so it's seen before that click-through rather than only
                discoverable after the fact in the generated YAML. */}
            {model.kind === 'CiliumClusterwideNetworkPolicy' && !model.namespace && (
              <div className="flex items-start gap-2 border border-allow/40 bg-allow/10 px-3 py-2 text-xs text-allow">
                <span>⚠</span>
                <span>
                  No target namespace set — this clusterwide policy will match{' '}
                  <span className="font-semibold">every</span> namespace with these target labels, not just one.
                  Set a namespace above if that's not intended.
                </span>
              </div>
            )}

            {/* Test in Verdict action */}
            <button
              type="button"
              disabled={validation !== null && !validation.valid}
              onClick={() => onSendToVerdict(model.namespace, generatedYAML)}
              title={validation && !validation.valid ? validation.error : 'Test this policy against live cluster flows'}
              className="w-full bg-signal py-2.5 font-display text-xs font-bold tracking-[0.1em] text-void uppercase transition-opacity hover:opacity-90 shadow-sm cursor-pointer flex items-center justify-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <span>🚀</span>
              <span>Test in Verdict Simulator</span>
            </button>
            <p className="text-[0.68rem] text-ink-faint text-center">
              Loads this candidate policy straight into the Verdict tab to test against live cluster flows.
            </p>
          </div>

          {/* Formatted YAML code box — sized up from the original text-xs/
              p-4/max-h-[600px] (see the screenshot that prompted this: a lot
              of surrounding whitespace around small, cramped text once the
              right column had real room to use). */}
          <div
            onClick={() => setYamlModalOpen(true)}
            title="Click to open a wider view"
            className="cursor-pointer border border-line bg-void p-5 font-mono text-sm overflow-x-auto max-h-[760px] shadow-inner text-ink leading-loose"
            style={{
              // Right-edge fade so a long line (e.g. a long `description:`)
              // visually signals there's more to scroll to instead of just
              // vanishing past the edge. Always-on rather than conditional
              // on overflow — harmless when a line doesn't overflow.
              WebkitMaskImage: 'linear-gradient(to right, black calc(100% - 24px), transparent)',
              maskImage: 'linear-gradient(to right, black calc(100% - 24px), transparent)',
            }}
          >
            <pre className="text-ink selection:bg-signal/30 whitespace-pre">{generatedYAML}</pre>
          </div>
        </div>
      </div>

      <PolicyTextModal
        isOpen={yamlModalOpen}
        onClose={() => setYamlModalOpen(false)}
        value={generatedYAML}
        readOnly
        title="Candidate Policy YAML"
      />
    </div>
  )
}
