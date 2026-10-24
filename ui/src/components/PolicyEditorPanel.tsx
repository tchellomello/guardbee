import { useEffect, useMemo, useState, type Dispatch, type SetStateAction } from 'react'
import { fetchNamespaces, validatePolicy, type PolicyValidationResult } from '../api'
import { BLANK_POLICY, generateCiliumNetworkPolicyYAML, type EgressRule, type IngressRule, type PolicyModel } from '../policy'
import { useTemplates } from '../shared/useTemplates'
import { PolicyGraph } from './PolicyGraph'
import { PolicyTextModal } from './PolicyTextModal'

// The "Blank Policy"/"Reset form" option is always available locally (no
// fetch needed) — every other generic template comes from useTemplates().
const BLANK_PRESET = {
  id: 'blank',
  name: 'Blank Policy',
  description: 'Start from scratch with target workload and custom rules',
  policy: BLANK_POLICY,
}

interface PolicyEditorPanelProps {
  model: PolicyModel
  setModel: Dispatch<SetStateAction<PolicyModel>>
  autoSelectNodeId: string | null
  onConsumeAutoSelect: () => void
  onSendToVerdict: (namespace: string, yaml: string) => void
}

export function PolicyEditorPanel({
  model,
  setModel,
  autoSelectNodeId,
  onConsumeAutoSelect,
  onSendToVerdict,
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
  }

  function handleCopyYAML() {
    navigator.clipboard.writeText(generatedYAML)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  function handleUpdateTargetLabels(labels: Record<string, string>) {
    setModel((prev) => ({ ...prev, targetLabels: labels }))
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
      {/* Presets Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border border-line bg-panel p-4 rise-in">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-display text-[0.65rem] font-bold uppercase tracking-wider text-ink-dim">
            Presets & Starters:
          </span>
          {genericPresets.map((tmpl) => (
            <button
              key={tmpl.id}
              type="button"
              onClick={() => handleLoadPreset(tmpl.id)}
              title={tmpl.description}
              className="border border-line bg-void/60 px-2.5 py-1 text-xs font-medium text-ink-dim hover:border-signal hover:text-signal transition-colors cursor-pointer"
            >
              {tmpl.name}
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={() => handleLoadPreset('blank')}
          className="font-display text-[0.65rem] font-bold uppercase tracking-wider text-ink-dim hover:text-drop transition-colors cursor-pointer"
        >
          Reset form
        </button>
      </div>

      {/* Left column: metadata, then the topology map (the editor for
          everything else) stacked below it. Right column: the YAML output,
          sticky, spanning the full height of the left column instead of
          sitting next to just the metadata card and leaving empty space
          beside the graph. */}
      <div className="grid grid-cols-1 items-start gap-6 2xl:grid-cols-[1fr_460px]">
        <div className="space-y-6">
          <div className="border border-line bg-panel p-5 space-y-4 rise-in">
            <div className="border-b border-line pb-2 font-display text-xs font-bold uppercase tracking-wider text-signal">
              Policy Metadata & Scope
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
                  Namespace
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
              ingressPresets={templates.ingress}
              egressPresets={templates.egress}
              autoSelectNodeId={autoSelectNodeId}
              onConsumeAutoSelect={onConsumeAutoSelect}
              onUpdateTargetLabels={handleUpdateTargetLabels}
              onAddIngressRule={handleAddIngressRule}
              onUpdateIngressRule={handleUpdateIngressRule}
              onRemoveIngressRule={handleRemoveIngressRule}
              onAddEgressRule={handleAddEgressRule}
              onUpdateEgressRule={handleUpdateEgressRule}
              onRemoveEgressRule={handleRemoveEgressRule}
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
                <span>Valid CiliumNetworkPolicy spec ({validation.ruleCount} rule(s) parsed)</span>
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

          {/* Formatted YAML code box */}
          <div
            onClick={() => setYamlModalOpen(true)}
            title="Click to open a wider view"
            className="cursor-pointer border border-line bg-void p-4 font-mono text-xs overflow-x-auto max-h-[600px] shadow-inner text-ink leading-relaxed"
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
