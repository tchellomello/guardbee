// Live CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy inventory — the
// one thing the CLI's "policies" subcommand could always show that the web
// UI couldn't at all before this tab: what's actually enforced on the
// cluster right now, not a candidate draft (Policy Editor) or a Verdict
// run's opaque baselineRuleCount.

import { useState } from 'react'
import { fetchPolicies, fetchPolicyForEdit, type EditablePolicyModel, type PolicyListItem } from '../api'
import { NamespaceScope } from './NamespaceScope'

export interface PoliciesPanelProps {
  // Loads a live policy straight into the Policy Editor tab for iteration —
  // previously the only way to tweak a running CNP/CCNP was to hand-copy
  // its YAML; this reuses the exact JSON shape a generic preset template
  // already loads through (see api.ts's EditablePolicyModel).
  onEditPolicy?: (model: EditablePolicyModel) => void
}

export function PoliciesPanel({ onEditPolicy }: PoliciesPanelProps = {}) {
  const [namespace, setNamespace] = useState('')
  // Defaults on, unlike Verdict/Flows' own all-namespaces toggles — this
  // tab's whole point is "what's actually enforced on the cluster right
  // now," and most clusters have only a handful of CNPs/CCNPs total, so
  // scoping down to one namespace first (and seeing nothing, or missing
  // the CCNPs entirely, since they're not namespaced to begin with) was
  // the wrong first impression for a cold "List policies" click.
  const [allNamespaces, setAllNamespaces] = useState(true)

  const [fetchedNamespace, setFetchedNamespace] = useState<string | null>(null)
  const [policies, setPolicies] = useState<PolicyListItem[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [editingKey, setEditingKey] = useState<string | null>(null)
  const [editError, setEditError] = useState<string | null>(null)

  async function handleEdit(p: PolicyListItem, key: string) {
    if (!onEditPolicy) return
    setEditingKey(key)
    setEditError(null)
    try {
      const model = await fetchPolicyForEdit(p.kind, p.namespace ?? '', p.name)
      onEditPolicy(model)
    } catch (err) {
      setEditError(err instanceof Error ? err.message : String(err))
    } finally {
      setEditingKey(null)
    }
  }

  async function runFetch() {
    setLoading(true)
    setError(null)
    const ns = allNamespaces ? '' : namespace

    try {
      const res = await fetchPolicies(ns)
      setPolicies(res.policies)
      setFetchedNamespace(ns)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    runFetch()
  }

  return (
    <div className="space-y-6">
      <form
        onSubmit={handleSubmit}
        className="rise-in flex flex-wrap items-end gap-5 border border-line bg-panel p-5"
      >
        <div className="w-64">
          <NamespaceScope
            namespace={namespace}
            onNamespaceChange={setNamespace}
            allNamespaces={allNamespaces}
            onAllNamespacesChange={setAllNamespaces}
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="bg-signal px-5 py-2 font-display text-xs font-bold tracking-[0.1em] text-void uppercase transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40 cursor-pointer"
        >
          {loading ? 'Loading…' : 'List policies'}
        </button>
      </form>

      {error && (
        <div className="rise-in flex flex-wrap items-center justify-between gap-3 border border-drop/40 bg-drop/10 px-4 py-3 text-sm text-drop">
          <p>{error}</p>
          <button
            type="button"
            onClick={() => runFetch()}
            disabled={loading}
            className="shrink-0 border border-drop/40 px-3 py-1 font-display text-[0.65rem] font-bold uppercase tracking-wider text-drop transition-colors hover:bg-drop/10 disabled:cursor-not-allowed disabled:opacity-40 cursor-pointer"
          >
            Retry
          </button>
        </div>
      )}

      {fetchedNamespace === null && !loading && (
        <div className="border border-line bg-panel p-8 text-center text-ink-dim space-y-3">
          <p className="font-mono text-2xl text-signal" aria-hidden="true">
            {'>_'}
          </p>
          <p className="font-display text-xs uppercase tracking-wider text-ink">Ready to list policies</p>
          <p className="text-xs max-w-md mx-auto leading-relaxed">
            Pick a namespace scope and click <strong className="text-signal">List policies</strong> to see what's
            actually enforced on the cluster right now.
          </p>
        </div>
      )}

      {editError && (
        <div className="rise-in flex items-center justify-between gap-3 border border-drop/40 bg-drop/10 px-4 py-3 text-sm text-drop">
          <p>{editError}</p>
          <button
            type="button"
            onClick={() => setEditError(null)}
            className="shrink-0 text-xs text-drop hover:underline cursor-pointer"
          >
            Dismiss
          </button>
        </div>
      )}

      {fetchedNamespace !== null && (
        <div className="border border-line bg-panel p-5 space-y-5 rise-in">
          <p className="text-xs text-ink-dim">
            <span className="font-semibold text-ink">{policies.length}</span> polic
            {policies.length === 1 ? 'y' : 'ies'} in{' '}
            <span className="text-ink">{fetchedNamespace || 'all namespaces'}</span>
          </p>

          {policies.length === 0 ? (
            <p className="text-sm text-ink-dim">
              No CiliumNetworkPolicy or CiliumClusterwideNetworkPolicy found for this scope — every workload here is
              fully default-allow.
            </p>
          ) : (
            <div className="overflow-x-auto border border-line">
              <table className="w-full min-w-[720px] text-left text-sm">
                <thead className="border-b border-line bg-panel-raised">
                  <tr>
                    {['Kind', 'Name', 'Namespace', 'Description', 'Ingress Rules', 'Egress Rules', ''].map((h) => (
                      <th
                        key={h}
                        className="px-3 py-2 text-[0.65rem] font-semibold tracking-[0.1em] text-ink-dim uppercase"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {policies.map((p, i) => {
                    const key = `${p.kind}/${p.namespace ?? ''}/${p.name}/${i}`
                    return (
                    <tr key={key} className="hover:bg-panel-raised/60">
                      <td className="px-3 py-2">
                        <span
                          className={`border px-2 py-0.5 text-[0.65rem] font-semibold ${
                            p.kind === 'CiliumClusterwideNetworkPolicy'
                              ? 'border-allow/40 bg-allow/10 text-allow'
                              : 'border-line-bright bg-panel-raised text-ink-dim'
                          }`}
                        >
                          {p.kind === 'CiliumClusterwideNetworkPolicy' ? 'CCNP' : 'CNP'}
                        </span>
                      </td>
                      <td className="px-3 py-2 font-mono text-xs text-ink">{p.name}</td>
                      <td className="px-3 py-2 font-mono text-xs text-ink-dim">{p.namespace || '—'}</td>
                      <td className="px-3 py-2 text-xs text-ink-dim">{p.description || '—'}</td>
                      <td className="px-3 py-2 font-mono text-xs text-ink">{p.ingressRuleCount}</td>
                      <td className="px-3 py-2 font-mono text-xs text-ink">{p.egressRuleCount}</td>
                      <td className="px-3 py-2">
                        {onEditPolicy && (
                          <button
                            type="button"
                            onClick={() => handleEdit(p, key)}
                            disabled={editingKey === key}
                            title="Load this policy into the Policy Editor for iteration"
                            className="whitespace-nowrap border border-signal/40 bg-signal/5 px-2 py-0.5 text-[0.65rem] font-bold uppercase tracking-wider text-signal hover:bg-signal/10 cursor-pointer disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            {editingKey === key ? 'Loading…' : '✎ Edit in Policy Editor'}
                          </button>
                        )}
                      </td>
                    </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
