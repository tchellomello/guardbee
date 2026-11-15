import type { Flow, PolicyRef } from '../api'

// Presentation of a flow's policy attribution (blame.go's flowAttribution).
// The decision and the text come from the backend; this only decides how a
// row shows them, so the Flows tab can't disagree with `guardbee blame`.

// Only these kinds can be opened by GET /api/policies/edit (ui.go's
// handlePolicyForEdit); a Kubernetes NetworkPolicy, or a rule without a name,
// stays a plain label.
export function isEditablePolicyRef(ref: PolicyRef): boolean {
  return !!ref.name && (ref.kind === 'CiliumNetworkPolicy' || ref.kind === 'CiliumClusterwideNetworkPolicy')
}

// The policies a row's badges show, and the words before them — the same
// lead-in blame.go puts in decidedBy. Without attributed policies there are
// no badges and the row shows decidedBy as-is.
export function attributionBadges(flow: Flow): { lead: string; refs: PolicyRef[] } | null {
  if (!flow.decision) return null
  const refs = (flow.decision === 'allowed' ? flow.allowedBy : flow.deniedBy) ?? []
  if (refs.length === 0) return null
  const lead = flow.decision === 'allowed' ? 'allowed by' : flow.decision === 'audit' ? 'audit: would be denied by' : 'denied by'
  return { lead, refs }
}
