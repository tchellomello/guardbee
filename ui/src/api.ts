// Typed client for the Go backend's JSON API (see ../../ui.go). Field names
// and shapes mirror ui.go's verdictRequest/verdictResponse/flowsResponse
// exactly — these two files are the one contract, kept in sync by hand since
// there's no shared schema generation for a project this size yet.

import type { EgressRule, IngressRule, PolicyModel } from './policy'

export interface VerdictRequest {
  namespace: string // "" = all namespaces
  candidateYAML: string
  last: number
  showUnchanged: boolean
}

export type VerdictChange = 'NEWLY_DROPPED' | 'NEWLY_ALLOWED' | 'UNCHANGED'

export interface VerdictRow {
  change: VerdictChange
  source: string
  destination: string
  protocol: string
  port: number
  count: number
  explanation: string
}

export interface VerdictCounts {
  unchanged: number
  newlyDropped: number
  newlyAllowed: number
  notSimulated: number
  replySkipped: number
  total: number
}

export interface VerdictResponse {
  namespace: string
  candidateRuleCount: number
  baselineRuleCount: number
  flowsRequested: number
  flowsSampled: number
  counts: VerdictCounts
  rows: VerdictRow[]
}

export interface Flow {
  time: string
  verdict: string
  dropReason?: string
  source: string
  destination: string
  l4: string
}

export interface FlowsResponse {
  namespace: string
  flows: Flow[]
}

export interface NamespacesResponse {
  namespaces: string[]
}

async function parseErrorOrJSON<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const text = await res.text()
    throw new Error(text || `request failed: ${res.status}`)
  }
  return res.json() as Promise<T>
}

export function runVerdict(req: VerdictRequest): Promise<VerdictResponse> {
  return fetch('/api/verdict', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  }).then((res) => parseErrorOrJSON<VerdictResponse>(res))
}

export function fetchFlows(namespace: string, last: number): Promise<FlowsResponse> {
  const params = new URLSearchParams({ last: String(last) })
  if (namespace) params.set('namespace', namespace)
  return fetch(`/api/flows?${params}`).then((res) => parseErrorOrJSON<FlowsResponse>(res))
}

export function fetchNamespaces(): Promise<NamespacesResponse> {
  return fetch('/api/namespaces').then((res) => parseErrorOrJSON<NamespacesResponse>(res))
}

export interface Pod {
  name: string
  labels: Record<string, string>
}

export interface PodsResponse {
  namespace: string
  pods: Pod[]
}

export function fetchPods(namespace: string): Promise<PodsResponse> {
  return fetch(`/api/pods?namespace=${encodeURIComponent(namespace)}`).then((res) =>
    parseErrorOrJSON<PodsResponse>(res)
  )
}

export interface PolicyValidationResult {
  valid: boolean
  ruleCount?: number
  error?: string
}

export function validatePolicy(namespace: string, candidateYAML: string): Promise<PolicyValidationResult> {
  return fetch('/api/policy/validate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ namespace, candidateYAML }),
  }).then((res) => parseErrorOrJSON<PolicyValidationResult>(res))
}

// Policy Editor preset templates — read server-side from a directory of real
// CiliumNetworkPolicy YAML (see ../../templates.go) rather than hardcoded
// here. Rule shapes omit "id": the frontend assigns a fresh one wherever a
// template is actually loaded or a rule preset added to the canvas.
export interface GenericPolicyTemplate {
  id: string
  name: string
  description: string
  // Free-text grouping for the Policy Editor's "Presets & Starters" menu
  // (see templates.go's guardbeeCategoryAnnotation) — "" for a template
  // that hasn't been categorized, grouped under PresetMenu's fallback.
  category: string
  policy: Omit<PolicyModel, 'ingressRules' | 'egressRules'> & {
    ingressRules: Omit<IngressRule, 'id'>[]
    egressRules: Omit<EgressRule, 'id'>[]
  }
}

export interface IngressRuleTemplate {
  id: string
  name: string
  description: string
  rule: Omit<IngressRule, 'id'>
}

export interface EgressRuleTemplate {
  id: string
  name: string
  description: string
  rule: Omit<EgressRule, 'id'>
}

export interface TemplatesResponse {
  generic: GenericPolicyTemplate[]
  ingress: IngressRuleTemplate[]
  egress: EgressRuleTemplate[]
}

export function fetchTemplates(): Promise<TemplatesResponse> {
  return fetch('/api/templates').then((res) => parseErrorOrJSON<TemplatesResponse>(res))
}

// Live CiliumNetworkPolicy/CiliumClusterwideNetworkPolicy state (Policies
// tab) — what's actually enforced on the cluster right now, as opposed to
// the Policy Editor's in-progress candidate or a Verdict run's opaque
// baselineRuleCount.
export interface PolicyListItem {
  kind: 'CiliumNetworkPolicy' | 'CiliumClusterwideNetworkPolicy'
  name: string
  namespace?: string
  description?: string
  ingressRuleCount: number
  egressRuleCount: number
}

export interface PoliciesResponse {
  namespace: string
  policies: PolicyListItem[]
}

export function fetchPolicies(namespace: string): Promise<PoliciesResponse> {
  const params = new URLSearchParams()
  if (namespace) params.set('namespace', namespace)
  return fetch(`/api/policies?${params}`).then((res) => parseErrorOrJSON<PoliciesResponse>(res))
}

// EditablePolicyModel is the same shape GenericPolicyTemplate.policy already
// uses — "Edit in Policy Editor" (GET /api/policies/edit) reuses that one
// JSON shape rather than inventing a second one, so the frontend's existing
// "load a preset" code path handles a live policy with no new parsing logic.
export type EditablePolicyModel = GenericPolicyTemplate['policy']

export function fetchPolicyForEdit(kind: string, namespace: string, name: string): Promise<EditablePolicyModel> {
  const params = new URLSearchParams({ kind, name })
  if (namespace) params.set('namespace', namespace)
  return fetch(`/api/policies/edit?${params}`).then((res) => parseErrorOrJSON<EditablePolicyModel>(res))
}

