// Typed client for the Go backend's JSON API (see ../../ui.go). Field names
// and shapes mirror ui.go's verdictRequest/verdictResponse/flowsResponse
// exactly — these two files are the one contract, kept in sync by hand since
// there's no shared schema generation for a project this size yet.

import type { EgressRule, IngressRule, PolicyModel } from './policy'
import type { FlowFilterParams } from './shared/flowFilter'

// The flow filter (shared/flowFilter.ts, ui.go's flowFilterParams) rides
// along as the same top-level keys the CLI flags use: toPod, fromIp, verdict…
export interface VerdictRequest extends FlowFilterParams {
  replaceExisting?: boolean
  namespace: string // "" = all namespaces
  candidateYAML: string
  last: number
  showUnchanged: boolean
}

export type VerdictChange = 'NEWLY_DROPPED' | 'NEWLY_ALLOWED' | 'UNCHANGED'

export interface VerdictRow {
  baselineAllowed?: boolean
  candidateAllowed?: boolean
  change: VerdictChange
  source: string
  destination: string
  protocol: string
  port: number
  count: number
  explanation: string
  // Which half of the verdict flipped (verdictRow.side in verdict.go):
  // the destination's ingress policy, the source's egress policy, or both.
  side?: 'ingress' | 'egress' | 'both'
  // The endpoints' security-identity labels as Hubble reports them
  // ("k8s:app=foo", "reserved:kube-apiserver", …).
  sourceLabels?: string[]
  destinationLabels?: string[]
  // The Kubernetes Service the flow was addressed to ("ns/name"), if any.
  destinationService?: string
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
  // Live baseline policies the engine couldn't load (fromNodes/toNodes), see fetchBaselineRules in policies.go.
  skippedPolicies?: string[]
  // The kubeconfig context and API server this verdict judged (see kubeTarget in kube.go).
  context?: string
  apiServer?: string
}

// A policy Cilium attributed a flow's verdict to (blame.go's policyRef).
// kind is Cilium's derived-from label as-is: CiliumNetworkPolicy,
// CiliumClusterwideNetworkPolicy, NetworkPolicy or ClusterNetworkPolicy.
export interface PolicyRef {
  kind?: string
  namespace?: string
  name?: string
  labels?: string[]
  revision?: number
  // How the CLI renders it ("CNP:ns/name", "CCNP:name", …).
  display: string
}

// blame.go's decisions; absent when the flow isn't a policy decision.
export type PolicyDecision = 'allowed' | 'denied' | 'default-deny' | 'audit'

export interface Flow {
  time: string
  verdict: string
  dropReason?: string
  // The side the verdict was taken on: INGRESS or EGRESS.
  direction?: string
  source: string
  destination: string
  l4: string
  // Security-identity labels Hubble reports for each endpoint.
  sourceLabels?: string[]
  destinationLabels?: string[]
  // Policy attribution (blame.go's flowAttribution), on policy-verdict events.
  decision?: PolicyDecision
  allowedBy?: PolicyRef[]
  deniedBy?: PolicyRef[]
  decidedBy?: string
}

export interface FlowsResponse {
  namespace: string
  flows: Flow[]
}

export interface NamespacesResponse {
  namespaces: string[]
}

export interface ProbePod {
  name: string
  uid: string
}

export type ProbeProtocol = 'TCP' | 'UDP'

export interface ConnectionProbeRequest {
  replaceExisting: boolean
  candidateNamespace: string
  namespace: string
  pod: string
  uid: string
  host: string
  port: number
  protocol: ProbeProtocol
  candidateYAML: string
}

export interface ConnectionProbeResponse {
  uid?: string
  context?: string
  apiServer?: string
  image?: string
  startedAt?: string
  durationMs?: number
  namespace: string
  pod: string
  host: string
  port: number
  protocol?: ProbeProtocol
  outcome?: 'connected' | 'generated' | 'failed' | 'inconclusive'
  message: string
  containerName?: string
  flows?: Flow[]
  simulation?: VerdictResponse
  warnings?: string[]
}

export interface ProbeCapabilities {
  enabled: boolean
  protocols?: ProbeProtocol[]
  context?: string
  apiServer?: string
  image?: string
}

export function fetchProbeCapabilities(): Promise<ProbeCapabilities> {
  return fetch('/api/probes/capabilities').then((res) => parseErrorOrJSON<ProbeCapabilities>(res))
}

// Unlike /api/pods (label suggestions), this inventory contains only running
// probe-eligible Pods and their UID, so replacement cannot target a namesake.
export function fetchProbePods(namespace: string): Promise<{ pods: ProbePod[]; excluded?: Record<string, number> }> {
  return fetch(`/api/probes/pods?${new URLSearchParams({ namespace })}`).then((res) =>
    parseErrorOrJSON<{ pods: ProbePod[]; excluded?: Record<string, number> }>(res)
  )
}

export function runConnectionProbe(req: ConnectionProbeRequest): Promise<ConnectionProbeResponse> {
  return fetch('/api/probes/connection', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  }).then(async (res) => {
    if (!res.ok) throw new ConnectionProbeError(await res.text() || `request failed: ${res.status}`, res.status)
    return res.json() as Promise<ConnectionProbeResponse>
  })
}

export class ConnectionProbeError extends Error {
  readonly definiteRejection: boolean
  readonly status: number
  constructor(message: string, status: number) {
    super(message)
    this.status = status
    this.name = 'ConnectionProbeError'
    this.definiteRejection = [400, 403, 405, 409, 413, 415, 429].includes(status)
  }
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

// Query string shared by the one-shot and streaming flows endpoints.
export function flowsQuery(namespace: string, last: number, filter?: FlowFilterParams): URLSearchParams {
  const params = new URLSearchParams({ last: String(last) })
  if (namespace) params.set('namespace', namespace)
  for (const [key, vals] of Object.entries(filter ?? {})) {
    for (const v of vals ?? []) params.append(key, v)
  }
  return params
}

export function fetchFlows(namespace: string, last: number, filter?: FlowFilterParams): Promise<FlowsResponse> {
  return fetch(`/api/flows?${flowsQuery(namespace, last, filter)}`).then((res) => parseErrorOrJSON<FlowsResponse>(res))
}

// GET /api/flow-filter-options: every value --verdict/--drop-reason-desc
// accept, from the pinned Cilium's own enums.
export interface FlowFilterOptions {
  verdicts: string[]
  dropReasons: string[]
  eventTypes: string[]
}

export function fetchFlowFilterOptions(): Promise<FlowFilterOptions> {
  return fetch('/api/flow-filter-options').then((res) => parseErrorOrJSON<FlowFilterOptions>(res))
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

export interface WorkloadMatch {
  namespace: string
  name: string
  serviceAccount: string
  selected: boolean
  ingress: boolean
  egress: boolean
}

export interface WorkloadsResult {
  valid: boolean
  error?: string
  workloads: WorkloadMatch[]
}

export function fetchPolicyWorkloads(namespace: string, candidateYAML: string): Promise<WorkloadsResult> {
  return fetch('/api/policy/workloads', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ namespace, candidateYAML }),
  }).then((res) => parseErrorOrJSON<WorkloadsResult>(res))
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

// PolicyParseResult backs POST /api/policy/parse — the Policy Editor's
// YAML import/hand-edit path (PolicyEditorPanel.tsx): same {valid, error}
// shape PolicyValidationResult already uses on failure, so the frontend
// has one consistent error shape regardless of which endpoint reported it,
// but carries the structured EditablePolicyModel back on success so the
// edited/imported YAML can replace the draft's model, not just report
// pass/fail like validatePolicy does.
export interface PolicyParseResult {
  valid: boolean
  policy?: EditablePolicyModel
  // True when `policy` is NOT a faithful rendering of the YAML (a scoped
  // ingressDeny/egressDeny the editor model can't express) — callers must
  // keep the user's text rather than regenerate it from `policy`.
  lossy?: boolean
  // Set (> 1) for a "---"-separated paste: `policy` is only the first one,
  // and the paste is always lossy for the single-policy editor.
  documents?: number
  error?: string
}

export function parsePolicy(namespace: string, candidateYAML: string): Promise<PolicyParseResult> {
  return fetch('/api/policy/parse', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ namespace, candidateYAML }),
  }).then((res) => parseErrorOrJSON<PolicyParseResult>(res))
}

// VersionInfo backs GET /api/version — the UI's counterpart to the CLI's
// stderr version-skew warning (see ../../clusterversion.go's
// warnOnVersionSkew). Unknown means detection couldn't reach hubble-relay
// or get a real version out of it; Skewed/NodeSkew are mutually exclusive
// with Unknown and with each other (see clusterversion.go's
// clusterVersionState).
export interface VersionInfo {
  binary: string
  pinned: string
  detected?: string
  skewed: boolean
  nodeSkew: boolean
  nodeVersions?: string[]
  unknown: boolean
}

export function fetchVersion(): Promise<VersionInfo> {
  return fetch('/api/version').then((res) => parseErrorOrJSON<VersionInfo>(res))
}

// Binary + pinned engine only, no cluster round trip (?client=1) — fast
// enough for the header on page load.
export function fetchClientVersion(): Promise<VersionInfo> {
  return fetch('/api/version?client=1').then((res) => parseErrorOrJSON<VersionInfo>(res))
}

// CompatGate/CompatResponse back GET /api/compat — compat.go's featureGates
// table, read-only, surfaced verbatim so "why was my candidate rejected"
// has a page to check (CompatModal.tsx) instead of only the rejection
// error text from a validate/parse call.
export interface CompatGate {
  name: string
  minVersion?: string
  maxVersion?: string
  reason: string
}

export interface CompatResponse {
  pinned: string
  gates: CompatGate[]
}

export function fetchCompat(): Promise<CompatResponse> {
  return fetch('/api/compat').then((res) => parseErrorOrJSON<CompatResponse>(res))
}
