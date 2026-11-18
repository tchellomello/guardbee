import { useEffect, useRef, useState } from 'react'
import {
  fetchNamespaces, fetchProbeCapabilities, fetchProbePods, runConnectionProbe,
  ConnectionProbeError,
  type ProbePod, type ProbeProtocol, type ConnectionProbeRequest, type ConnectionProbeResponse,
  type ProbeCapabilities,
} from '../api'
import { validProbeHost, validProbeNamespace, validProbePort } from '../shared/tcpProbe'
import { candidateFingerprint, connectivityDecision, type ConnectivityDecision } from '../shared/connectivity'
import { Field } from './NamespaceScope'
import { downloadTextFile } from '../shared/tableExport'

const inputClass = 'w-full min-w-0 rounded-sm border border-line bg-void px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-signal focus:outline-none disabled:cursor-not-allowed disabled:opacity-50'
const buttonClass = 'rounded-sm bg-signal px-5 py-2.5 font-display text-xs font-bold tracking-wide text-void uppercase transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40 cursor-pointer'
const errorText = (err: unknown) => err instanceof Error ? err.message : String(err)
type RequestSnapshot = Readonly<ConnectionProbeRequest>
type Attempt = { request: RequestSnapshot; allNamespaces: boolean; submittedAt: string; capabilities: ProbeCapabilities; response?: ConnectionProbeResponse; error?: string; definiteRejection?: boolean; errorStatus?: number }

export function ConnectivityTestsPanel({ active, candidateYAML, namespace: verdictNamespace, allNamespaces, replaceExisting, resetGeneration, onRunningChange }: {
  active: boolean; candidateYAML: string; namespace: string; allNamespaces: boolean; replaceExisting: boolean; resetGeneration: number; onRunningChange: (running: boolean) => void
}) {
  const [expanded, setExpanded] = useState(false)
  const [capability, setCapability] = useState({ enabled: false, message: 'Checking test availability…' })
  const [server, setServer] = useState<ProbeCapabilities>({ enabled: false })
  const [namespaces, setNamespaces] = useState<string[]>([])
  const [sourceNamespace, setSourceNamespace] = useState('')
  const namespace = allNamespaces ? sourceNamespace : verdictNamespace
  const [inventory, setInventory] = useState<{ namespace: string; pods: ProbePod[]; loading: boolean; error: string; excluded?: Record<string, number> }>({ namespace: '', pods: [], loading: false, error: '' })
  const [selection, setSelection] = useState({ namespace: '', uid: '' })
  const [host, setHost] = useState('')
  const [port, setPort] = useState('5432')
  const [protocol, setProtocol] = useState<ProbeProtocol>('TCP')
  const [running, setRunning] = useState(false)
  const [attempt, setAttempt] = useState<Attempt | null>(null)
  const [podRefresh, setPodRefresh] = useState(0)
  // State is not a synchronous lock. The panel stays mounted across app tabs;
  // never abort or repeat this mutating request just because the view changes.
  const runningRef = useRef(false)
  const mounted = useRef(false)
  useEffect(() => {
    if (runningRef.current) return
    setAttempt(null)
    setSourceNamespace('')
    setSelection({ namespace: '', uid: '' })
    setHost('')
    setPort('5432')
    setProtocol('TCP')
  }, [resetGeneration])

  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false }
  }, [])

  useEffect(() => {
    if (!active || !expanded) return
    let ignore = false
    setCapability({ enabled: false, message: 'Checking test availability…' })
    fetchProbeCapabilities().then((res) => {
      if (!ignore) setServer(res)
      if (!ignore) setCapability(res.enabled === true
        ? { enabled: true, message: 'Connection tests enabled on this server.' }
        : { enabled: false, message: 'Connection tests are disabled. Start the server with --enable-probes and --probe-image (tag or digest).' })
    }).catch((err) => {
      if (!ignore) setCapability({ enabled: false, message: `Test availability could not be verified: ${errorText(err)}. No test can be started.` })
    })
    return () => { ignore = true }
  }, [active, expanded])

  useEffect(() => {
    if (!active || !expanded || !allNamespaces) return
    let ignore = false
    fetchNamespaces().then((res) => { if (!ignore) setNamespaces(res.namespaces) }).catch(() => {})
    return () => { ignore = true }
  }, [active, expanded, allNamespaces])

  useEffect(() => {
    // A scope change requires a fresh Pod selection, even if the old UID is
    // later seen again. Old async inventories cannot populate the new scope.
    setSelection({ namespace, uid: '' })
  }, [namespace, allNamespaces])

  useEffect(() => {
    if (!active || !expanded || !capability.enabled || !validProbeNamespace(namespace)) return
    let ignore = false
    setInventory((previous) => ({ namespace, pods: previous.namespace === namespace ? previous.pods : [], loading: true, error: '' }))
    fetchProbePods(namespace).then((res) => {
      if (!ignore) setInventory({ namespace, pods: res.pods ?? [], loading: false, error: '', excluded: res.excluded })
    }).catch((err) => {
      if (!ignore) setInventory({ namespace, pods: [], loading: false, error: errorText(err) })
    })
    return () => { ignore = true }
  }, [namespace, allNamespaces, capability.enabled, podRefresh, active, expanded])

  const currentInventory = inventory.namespace === namespace && validProbeNamespace(namespace)
  const pods = currentInventory ? inventory.pods : []
  const selectedPod = selection.namespace === namespace ? pods.find((pod) => pod.uid === selection.uid) : undefined
  const protocolSupported = !server.protocols || server.protocols.includes(protocol)
  const podPlaceholder = !capability.enabled ? 'Enable connectivity tests first' : !validProbeNamespace(namespace) ? 'Select a source namespace' : inventory.loading ? 'Loading eligible Pods…' : inventory.error ? 'Could not load Pods' : !pods.length ? 'No eligible Pods found' : 'Select an existing Pod'
  const excluded = currentInventory ? Object.entries(inventory.excluded ?? {}) : []
  const ready = active && expanded && capability.enabled && protocolSupported && candidateYAML.trim() && selectedPod && validProbeHost(host) && validProbePort(port) && !inventory.loading
  const stale = !!attempt && (attempt.request.namespace !== namespace || attempt.allNamespaces !== allNamespaces ||
    (!inventory.loading && attempt.request.uid !== selectedPod?.uid) || attempt.request.host !== host || attempt.request.port !== Number(port) ||
    attempt.request.protocol !== protocol || attempt.request.candidateYAML !== candidateYAML || attempt.request.replaceExisting !== replaceExisting || attempt.request.candidateNamespace !== (allNamespaces ? '' : verdictNamespace))

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!ready || runningRef.current || !selectedPod) return
    runningRef.current = true
    const request: RequestSnapshot = Object.freeze({ namespace, pod: selectedPod.name, uid: selectedPod.uid, host, port: Number(port), protocol, candidateYAML, replaceExisting, candidateNamespace: allNamespaces ? '' : verdictNamespace })
    const snapshot = { request, allNamespaces, submittedAt: new Date().toISOString(), capabilities: { ...server } }
    const confirmed = window.confirm(
      `Run one bounded ${protocol === 'UDP' ? 'UDP datagram with a fixed payload (27 bytes: guardbee-connectivity-probe)' : 'TCP connection'} from existing Pod ${namespace}/${selectedPod.name} (UID ${selectedPod.uid}) to ${host}:${port}?\n\n` +
      (server.context || server.apiServer ? `Cluster: ${server.context ?? 'unknown context'}${server.apiServer ? ` · ${server.apiServer}` : ''}\n\n` : '') +
      'This adds an ephemeral container, changing the Pod spec but not its labels. The process exits, but its spec entry remains until normal Pod replacement. GuardBee does NOT automatically restart or delete the Pod.\n\n' +
      'Traffic runs against current policy. The loaded candidate is simulated separately, never applied. No shell, editable payload, or arbitrary commands. ' +
      (protocol === 'UDP' ? 'Generating a UDP datagram does not prove reachability or delivery.' : 'A TCP connection is not database authentication.')
    )
    if (!confirmed) { runningRef.current = false; return }
    setRunning(true)
    onRunningChange(true)
    setAttempt(snapshot)
    try {
      const response = await runConnectionProbe(request)
      if (mounted.current) setAttempt({ ...snapshot, response })
    } catch (err) {
      if (mounted.current) setAttempt({ ...snapshot, error: errorText(err), definiteRejection: err instanceof ConnectionProbeError && err.definiteRejection, errorStatus: err instanceof ConnectionProbeError ? err.status : undefined })
    } finally {
      runningRef.current = false
      onRunningChange(false)
      if (mounted.current) setRunning(false)
    }
  }

  return (
    <section aria-label="Connectivity tests" className="mt-6 min-w-0 rounded-sm border border-line bg-panel">
      <button type="button" aria-expanded={expanded} aria-controls="connectivity-tests-content" onClick={() => setExpanded(!expanded)} className="flex w-full cursor-pointer flex-wrap items-center justify-between gap-3 p-5 text-left hover:bg-void/30">
        <span><span className="block font-display text-sm font-bold tracking-wide text-ink">Connectivity tests</span><span className="mt-1 block text-xs text-ink-dim">Test a specific connection against your loaded candidate.</span></span>
        <span className="flex items-center gap-3"><Badge>Bounded · opt-in</Badge><span aria-hidden="true" className="text-ink-dim">{expanded ? '−' : '+'}</span></span>
      </button>
      <div id="connectivity-tests-content" hidden={!expanded} className="min-w-0 space-y-5 border-t border-line p-5">
        <div className="flex flex-wrap items-center gap-2 text-xs text-ink-dim" aria-label="Current candidate context">
          <Badge>{candidateYAML.trim() ? `Candidate snapshot ${candidateFingerprint(candidateYAML)}` : 'No candidate loaded'}</Badge>
          <span>{allNamespaces ? 'All namespaces · choose a source below' : `Source namespace: ${namespace || 'not selected'}`}</span>
          <span>Simulation only · never applied</span>
          <span>{replaceExisting ? 'Replace matching live policies' : 'Additive · keep live policies'}</span>
          {(server.context || server.apiServer) && <span className="break-all">Cluster: {server.context ?? 'unknown context'}{server.apiServer && ` · ${server.apiServer}`}</span>}
        </div>
        {!candidateYAML.trim() && <p role="status" className="text-sm text-ink-dim">Load a nonempty candidate in the Verdict form above before running a connectivity test.</p>}
        <p id="connection-capability" role="status" className="break-words text-xs text-ink-dim">{capability.message}</p>
        {!capability.enabled && <div className="space-y-2 border border-line bg-void/40 p-4 text-sm text-ink-dim" aria-label="Connectivity enablement">
          <h3 className="font-display font-bold text-ink">Connectivity tests require explicit server opt-in</h3>
          <p>Read-only launch cannot select a source Pod or start a test. No Pod lookup is made until connectivity tests are explicitly enabled.</p>
          <p>Restart your local server with your probe image (tag or digest) and the separate probes RBAC:</p>
          <code className="block whitespace-pre-wrap break-all text-xs text-ink">./guardbee ui --enable-probes --probe-image &lt;your-image:tag&gt;</code>
          <details className="text-xs"><summary className="cursor-pointer">Runtime requirements & permissions</summary><p className="mt-2">The image must provide timeout and nc for TCP; UDP requires timeout and Python 3. Enabling tests permits bounded ephemeral-container mutations; candidates are never applied. Use the separate probes RBAC.</p></details>
        </div>}
        <form aria-label="Connection test configuration" onSubmit={handleSubmit} className="min-w-0 space-y-4">
          <fieldset disabled={running || !capability.enabled} className="min-w-0 space-y-4">
            <div className="grid min-w-0 gap-4 sm:grid-cols-2 lg:grid-cols-4">
              {allNamespaces && <Field label="Source namespace">
                <input value={sourceNamespace} list="connection-namespaces" required maxLength={63} pattern="[a-z0-9]([a-z0-9-]*[a-z0-9])?" className={inputClass} placeholder="Choose a namespace" onChange={(e) => setSourceNamespace(e.target.value)} />
                <datalist id="connection-namespaces">{namespaces.map((ns) => <option key={ns} value={ns} />)}</datalist>
              </Field>}
              <Field label="Source Pod"><select aria-label="Source Pod" value={selectedPod?.uid ?? ''} required className={inputClass} onChange={(e) => setSelection({ namespace, uid: e.target.value })}>
                <option value="">{podPlaceholder}</option>
                {pods.map((pod) => <option key={pod.uid} value={pod.uid}>{pod.name}</option>)}
              </select></Field>
              <Field label="Host or IP"><input value={host} required maxLength={253} aria-describedby="connection-host-help" aria-invalid={!!host && !validProbeHost(host)} className={inputClass} placeholder="db.myapp.svc.cluster.local" onChange={(e) => setHost(e.target.value)} /></Field>
              <Field label="Port"><input value={port} required inputMode="numeric" maxLength={5} pattern="[0-9]{1,5}" aria-invalid={!validProbePort(port)} className={inputClass} onChange={(e) => setPort(e.target.value)} /></Field>
              <Field label="Protocol"><select value={protocol} className={inputClass} onChange={(e) => setProtocol(e.target.value as ProbeProtocol)}><option value="TCP" disabled={!!server.protocols && !server.protocols.includes('TCP')}>TCP</option><option value="UDP" disabled={!!server.protocols && !server.protocols.includes('UDP')}>UDP</option></select></Field>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p id="connection-host-help" className="text-xs text-ink-dim">One DNS name or IPv4/IPv6 address; no URL or embedded port. Port: 1–65535.</p>
              <button type="button" className="cursor-pointer text-xs text-signal disabled:opacity-40" disabled={!validProbeNamespace(namespace) || inventory.loading} onClick={() => setPodRefresh((value) => value + 1)}>Refresh running Pods</button>
            </div>
            {currentInventory && inventory.error && <p role="alert" className="break-words text-sm text-drop">Could not list running Pods: {inventory.error}</p>}
            {capability.enabled && currentInventory && !inventory.loading && !inventory.error && !pods.length && <p role="status" className="text-xs text-ink-dim">No eligible Pods found in this namespace. Choose a ready, normal Linux workload; system, host-network, process-sharing, and Pods with pending GuardBee containers are excluded.</p>}
            {excluded.length > 0 && <details open={!pods.length} className="text-xs text-ink-dim"><summary className="cursor-pointer">{excluded.reduce((total, [, count]) => total + count, 0)} Pods excluded</summary><ul className="mt-2 space-y-1">{excluded.map(([reason, count]) => <li key={reason}>{reason} ({count})</li>)}</ul></details>}
            <p className="text-xs text-ink-dim">{protocol === 'UDP' ? 'UDP sends one bounded datagram with a fixed payload: guardbee-connectivity-probe (27 bytes). Payload and commands are not editable. Requires Python 3 in the probe image; missing runtime is inconclusive. Policy prediction, not proof of reachability or delivery.' : 'TCP opens one bounded connection. It does not authenticate to the application.'}</p>
          </fieldset>
          <div className="flex flex-wrap items-center justify-between gap-4 border-t border-line pt-4">
            <details className="max-w-2xl text-xs leading-relaxed text-ink-dim"><summary className="cursor-pointer">Active cluster change · adds an ephemeral container · confirmation required</summary><p className="mt-2">Its spec entry remains after exit until normal Pod replacement. No label changes, candidate apply, automatic restart, or deletion.</p></details>
            <button type="submit" disabled={!ready || running} aria-describedby="connection-capability" className={buttonClass}>{running ? 'Running connection test…' : 'Review & run connection test'}</button>
          </div>
        </form>
        {attempt && <section aria-label="Submitted connection test" className="min-w-0 space-y-4 border-t border-line pt-5 break-words">
          <div className="flex flex-wrap items-center gap-2"><Badge>{attempt.request.protocol}</Badge><Badge>{attempt.request.namespace}/{attempt.request.pod}</Badge><span aria-hidden="true" className="text-ink-faint">→</span><Badge>{attempt.request.host} · port {attempt.request.port}</Badge></div>
          {stale && <p role="status" className="text-xs text-allow">Inputs changed since this test. Results are stale and refer only to the submitted Pod, target, scope, and candidate snapshot, not the current Verdict form.</p>}
          {attempt.response && <ConnectionResult response={attempt.response} request={attempt.request} />}
          {attempt.error !== undefined && <div role="alert" className="space-y-2 rounded-sm border border-drop/40 bg-drop/10 p-4 text-sm text-drop">
            <p>{attempt.definiteRejection ? 'Test not started' : 'Predicted candidate: INCONCLUSIVE'}</p><p>{attempt.error}</p>
            {attempt.definiteRejection ? <p>The server rejected this request before adding an ephemeral container. Fix the error before running a new confirmed test.</p> : <p>An ephemeral container may already have been added to the original Pod {attempt.request.namespace}/{attempt.request.pod} (UID {attempt.request.uid}). Inspect that Pod before deciding to run again. GuardBee does not automatically retry, restart, or delete it.</p>}
          </div>}
          {running && <p role="status" className="text-xs text-ink-dim">Preparing the workload test, collecting traffic, and evaluating the candidate. This can take up to 30 seconds. Switching tabs does not cancel or repeat it.</p>}
          {!running && <button type="button" className="cursor-pointer text-xs text-signal" onClick={() => downloadTextFile(`guardbee-connectivity-${candidateFingerprint(attempt.request.candidateYAML)}.json`, JSON.stringify({ schemaVersion: 1, ...attempt }, null, 2), 'application/json')}>Download test report (JSON)</button>}
          {!running && <button type="button" className="ml-4 cursor-pointer text-xs text-ink-dim" onClick={() => setAttempt(null)}>Clear completed test</button>}
          <details><summary className="cursor-pointer text-xs text-ink-dim">Submitted candidate snapshot {candidateFingerprint(attempt.request.candidateYAML)}</summary>
            <p className="mt-3 text-xs text-ink-dim">Original Pod UID: {attempt.request.uid} · {attempt.allNamespaces ? 'All namespaces' : 'Single namespace'}</p>
            <pre className="mt-3 whitespace-pre-wrap break-words text-xs text-ink-dim">{attempt.request.candidateYAML}</pre>
          </details>
        </section>}
      </div>
    </section>
  )
}

function Badge({ children }: { children: React.ReactNode }) {
  return <span className="max-w-full break-words rounded-sm border border-line bg-void/50 px-2 py-1 font-mono text-[0.65rem] text-ink-dim">{children}</span>
}

function Decision({ label, decision }: { label: string; decision: ConnectivityDecision }) {
  return <div className="space-y-1"><p className="text-xs text-ink-dim">{label}</p><p className={`font-display text-sm font-bold ${decision === 'ALLOWED' ? 'text-allow' : decision === 'BLOCKED' ? 'text-drop' : 'text-ink-dim'}`}>{decision}</p></div>
}

function ConnectionResult({ response, request }: { response: ConnectionProbeResponse; request: RequestSnapshot }) {
  const simulation = response.simulation
  const protocolMatches = !response.protocol || response.protocol === request.protocol
  const baseline = protocolMatches ? connectivityDecision(response, 'baselineAllowed') : 'INCONCLUSIVE'
  const candidate = protocolMatches ? connectivityDecision(response, 'candidateAllowed') : 'INCONCLUSIVE'
  const warnings = [...new Set([...(response.warnings ?? []), ...(simulation?.skippedPolicies ?? []).map((policy) => `Baseline policy skipped: ${policy}. Simulation does not account for it.`)])]
  return <div className="min-w-0 space-y-4" aria-live="polite">
    <section aria-label="Candidate prediction" className="space-y-4 rounded-sm border border-line bg-void/40 p-4">
      <div><p className="text-xs text-ink-dim">Predicted candidate policy</p><h3 className={`mt-1 font-display text-xl font-bold ${candidate === 'ALLOWED' ? 'text-allow' : candidate === 'BLOCKED' ? 'text-drop' : 'text-ink'}`}>{candidate}</h3></div>
      <div className="flex flex-wrap items-center gap-4 border-t border-line pt-3"><Decision label="Baseline model" decision={baseline} /><span aria-hidden="true" className="text-ink-faint">→</span><Decision label="With candidate" decision={candidate} /></div>
      {candidate === 'INCONCLUSIVE' && <p className="text-sm text-ink-dim">{warnings.find((warning) => warning.startsWith('Simulation inconclusive:')) ?? (!response.flows?.length ? 'No matching Hubble evidence was captured for this attempt.' : 'The sample does not provide one complete, consistent candidate decision. Expand the evidence below for details.')}</p>}
      <p className="text-xs leading-relaxed text-ink-dim">Hypothetical engine comparison; the candidate was never applied. UNCHANGED is not an allow decision. Missing, partial, or conflicting evidence is inconclusive.</p>
    </section>
    <p className="text-xs text-ink-dim">{request.protocol === 'UDP' ? 'Traffic generation' : 'Observed TCP transport'}: {response.outcome ?? 'inconclusive'} · {response.message}<br />{request.protocol === 'UDP' ? 'A generated datagram does not prove reachability or delivery.' : 'Connected proves TCP transport only, not application authentication. Failure does not by itself prove policy denial.'}</p>
    <details><summary className="cursor-pointer text-xs text-ink-dim">Evidence & limitations · {response.flows?.length ?? 0} observed flows{warnings.length > 0 && ` · ${warnings.length} warnings`}</summary>
      <div className="mt-3 min-w-0 space-y-4 text-xs text-ink-dim">
        {response.containerName && <p>Ephemeral container: {response.containerName}. Its entry remains until normal Pod replacement.</p>}
        {(response.context || response.apiServer) && <p className="break-all">Cluster: {response.context ?? 'unknown context'}{response.apiServer && ` · ${response.apiServer}`}</p>}
        {response.startedAt && <p>Started: {response.startedAt}{response.durationMs !== undefined && ` · ${response.durationMs} ms`}</p>}
        {response.image && <p className="break-all">Probe image: {response.image}</p>}
        {warnings.map((warning, i) => <p key={i} className="text-allow">Warning: {warning}</p>)}
        <section aria-label="Observed Hubble flows" className="space-y-2"><h4 className="font-display font-bold text-ink">Observed under current policy</h4>
          {!response.flows?.length ? <p>No Hubble flows observed. Observation is unavailable or inconclusive.</p> : response.flows.map((flow, i) => <div key={i} className="space-y-1 border border-line p-3"><p>{flow.source} → {flow.destination} · {flow.l4}</p><p>Hubble verdict: {flow.verdict}{flow.dropReason && ` · ${flow.dropReason}`}</p><p>{flow.time}{flow.direction && ` · ${flow.direction}`}</p>{flow.decision && <p>Observed policy decision: {flow.decision}</p>}{flow.allowedBy?.map((policy, j) => <p key={`allow-${j}`}>Hubble allowed by: {policy.display}</p>)}{flow.deniedBy?.map((policy, j) => <p key={`deny-${j}`}>Hubble denied by: {policy.display}</p>)}</div>)}
        </section>
        <section aria-label="Candidate simulation" className="space-y-2"><h4 className="font-display font-bold text-ink">Candidate simulation evidence</h4>
          {!simulation?.rows?.length ? <p>No modeled result rows; candidate impact is inconclusive.</p> : simulation.rows.map((row, i) => <div key={i} className="space-y-1 border border-line p-3"><p>{row.change} · {row.source} → {row.destination} · {row.protocol}:{row.port}</p><p>Baseline: {row.baselineAllowed === true ? 'ALLOWED' : row.baselineAllowed === false ? 'BLOCKED' : 'INCONCLUSIVE'} · Candidate: {row.candidateAllowed === true ? 'ALLOWED' : row.candidateAllowed === false ? 'BLOCKED' : 'INCONCLUSIVE'}</p><p>{row.explanation}</p></div>)}
        </section>
      </div>
    </details>
  </div>
}
