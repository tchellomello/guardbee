import { useEffect, useRef, useState } from 'react'
import {
  fetchNamespaces, fetchProbeCapabilities, fetchProbePods, runTCPProbe,
  type ProbePod, type TCPProbeRequest, type TCPProbeResponse,
} from '../api'
import { validProbeHost, validProbeNamespace, validProbePort } from '../shared/tcpProbe'
import { Field } from './NamespaceScope'

const inputClass = 'w-full min-w-0 border border-line bg-void px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-signal focus:outline-none disabled:cursor-not-allowed disabled:opacity-50'
const buttonClass = 'bg-signal px-5 py-2 font-display text-xs font-bold tracking-[0.1em] text-void uppercase transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40 cursor-pointer'
const errorText = (err: unknown) => err instanceof Error ? err.message : String(err)

type ProbeRequestSnapshot = Readonly<TCPProbeRequest>
type ProbeAttempt = { request: ProbeRequestSnapshot } & (
  { response: TCPProbeResponse; error?: never } | { error: string; response?: never }
)

export function TCPProbePanel({ active }: { active: boolean }) {
  const [capability, setCapability] = useState<{ enabled: boolean; message: string }>({ enabled: false, message: 'Checking probe availability…' })
  const [namespaces, setNamespaces] = useState<string[]>([])
  const [namespace, setNamespace] = useState('')
  const [inventory, setInventory] = useState<{ namespace: string; pods: ProbePod[]; loading: boolean; error: string }>({ namespace: '', pods: [], loading: false, error: '' })
  const [podUID, setPodUID] = useState('')
  const [host, setHost] = useState('')
  const [port, setPort] = useState('5432')
  const [candidateYAML, setCandidateYAML] = useState('')
  const [running, setRunning] = useState(false)
  const [attempt, setAttempt] = useState<ProbeAttempt | null>(null)
  const [podRefresh, setPodRefresh] = useState(0)
  // State alone is not a lock: two submit events can arrive before React
  // renders the disabled button. Never abort/retry a mutating POST on tab change.
  const runningRef = useRef(false)
  const mounted = useRef(false)

  useEffect(() => {
    mounted.current = true
    return () => { mounted.current = false }
  }, [])

  useEffect(() => {
    if (!active) return
    let ignore = false
    setCapability({ enabled: false, message: 'Checking probe availability…' })
    fetchProbeCapabilities().then((res) => {
      if (!ignore) setCapability(res.enabled === true
        ? { enabled: true, message: 'TCP probes enabled on this server.' }
        : { enabled: false, message: 'TCP probes are disabled. Start the server with --enable-probes and a digest-pinned --probe-image to enable this mutating action.' })
    }).catch((err) => {
      if (!ignore) setCapability({ enabled: false, message: `Probe availability could not be verified: ${errorText(err)}. No probe can be started.` })
    })
    return () => { ignore = true }
  }, [active])

  useEffect(() => {
    let ignore = false
    fetchNamespaces().then((res) => { if (!ignore) setNamespaces(res.namespaces) }).catch(() => {})
    return () => { ignore = true }
  }, [])

  useEffect(() => {
    if (!capability.enabled || !validProbeNamespace(namespace)) return
    let ignore = false
    setInventory({ namespace, pods: [], loading: true, error: '' })
    fetchProbePods(namespace).then((res) => {
      if (!ignore) setInventory({ namespace, pods: res.pods ?? [], loading: false, error: '' })
    }).catch((err) => {
      if (!ignore) setInventory({ namespace, pods: [], loading: false, error: errorText(err) })
    })
    return () => { ignore = true }
  }, [namespace, capability.enabled, podRefresh])

  const currentInventory = inventory.namespace === namespace && validProbeNamespace(namespace)
  const pods = currentInventory ? inventory.pods : []
  const selectedPod = pods.find((pod) => pod.uid === podUID)
  const ready = capability.enabled && selectedPod && validProbeHost(host) && validProbePort(port) && !inventory.loading
  const editedSinceAttempt = !!attempt && (
    attempt.request.namespace !== namespace || attempt.request.uid !== podUID ||
    attempt.request.host !== host || attempt.request.port !== Number(port) ||
    (attempt.request.candidateYAML ?? '') !== (candidateYAML.trim() ? candidateYAML : '')
  )

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!ready || runningRef.current || !selectedPod) return
    runningRef.current = true
    // All request fields are primitives: this frozen snapshot remains the
    // identity of the attempt even after the form is edited or Pods replaced.
    const request: ProbeRequestSnapshot = Object.freeze({
      namespace, pod: selectedPod.name, uid: selectedPod.uid, host, port: Number(port),
      ...(candidateYAML.trim() ? { candidateYAML } : {}),
    })
    const confirmed = window.confirm(
      `Run one finite TCP connection from existing Pod ${namespace}/${selectedPod.name} (UID ${selectedPod.uid}) to ${host}:${port}?\n\n` +
      'This adds an ephemeral container, changing the Pod spec but not its labels. The process exits, but its spec entry remains until normal Pod replacement. GuardBee does NOT automatically restart or delete the Pod.\n\n' +
      'This is actual TCP against current policy, not database authentication and not a test under the hypothetical candidate. Optional candidate YAML is simulated separately, never applied. No shell, UDP, or arbitrary arguments are run.'
    )
    if (!confirmed) { runningRef.current = false; return }
    setRunning(true)
    setAttempt(null)
    try {
      const response = await runTCPProbe(request)
      if (mounted.current) setAttempt({ request, response })
    } catch (err) {
      if (mounted.current) setAttempt({ request, error: errorText(err) })
    } finally {
      runningRef.current = false
      if (mounted.current) setRunning(false)
    }
  }

  return (
    <section aria-label="TCP Probe" className="space-y-6 min-w-0">
      <div className="border border-line bg-panel p-5 space-y-3">
        <h2 className="font-display text-sm font-bold tracking-wider uppercase">TCP Probe</h2>
        <p className="text-sm text-ink-dim">Generate real traffic from a running, existing Pod with one finite TCP connection. This is an opt-in cluster mutation, unlike read-only flow observation.</p>
        <p id="probe-capability" role="status" className="text-sm text-ink-dim break-words">{capability.message}</p>
      </div>
      <form onSubmit={handleSubmit} className="border border-line bg-panel p-5 space-y-5">
        <fieldset disabled={running || !capability.enabled} className="min-w-0 space-y-5">
          <div className="grid min-w-0 gap-5 sm:grid-cols-2 lg:grid-cols-4">
            <Field label="Probe namespace">
              <input value={namespace} list="probe-namespaces" maxLength={63} required pattern="[a-z0-9]([a-z0-9-]*[a-z0-9])?" className={inputClass} placeholder="myapp" onChange={(e) => { setNamespace(e.target.value); setPodUID('') }} />
              <datalist id="probe-namespaces">{namespaces.map((ns) => <option key={ns} value={ns} />)}</datalist>
            </Field>
            <Field label="Running Pod">
              <select value={selectedPod?.uid ?? ''} required className={inputClass} onChange={(e) => setPodUID(e.target.value)}>
                <option value="">{currentInventory && inventory.loading ? 'Loading Pods…' : 'Select an existing Pod'}</option>
                {pods.map((pod) => <option key={pod.uid} value={pod.uid}>{pod.name}</option>)}
              </select>
            </Field>
            <Field label="Host or IP">
              <input value={host} required maxLength={253} aria-describedby="probe-host-help" aria-invalid={!!host && !validProbeHost(host)} className={inputClass} placeholder="db.myapp.svc.cluster.local" onChange={(e) => setHost(e.target.value)} />
            </Field>
            <Field label="TCP port">
              <input value={port} required inputMode="numeric" maxLength={5} pattern="[0-9]{1,5}" aria-invalid={!validProbePort(port)} className={inputClass} onChange={(e) => setPort(e.target.value)} />
            </Field>
          </div>
          <p id="probe-host-help" className="text-xs text-ink-dim">One DNS name or IPv4/IPv6 address (IPv6 without brackets); no URL or embedded port. TCP port must be an integer from 1 to 65535.</p>
          {currentInventory && inventory.error && <p role="alert" className="text-sm text-drop break-words">Could not list running Pods: {inventory.error}</p>}
          {currentInventory && !inventory.loading && !inventory.error && !pods.length && <p role="status" className="text-sm text-ink-dim">No running Pods available in this namespace.</p>}
          <button type="button" className="border border-line px-3 py-2 text-xs text-ink-dim cursor-pointer disabled:opacity-40" disabled={!validProbeNamespace(namespace) || inventory.loading} onClick={() => { setPodUID(''); setPodRefresh((value) => value + 1) }}>Refresh running Pods</button>
          <Field label="Candidate YAML (optional, simulation only)">
            <textarea value={candidateYAML} rows={7} spellCheck={false} className={`${inputClass} font-mono`} placeholder="Paste a candidate policy to simulate against observed probe flows; it is never applied." onChange={(e) => setCandidateYAML(e.target.value)} />
          </Field>
        </fieldset>
        <p className="text-xs text-ink-dim">Confirmation is required before adding an ephemeral container. It changes the Pod spec, not labels; its entry remains after exit until normal replacement. No automatic restart or deletion.</p>
        <button type="submit" disabled={!ready || running} aria-describedby="probe-capability probe-host-help" className={buttonClass}>{running ? 'Running TCP probe…' : 'Review & run TCP probe'}</button>
        {running && <p role="status" className="text-sm text-ink-dim">Waiting for the finite TCP probe and observations. Switching tabs does not cancel or repeat the probe.</p>}
      </form>
      {attempt && <section aria-label="Submitted probe attempt" className="border border-line bg-panel p-5 space-y-3 min-w-0 break-words">
        <h3 className="font-display text-xs font-bold uppercase tracking-wider">Submitted probe attempt</h3>
        <p className="text-sm">Original Pod: {attempt.request.namespace}/{attempt.request.pod} · UID {attempt.request.uid}</p>
        <p className="text-sm">Original TCP target: {attempt.request.host}:{attempt.request.port}</p>
        {editedSinceAttempt && <p role="status" className="text-sm text-allow">The form has changed since this attempt. These results and warnings refer only to the original Pod, target, and candidate snapshot below, not the edited form. Run a new confirmed probe to test the edited inputs.</p>}
        {attempt.request.candidateYAML ? <details>
          <summary className="cursor-pointer text-xs text-ink-dim">Submitted candidate YAML snapshot (simulation only)</summary>
          <pre className="mt-3 whitespace-pre-wrap break-words text-xs text-ink-dim">{attempt.request.candidateYAML}</pre>
        </details> : <p className="text-xs text-ink-dim">No candidate YAML was submitted with this attempt.</p>}
      </section>}
      {attempt?.error !== undefined && <div role="alert" className="border border-drop/40 bg-drop/10 p-4 text-sm text-drop break-words space-y-2"><p>{attempt.error}</p><p>The request failed; an ephemeral container may already have been added to the original Pod {attempt.request.namespace}/{attempt.request.pod} (UID {attempt.request.uid}). Inspect that Pod before deciding to run again, even if the form now selects another Pod. GuardBee does not automatically retry, restart, or delete it.</p></div>}
      {attempt?.response && <ProbeResult response={attempt.response} request={attempt.request} />}
    </section>
  )
}

function ProbeResult({ response, request }: { response: TCPProbeResponse; request: ProbeRequestSnapshot }) {
  const simulation = response.simulation
  return (
    <div className="space-y-5 min-w-0" aria-live="polite">
      <section aria-label="TCP transport result" className="border border-line bg-panel p-5 space-y-3 break-words">
        <h3 className="font-display text-xs font-bold uppercase tracking-wider">TCP transport result: {response.outcome}</h3>
        <p className="text-sm">{request.namespace}/{request.pod} (UID {request.uid}) → {request.host}:{request.port}</p>
        <p className="text-sm text-ink-dim">{response.message}</p>
        <p className="text-xs text-ink-dim">A connected result proves a TCP connection only, not database authentication. Failed or inconclusive TCP does not by itself prove policy denial.</p>
        {response.containerName && <p className="text-xs text-ink-dim">Ephemeral container: {response.containerName}. Its entry remains until normal Pod replacement; no automatic restart or deletion.</p>}
        {(response.warnings ?? []).map((warning, i) => <p key={i} className="text-sm text-allow">Warning: {warning}</p>)}
      </section>
      <section aria-label="Observed Hubble flows" className="border border-line bg-panel p-5 space-y-3 min-w-0">
        <h3 className="font-display text-xs font-bold uppercase tracking-wider">Observed Hubble flows</h3>
        <p className="text-xs text-ink-dim">Real observations under current policy, not candidate predictions. Missing observations are not proof of allow or deny.</p>
        {!response.flows?.length ? <p className="text-sm text-ink-dim">No Hubble flows observed. Observation is unavailable or inconclusive.</p> :
          <ul className="space-y-3">{response.flows.map((flow, i) => <li key={i} className="border border-line p-3 text-xs break-words space-y-1">
            <p>{flow.source} → {flow.destination} · {flow.l4}</p>
            <p>Hubble verdict: {flow.verdict}{flow.dropReason && ` · ${flow.dropReason}`}</p>
            <p className="text-ink-dim">{flow.time}{flow.direction && ` · ${flow.direction}`}</p>
            {flow.decision && <p>Observed policy decision: {flow.decision}</p>}
            {flow.allowedBy?.map((policy, j) => <p key={`allow-${j}`}>Hubble allowed by: {policy.display}</p>)}
            {flow.deniedBy?.map((policy, j) => <p key={`deny-${j}`}>Hubble denied by: {policy.display}</p>)}
          </li>)}</ul>}
      </section>
      <section aria-label="Candidate simulation" className="border border-line bg-panel p-5 space-y-3 break-words">
        <h3 className="font-display text-xs font-bold uppercase tracking-wider">Candidate simulation</h3>
        <p className="text-xs text-ink-dim">Hypothetical engine comparison only; the candidate was not applied and the TCP probe did not run under it. UNCHANGED means no modeled change, not allowed.</p>
        <p className="text-xs text-ink-dim">This section refers only to the submitted candidate YAML snapshot above, never subsequent textarea edits.</p>
        {!simulation ? <p className="text-sm text-ink-dim">{request.candidateYAML ? 'Simulation unavailable or inconclusive for this probe.' : 'No candidate supplied; simulation not requested.'}</p> : <>
          <p className="text-sm">{simulation.flowsSampled} flows sampled · {simulation.counts.newlyDropped} NEWLY_DROPPED · {simulation.counts.newlyAllowed} NEWLY_ALLOWED · {simulation.counts.unchanged} UNCHANGED</p>
          <p className="text-xs text-ink-dim">{simulation.counts.notSimulated} NOT_SIMULATED · {simulation.counts.replySkipped} reply flows skipped</p>
          {!simulation.rows?.length && <p className="text-sm text-ink-dim">No modeled result rows; candidate impact is inconclusive.</p>}
          {simulation.skippedPolicies?.map((policy, i) => <p key={i} className="text-sm text-allow">Baseline policy skipped: {policy}. Simulation does not account for it.</p>)}
          <ul className="space-y-3">{simulation.rows?.map((row, i) => <li key={i} className="border border-line p-3 text-xs space-y-1">
            <p>{row.change} · {row.source} → {row.destination} · {row.protocol}:{row.port} · {row.count} flows{row.side && ` · ${row.side}`}</p>
            <p className="text-ink-dim">{row.explanation}</p>
          </li>)}</ul>
        </>}
      </section>
    </div>
  )
}
