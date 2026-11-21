import type { Page } from '@playwright/test'
import type { ConnectionProbeRequest, ConnectionProbeResponse } from '../src/api'
import { LOOKS_CORRECT_CNP, VERDICT } from './fixtures/lab'
import { expect, openTab, test, typeSlowly, visibleForm } from './fixtures/test'

const response: ConnectionProbeResponse = {
  namespace: 'webapp', pod: 'webapp-123', host: 'postgres.postgres.svc', port: 5432, protocol: 'TCP',
  outcome: 'connected', message: 'TCP connection completed', containerName: 'guardbee-probe-1',
  flows: [{ time: '2026-11-17T12:00:00Z', source: 'webapp/webapp-123', destination: 'postgres/postgres-0', l4: 'TCP:5432', verdict: 'FORWARDED' }],
  simulation: { ...VERDICT, counts: { ...VERDICT.counts, notSimulated: 0 }, rows: [{ ...VERDICT.rows[0], baselineAllowed: true, candidateAllowed: false }] },
}
// The UI reads the streamed endpoint: stages, then one terminal line.
const ALL_STAGES = ['authorize', 'capture', 'inject', 'run', 'collect', 'simulate']
function probeStream(result: unknown, stages: string[] = ALL_STAGES, terminal: Record<string, unknown> = { result }) {
  return { contentType: 'application/x-ndjson', body: [...stages.map((stage) => ({ stage })), terminal].map((line) => JSON.stringify(line)).join('\n') + '\n' }
}
const panel = (page: Page) => page.getByRole('region', { name: 'Connectivity tests', exact: true })
const configuration = (page: Page) => page.getByRole('form', { name: 'Connection test configuration' })
const run = (page: Page) => configuration(page).getByRole('button', { name: 'Review & run connection test' })
const prediction = (page: Page) => page.getByRole('region', { name: 'Candidate prediction' })

async function enabled(page: Page, candidate = LOOKS_CORRECT_CNP) {
  await page.route('**/api/probes/capabilities', (route) => route.fulfill({ json: { enabled: true } }))
  await page.route('**/api/probes/pods?*', (route) => route.fulfill({ json: { pods: [{ name: 'webapp-123', uid: 'uid-original' }] } }))
  await openTab(page, 'Verdict')
  const main = visibleForm(page)
  await main.getByLabel('Namespace', { exact: true }).fill('webapp')
  await main.locator('textarea').fill(candidate)
  await panel(page).getByRole('button', { name: /Connectivity tests/ }).click()
  const form = configuration(page)
  await form.getByLabel('Source Pod').selectOption('uid-original')
  await form.getByLabel('Host or IP').fill('postgres.postgres.svc')
  return form
}

async function submit(page: Page) {
  page.once('dialog', (dialog) => dialog.accept())
  await run(page).click()
}

test.describe('Connectivity tests', () => {
  test('disabled capability and capability failure fail closed', async ({ page }) => {
    let podLookups = 0
    await page.route('**/api/probes/pods?*', (route) => { podLookups++; return route.fulfill({ json: { pods: [] } }) })
    await openTab(page, 'Verdict')
    await expect(page.getByRole('button', { name: 'TCP Probe', exact: true })).toHaveCount(0)
    await panel(page).getByRole('button', { name: /Connectivity tests/ }).click()
    await expect(panel(page)).toContainText('Connection tests are disabled')
    await expect(run(page)).toBeDisabled()
    await expect(configuration(page).getByLabel('Source Pod')).toContainText('Enable connectivity tests first')
    await expect(panel(page).getByLabel('Connectivity enablement')).toContainText('./guardbee ui --enable-probes')
    await page.route('**/api/probes/capabilities', (route) => route.fulfill({ status: 503, body: 'capability unavailable' }))
    await panel(page).getByRole('button', { name: /Connectivity tests/ }).click()
    await panel(page).getByRole('button', { name: /Connectivity tests/ }).click()
    await expect(panel(page).getByRole('status')).toContainText(['Load a nonempty candidate', 'Test availability could not be verified'])
    await expect(run(page)).toBeDisabled()
    expect(podLookups).toBe(0)
  })

  test('requires a loaded candidate, inherits Verdict namespace, and has no nested or duplicated candidate form', async ({ page }) => {
    let posts = 0
    await page.route('**/api/probes/connection/stream', (route) => { posts++; return route.fulfill(probeStream(response)) })
    const form = await enabled(page, '')
    await expect(run(page)).toBeDisabled()
    await expect(form.locator('textarea')).toHaveCount(0)
    await expect(form.getByLabel('Source namespace')).toHaveCount(0)
    await expect(page.locator('form form')).toHaveCount(0)
    await expect(visibleForm(page).getByLabel('Candidate YAML', { exact: true })).toBeVisible()
    await expect(panel(page)).toContainText('Source namespace: webapp')
    expect(posts).toBe(0)
  })

  test('confirmation sends inherited candidate, protocol, and Pod UID; outcome leads evidence', async ({ page }) => {
    const requests: ConnectionProbeRequest[] = []
    await page.route('**/api/probes/connection/stream', (route) => { requests.push(route.request().postDataJSON()); return route.fulfill(probeStream(response)) })
    await enabled(page)
    page.once('dialog', async (dialog) => {
      expect(dialog.message()).toContain('changing the Pod spec but not its labels')
      expect(dialog.message()).toContain('entry remains until normal Pod replacement')
      expect(dialog.message()).toContain('does NOT automatically restart or delete')
      expect(dialog.message()).toContain('UID uid-original')
      await dialog.dismiss()
    })
    await run(page).click()
    expect(requests).toHaveLength(0)
    await submit(page)
    await expect(prediction(page).getByRole('heading')).toHaveText('BLOCKED')
    await expect(prediction(page)).toContainText('Baseline modelALLOWED')
    await expect(prediction(page)).toContainText('With candidateBLOCKED')
    expect(requests).toEqual([{ namespace: 'webapp', pod: 'webapp-123', uid: 'uid-original', host: 'postgres.postgres.svc', port: 5432, protocol: 'TCP', candidateYAML: LOOKS_CORRECT_CNP, replaceExisting: true, candidateNamespace: 'webapp' }])
    await expect(page.getByRole('region', { name: 'Observed Hubble flows' })).not.toBeVisible()
    await panel(page).getByText(/Evidence & limitations/).click()
    await expect(page.getByRole('region', { name: 'Observed Hubble flows' })).toContainText('FORWARDED')
  })

  test('main candidate edits preserve the exact submitted snapshot and mark prediction stale', async ({ page }) => {
    await page.route('**/api/probes/connection/stream', (route) => route.fulfill(probeStream(response)))
    await enabled(page)
    await submit(page)
    const submitted = page.getByRole('region', { name: 'Submitted connection test' })
    await submitted.getByText(/Submitted candidate snapshot/).click()
    await expect(submitted.locator('pre')).toHaveText(LOOKS_CORRECT_CNP)
    const yaml = visibleForm(page).getByLabel('Candidate YAML', { exact: true })
    await yaml.focus()
    await page.keyboard.press('Control+End')
    await typeSlowly(page, '\n# edited candidate\n')
    await expect(submitted.getByRole('status')).toContainText('Results are stale')
    await expect(submitted.locator('pre')).toHaveText(LOOKS_CORRECT_CNP)
    await yaml.fill(LOOKS_CORRECT_CNP)
    await expect(submitted.getByRole('status')).toHaveCount(0)
  })

  test('UDP sends protocol and fixed datagram only; both-blocked UNCHANGED stays BLOCKED', async ({ page }) => {
    let request: ConnectionProbeRequest | undefined
    await page.route('**/api/probes/connection/stream', (route) => {
      request = route.request().postDataJSON()
      return route.fulfill(probeStream({ ...response, protocol: 'UDP', outcome: 'generated', message: 'One datagram generated', simulation: { ...response.simulation, rows: [{ ...VERDICT.rows[0], change: 'UNCHANGED', baselineAllowed: false, candidateAllowed: false }] } }))
    })
    const form = await enabled(page)
    await form.getByLabel('Protocol').selectOption('UDP')
    await expect(form).toContainText('one bounded datagram with a fixed payload')
    page.once('dialog', async (dialog) => {
      expect(dialog.message()).toContain('one bounded UDP datagram with a fixed payload')
      expect(dialog.message()).toContain('27 bytes: guardbee-connectivity-probe')
      expect(dialog.message()).toContain('does not prove reachability or delivery')
      await dialog.accept()
    })
    await run(page).click()
    await expect(prediction(page).getByRole('heading')).toHaveText('BLOCKED')
    await expect(prediction(page)).toContainText('Baseline modelBLOCKED')
    await expect(panel(page)).toContainText('Traffic generation: generated')
    expect(request?.protocol).toBe('UDP')
    expect(Object.keys(request!)).toEqual(['namespace', 'pod', 'uid', 'host', 'port', 'protocol', 'candidateYAML', 'replaceExisting', 'candidateNamespace'])
  })

  test('attempt warnings stay visible; standing notices and repeated trace events are folded away', async ({ page }) => {
    const result: ConnectionProbeResponse = {
      ...response,
      flows: [{ ...response.flows![0], count: 8 }, { ...response.flows![0], verdict: 'DROPPED', count: 1 }],
      warnings: ['Simulation inconclusive: Kubernetes NetworkPolicy objects in namespace postgres are not included in this probe engine baseline'],
      notices: ['The terminated ephemeral-container entry cannot be removed or restarted and remains until the Pod is replaced.'],
      simulation: undefined,
    }
    await page.route('**/api/probes/connection/stream', (route) => route.fulfill(probeStream(result)))
    await enabled(page)
    await submit(page)
    await expect(prediction(page).getByRole('heading')).toHaveText('INCONCLUSIVE')
    await expect(page.getByRole('list', { name: 'Attempt warnings' })).toBeVisible()
    await expect(page.getByRole('list', { name: 'Attempt warnings' })).toContainText('namespace postgres')
    await expect(page.getByRole('region', { name: 'Test notes' })).not.toBeVisible()
    await expect(panel(page).getByText(/Evidence & limitations/)).toContainText('2 distinct flows (9 Hubble events) · 1 notes')
    await panel(page).getByText(/Evidence & limitations/).click()
    await expect(page.getByRole('region', { name: 'Observed Hubble flows' })).toContainText('×8 events')
    await expect(page.getByRole('region', { name: 'Test notes' })).toContainText('entry cannot be removed')
  })

  for (const scenario of ['missing decisions', 'mixed decisions', 'not simulated', 'missing flows', 'skipped baseline', 'missing simulation'] as const) {
    test(`${scenario} never implies a universal allow`, async ({ page }) => {
      const simulation = { ...response.simulation!, rows: [{ ...VERDICT.rows[0], baselineAllowed: true, candidateAllowed: true }] }
      const result = { ...response, simulation }
      if (scenario === 'missing decisions') simulation.rows = [{ ...VERDICT.rows[0] }] as typeof simulation.rows
      if (scenario === 'mixed decisions') simulation.rows.push({ ...simulation.rows[0], candidateAllowed: false })
      if (scenario === 'not simulated') simulation.counts = { ...simulation.counts, notSimulated: 1 }
      if (scenario === 'missing flows') result.flows = []
      if (scenario === 'skipped baseline') simulation.skippedPolicies = ['CNP:webapp/node-selectors']
      if (scenario === 'missing simulation') result.simulation = undefined as unknown as typeof simulation
      await page.route('**/api/probes/connection/stream', (route) => route.fulfill(probeStream(result)))
      await enabled(page)
      await submit(page)
      await expect(prediction(page).getByRole('heading')).toHaveText('INCONCLUSIVE')
    })
  }

  test('namespace edits require fresh Pod selection and preserve uncertain mutation warnings', async ({ page }) => {
    let posts = 0
    await page.route('**/api/probes/connection/stream', (route) => { posts++; return route.fulfill({ status: 504, body: 'Timed out waiting for ephemeral container status' }) })
    const form = await enabled(page)
    await submit(page)
    await expect(panel(page).getByRole('alert')).toContainText('may already have been added')
    await page.route('**/api/probes/pods?*', (route) => route.fulfill({ json: { pods: [{ name: 'replacement-pod', uid: 'uid-replacement' }] } }))
    await visibleForm(page).getByLabel('Namespace', { exact: true }).fill('other')
    await expect(form.getByLabel('Source Pod')).toHaveValue('')
    await expect(run(page)).toBeDisabled()
    await form.getByLabel('Source Pod').selectOption('uid-replacement')
    await expect(panel(page).getByRole('alert')).toContainText('original Pod webapp/webapp-123 (UID uid-original)')
    await expect(panel(page)).toContainText('Results are stale')
    expect(posts).toBe(1)
  })

  test('all namespaces requires explicit source namespace; stale inventories are ignored', async ({ page }) => {
    const form = await enabled(page)
    await visibleForm(page).getByText('All namespaces', { exact: true }).click()
    await expect(form.getByLabel('Source namespace')).toBeVisible()
    await expect(run(page)).toBeDisabled()
    let release!: () => void
    const pending = new Promise<void>((resolve) => { release = resolve })
    await page.route('**/api/probes/pods?*', async (route) => {
      const namespace = new URL(route.request().url()).searchParams.get('namespace')
      if (namespace === 'slow') await pending
      await route.fulfill({ json: { pods: [{ name: `${namespace}-pod`, uid: `${namespace}-uid` }] } })
    })
    const slow = page.waitForRequest('**/api/probes/pods?namespace=slow')
    await form.getByLabel('Source namespace').fill('slow')
    await slow
    await form.getByLabel('Source namespace').fill('fast')
    await form.getByLabel('Source Pod').selectOption('fast-uid')
    release()
    await expect(form.getByLabel('Source Pod').locator('option')).toHaveText(['Select an existing Pod', 'fast-pod'])
  })

  test('double submission and tab changes cannot repeat pending mutation', async ({ page }) => {
    let posts = 0
    let release!: () => void
    const pending = new Promise<void>((resolve) => { release = resolve })
    await page.route('**/api/probes/connection/stream', async (route) => { posts++; await pending; await route.fulfill(probeStream(response)) })
    const form = await enabled(page)
    let confirmations = 0
    page.on('dialog', (dialog) => { confirmations++; return dialog.accept() })
    await form.evaluate((element) => {
      element.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
      element.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
    })
    await expect.poll(() => posts).toBe(1)
    await page.getByRole('button', { name: 'Flows', exact: true }).click()
    await page.getByRole('button', { name: 'Verdict', exact: true }).click()
    await expect(form.getByRole('button', { name: 'Running connection test…' })).toBeDisabled()
    await expect(visibleForm(page).getByRole('button', { name: 'Reset', exact: true })).toBeDisabled()
    release()
    await expect(prediction(page).getByRole('heading')).toHaveText('BLOCKED')
    expect(posts).toBe(1)
    expect(confirmations).toBe(1)
  })

  test('in-flight candidate changes keep old snapshot; JSON report preserves evidence and server metadata', async ({ page }) => {
    let release!: () => void
    const pending = new Promise<void>((resolve) => { release = resolve })
    const result = { ...response, uid: 'uid-original', context: 'lab-review', apiServer: 'https://cluster.invalid', image: 'probe@sha256:123', startedAt: '2026-11-17T12:00:00Z', durationMs: 1234 }
    await page.route('**/api/probes/connection/stream', async (route) => { await pending; await route.fulfill(probeStream(result)) })
    await enabled(page)
    await page.route('**/api/probes/capabilities', (route) => route.fulfill({ json: { enabled: true, protocols: ['TCP', 'UDP'], context: 'lab-review', apiServer: 'https://cluster.invalid' } }))
    await panel(page).getByRole('button', { name: /Connectivity tests/ }).click()
    await panel(page).getByRole('button', { name: /Connectivity tests/ }).click()
    await expect(panel(page)).toContainText('Cluster: lab-review')
    await configuration(page).getByLabel('Source Pod').selectOption('uid-original')
    page.once('dialog', async (dialog) => { expect(dialog.message()).toContain('Cluster: lab-review'); await dialog.accept() })
    await run(page).click()
    await visibleForm(page).getByLabel('Candidate YAML', { exact: true }).fill(`${LOOKS_CORRECT_CNP}\n# next candidate`)
    release()
    await expect(prediction(page).getByRole('heading')).toHaveText('BLOCKED')
    await expect(panel(page)).toContainText('Results are stale')
    const downloadPromise = page.waitForEvent('download')
    await panel(page).getByRole('button', { name: 'Download test report (JSON)' }).click()
    const download = await downloadPromise
    const stream = await download.createReadStream()
    const chunks: Buffer[] = []
    for await (const chunk of stream!) chunks.push(Buffer.from(chunk))
    const report = JSON.parse(Buffer.concat(chunks).toString())
    expect(report.request.candidateYAML).toBe(LOOKS_CORRECT_CNP)
    expect(report.request.uid).toBe('uid-original')
    expect(report.response).toEqual(result)
    expect(report.capabilities.context).toBe('lab-review')
    expect(report.submittedAt).toMatch(/^\d{4}-/)
  })

  test('same UID in a different namespace cannot retain source selection', async ({ page }) => {
    const form = await enabled(page)
    await expect(run(page)).toBeEnabled()
    await visibleForm(page).getByLabel('Namespace', { exact: true }).fill('other')
    await expect(form.getByLabel('Source Pod')).toHaveValue('')
    await expect(run(page)).toBeDisabled()
    await expect(form.getByLabel('Source Pod').locator('option')).toHaveText(['Select an existing Pod', 'webapp-123'])
  })

  test('replacement mode is shared with connectivity and frozen in verdict runs and streams', async ({ page }) => {
    const verdicts: Record<string, unknown>[] = []
    let connection: ConnectionProbeRequest | undefined
    await page.route('**/api/verdict', (route) => { verdicts.push(route.request().postDataJSON()); return route.fulfill({ json: VERDICT }) })
    await page.route('**/api/probes/connection/stream', (route) => { connection = route.request().postDataJSON(); return route.fulfill(probeStream(response)) })
    await enabled(page)
    const main = visibleForm(page)
    await expect(main.getByLabel('Replace matching live policies')).toBeChecked()
    await main.getByText('Replace matching live policies', { exact: true }).click()
    await main.getByRole('button', { name: 'Run verdict', exact: true }).click()
    expect(verdicts[0].replaceExisting).toBe(false)
    await submit(page)
    expect(connection?.replaceExisting).toBe(false)
    await main.getByText('Replace matching live policies', { exact: true }).click()
    await expect(panel(page)).toContainText('Results are stale')
    await page.getByRole('button', { name: 'Duplicate to form', exact: true }).click()
    await expect(main.getByLabel('Replace matching live policies')).not.toBeChecked()
    await main.getByText('Follow (live)', { exact: true }).click()
    const stream = page.waitForRequest('**/api/verdict/stream?*')
    await main.getByRole('button', { name: 'Start following', exact: true }).click()
    expect(new URL((await stream).url()).searchParams.get('replaceExisting')).toBe('false')
  })

  test('candidate namespace is distinct from explicit source in all-namespace scope', async ({ page }) => {
    let request: ConnectionProbeRequest | undefined
    await page.route('**/api/probes/connection/stream', (route) => { request = route.request().postDataJSON(); return route.fulfill(probeStream(response)) })
    const form = await enabled(page)
    await visibleForm(page).getByText('All namespaces', { exact: true }).click()
    await form.getByLabel('Source namespace').fill('source-only')
    await form.getByLabel('Source Pod').selectOption('uid-original')
    await submit(page)
    await expect(prediction(page).getByRole('heading')).toHaveText('BLOCKED')
    expect(request?.namespace).toBe('source-only')
    expect(request?.candidateNamespace).toBe('')
  })

  test('returning to tab refreshes replaced Pod inventory and marks completed evidence stale', async ({ page }) => {
    await page.route('**/api/probes/connection/stream', (route) => route.fulfill(probeStream(response)))
    await enabled(page)
    await submit(page)
    await expect(prediction(page).getByRole('heading')).toHaveText('BLOCKED')
    await page.getByRole('button', { name: 'Flows', exact: true }).click()
    await page.route('**/api/probes/pods?*', (route) => route.fulfill({ json: { pods: [{ name: 'webapp-123', uid: 'replacement-uid' }] } }))
    await page.getByRole('button', { name: 'Verdict', exact: true }).click()
    await expect(configuration(page).getByLabel('Source Pod')).toHaveValue('')
    await expect(panel(page)).toContainText('Results are stale')
  })

  test('inventory refresh does not mark results stale while the same Pod is loading', async ({ page }) => {
    await page.route('**/api/probes/connection/stream', (route) => route.fulfill(probeStream(response)))
    const form = await enabled(page)
    await submit(page)
    await expect(prediction(page)).toBeVisible()
    let release!: () => void
    const pending = new Promise<void>((resolve) => { release = resolve })
    await page.route('**/api/probes/pods?*', async (route) => { await pending; await route.fulfill({ json: { pods: [{ name: 'webapp-123', uid: 'uid-original' }] } }) })
    await form.getByRole('button', { name: 'Refresh running Pods' }).click()
    await expect(form.getByLabel('Source Pod')).toContainText('Loading eligible Pods…')
    await expect(panel(page).getByText(/Results are stale/)).toHaveCount(0)
    release()
    await expect(form.getByLabel('Source Pod')).toHaveValue('uid-original')
    await expect(panel(page).getByText(/Results are stale/)).toHaveCount(0)
  })

  test('network failure remains an uncertain mutation and is never retried', async ({ page }) => {
    let posts = 0
    await page.route('**/api/probes/connection/stream', (route) => { posts++; return route.abort('failed') })
    await enabled(page)
    await submit(page)
    await expect(panel(page).getByRole('alert')).toContainText('may already have been added')
    expect(posts).toBe(1)
  })

  test('reset clears completed connectivity inputs and evidence without remounting the panel', async ({ page }) => {
    await page.route('**/api/probes/connection/stream', (route) => route.fulfill(probeStream(response)))
    const form = await enabled(page)
    await submit(page)
    await expect(prediction(page)).toBeVisible()
    await panel(page).getByRole('button', { name: 'Clear completed test' }).click()
    await expect(prediction(page)).toHaveCount(0)
    await submit(page)
    await expect(prediction(page)).toBeVisible()
    await visibleForm(page).getByRole('button', { name: 'Reset', exact: true }).click()
    await expect(prediction(page)).toHaveCount(0)
    await expect(form.getByLabel('Host or IP')).toHaveValue('')
    await expect(run(page)).toBeDisabled()
  })

  test('eligible Pod exclusions explain an empty chooser and permit refresh', async ({ page }) => {
    const form = await enabled(page)
    await page.route('**/api/probes/pods?*', (route) => route.fulfill({ json: { pods: [], excluded: { 'host network': 2, 'not ready': 1 } } }))
    await form.getByRole('button', { name: 'Refresh running Pods' }).click()
    await expect(form.getByLabel('Source Pod')).toContainText('No eligible Pods found')
    await expect(form).toContainText('host network (2)')
    await expect(form).toContainText('not ready (1)')
    await expect(run(page)).toBeDisabled()
    await page.route('**/api/probes/pods?*', (route) => route.fulfill({ json: { pods: [{ name: 'eligible', uid: 'new-uid' }], excluded: { 'host network': 2 } } }))
    await form.getByRole('button', { name: 'Refresh running Pods' }).click()
    await form.getByLabel('Source Pod').selectOption('new-uid')
    await expect(run(page)).toBeEnabled()
  })

  for (const status of [400, 403, 405, 409, 413, 415, 429, 500, 504]) {
    test(`HTTP ${status} distinguishes definite rejection from uncertain mutation`, async ({ page }) => {
      await page.route('**/api/probes/connection/stream', (route) => route.fulfill({ status, body: 'Request rejected or unavailable' }))
      await enabled(page)
      await submit(page)
      const alert = panel(page).getByRole('alert')
      if (status < 500) {
        await expect(alert).toContainText('Test not started')
        await expect(alert).not.toContainText('may already have been added')
      } else await expect(alert).toContainText('may already have been added')
      await expect(panel(page).getByRole('button', { name: 'Download test report (JSON)' })).toBeVisible()
    })
  }

  for (const scenario of ['not simulated', 'replies only', 'skipped baseline', 'no judged flows']) {
    test(`empty verdict rows with ${scenario} never claim all unchanged`, async ({ page }) => {
      const counts = { ...VERDICT.counts, newlyDropped: 0, newlyAllowed: 0, unchanged: 0, notSimulated: scenario === 'not simulated' ? 1 : 0, replySkipped: scenario === 'replies only' ? 1 : 0 }
      await page.route('**/api/verdict', (route) => route.fulfill({ json: { ...VERDICT, rows: [], counts, skippedPolicies: scenario === 'skipped baseline' ? ['CNP:test/skipped'] : [] } }))
      await enabled(page)
      await visibleForm(page).getByRole('button', { name: 'Run verdict', exact: true }).click()
      await expect(page.getByText(/Inconclusive sample/)).toBeVisible()
      await expect(page.getByText(/No regressions.*all unchanged/)).toHaveCount(0)
    })
  }

  test('constraints reject commands; Pod listing errors can be refreshed', async ({ page }) => {
    const form = await enabled(page)
    for (const host of ['https://db', 'db;id', 'db:5432', '999.1.1.1']) {
      await form.getByLabel('Host or IP').fill(host)
      await expect(run(page)).toBeDisabled()
    }
    await form.getByLabel('Host or IP').fill('::1')
    for (const port of ['0', '65536', '1e3']) {
      await form.getByLabel('Port', { exact: true }).fill(port)
      await expect(run(page)).toBeDisabled()
    }
    await form.getByLabel('Port', { exact: true }).fill('443')
    await expect(run(page)).toBeEnabled()
    await page.route('**/api/probes/pods?*', (route) => route.fulfill({ status: 403, body: 'Pods permission denied' }))
    await form.getByRole('button', { name: 'Refresh running Pods' }).click()
    await expect(panel(page).getByRole('alert')).toContainText('Pods permission denied')
    await expect(run(page)).toBeDisabled()
  })

  test('console hierarchy fits desktop light, dark, and mobile', async ({ page }) => {
    await page.route('**/api/probes/connection/stream', (route) => route.fulfill(probeStream(response)))
    await enabled(page)
    await submit(page)
    await expect(prediction(page).getByRole('heading')).toHaveText('BLOCKED')
    await panel(page).scrollIntoViewIfNeeded()
    await page.screenshot({ path: '/tmp/opencode/connectivity-desktop.png', fullPage: true })
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'light'))
    await page.screenshot({ path: '/tmp/opencode/connectivity-light.png', fullPage: true })
    await page.evaluate(() => document.documentElement.setAttribute('data-theme', 'dark'))
    await page.screenshot({ path: '/tmp/opencode/connectivity-dark.png', fullPage: true })
    await page.setViewportSize({ width: 375, height: 812 })
    await page.screenshot({ path: '/tmp/opencode/connectivity-mobile.png', fullPage: true })
    const dimensions = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, width: window.innerWidth }))
    expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.width)
  })

  test.describe('probe image catalog and live progress', () => {
    const IMAGES = [
      { id: 'netshoot', name: 'netshoot', image: 'docker.io/nicolaka/netshoot@sha256:' + 'b'.repeat(64), protocols: ['TCP', 'UDP'], description: 'Toolbox', pinned: true },
      { id: 'busybox', name: 'BusyBox 1.37', image: 'docker.io/library/busybox:1.37', protocols: ['TCP'], description: 'Tiny', pinned: false },
    ]
    async function withCatalog(page: Page) {
      const form = await enabled(page)
      await page.route('**/api/probes/capabilities', (route) => route.fulfill({ json: { enabled: true, protocols: ['TCP', 'UDP'], images: IMAGES } }))
      await panel(page).getByRole('button', { name: /Connectivity tests/ }).click()
      await panel(page).getByRole('button', { name: /Connectivity tests/ }).click()
      await form.getByLabel('Source Pod').selectOption('uid-original')
      return form
    }

    test('picks a catalog image by id; a TCP-only image cannot run UDP', async ({ page }) => {
      let request: ConnectionProbeRequest | undefined
      await page.route('**/api/probes/connection/stream', (route) => { request = route.request().postDataJSON(); return route.fulfill(probeStream({ ...response, imageId: 'busybox' })) })
      const form = await withCatalog(page)
      const picker = form.getByRole('radiogroup', { name: 'Probe image' })
      await expect(picker.getByRole('radio')).toHaveCount(2)
      await expect(picker.getByRole('radio', { name: /netshoot/ })).toBeChecked()
      await expect(picker).toContainText('Tag only, re-pulled on every test')
      await form.getByLabel('Protocol').selectOption('UDP')
      await picker.getByRole('radio', { name: /BusyBox/ }).check()
      await expect(form.getByLabel('Protocol')).toHaveValue('TCP')
      await expect(form.getByLabel('Protocol').locator('option[value="UDP"]')).toHaveJSProperty('disabled', true)
      await expect(form.locator('input[name="image"], textarea[name="image"]')).toHaveCount(0)
      page.once('dialog', async (dialog) => { expect(dialog.message()).toContain('Probe image: BusyBox 1.37 (docker.io/library/busybox:1.37)'); await dialog.accept() })
      await run(page).click()
      await expect(prediction(page).getByRole('heading')).toHaveText('BLOCKED')
      expect(request?.imageId).toBe('busybox')
      expect(request?.protocol).toBe('TCP')
      await expect(page.getByRole('region', { name: 'Submitted connection test' })).toContainText('BusyBox 1.37')
      await picker.getByRole('radio', { name: /netshoot/ }).check()
      await expect(panel(page)).toContainText('Results are stale')
    })

    test('stepper shows streamed stages; an unreached simulation is skipped, and the path is drawn', async ({ page }) => {
      await page.route('**/api/probes/connection/stream', (route) => route.fulfill(probeStream(response, ['authorize', 'capture', 'inject', 'run', 'collect'])))
      await withCatalog(page)
      await submit(page)
      await expect(prediction(page).getByRole('heading')).toHaveText('BLOCKED')
      const steps = panel(page).getByRole('list', { name: 'Connection test progress' }).getByRole('listitem')
      await expect(steps).toHaveCount(6)
      for (let i = 0; i < 5; i++) await expect(steps.nth(i)).toHaveAttribute('data-state', 'done')
      await expect(steps.nth(5)).toHaveAttribute('data-state', 'skipped')
      await expect(prediction(page).getByRole('img')).toHaveAttribute('aria-label', 'webapp/webapp-123 to postgres/postgres-0: baseline allowed, candidate blocked')
    })

    test('a rejection after the stream began keeps its definite status and fails the current stage', async ({ page }) => {
      await page.route('**/api/probes/connection/stream', (route) => route.fulfill(probeStream(null, ['authorize', 'capture'], { error: 'Pod changed before injection; select it again', status: 409 })))
      await withCatalog(page)
      await submit(page)
      const alert = panel(page).getByRole('alert')
      await expect(alert).toContainText('Test not started')
      await expect(alert).toContainText('Pod changed before injection')
      const steps = panel(page).getByRole('list', { name: 'Connection test progress' }).getByRole('listitem')
      await expect(steps.nth(1)).toHaveAttribute('data-state', 'failed')
      await expect(steps.nth(2)).toHaveAttribute('data-state', 'skipped')
    })

    test('a stream that ends without a result is an uncertain mutation', async ({ page }) => {
      await page.route('**/api/probes/connection/stream', (route) => route.fulfill({ contentType: 'application/x-ndjson', body: '{"stage":"authorize"}\n{"stage":"capture"}\n{"stage":"inject"}\n' }))
      await withCatalog(page)
      await submit(page)
      const alert = panel(page).getByRole('alert')
      await expect(alert).toContainText('ended before reporting a result')
      await expect(alert).toContainText('may already have been added')
      await expect(panel(page).getByRole('list', { name: 'Connection test progress' }).getByRole('listitem').nth(2)).toHaveAttribute('data-state', 'failed')
    })
  })
})
