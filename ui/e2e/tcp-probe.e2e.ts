import type { Page } from '@playwright/test'
import type { TCPProbeRequest, TCPProbeResponse } from '../src/api'
import { LOOKS_CORRECT_CNP, VERDICT } from './fixtures/lab'
import { expect, openTab, test, visibleForm } from './fixtures/test'

const response: TCPProbeResponse = {
  namespace: 'webapp', pod: 'webapp-123', host: 'postgres.postgres.svc', port: 5432,
  outcome: 'connected', message: 'TCP connection completed', containerName: 'guardbee-probe-1',
  warnings: [], flows: [{ time: '2026-11-17T12:00:00Z', source: 'webapp/webapp-123', destination: 'postgres/postgres-0', l4: 'TCP:5432', verdict: 'FORWARDED' }],
}

async function enabled(page: Page) {
  await page.route('**/api/probes/capabilities', (route) => route.fulfill({ json: { enabled: true } }))
  await page.route('**/api/probes/pods?*', (route) => route.fulfill({ json: { pods: [{ name: 'webapp-123', uid: 'uid-original' }] } }))
  await openTab(page, 'TCP Probe')
  const form = visibleForm(page)
  await expect(form.getByLabel('Probe namespace')).toBeEnabled()
  await form.getByLabel('Probe namespace').fill('webapp')
  await form.getByLabel('Running Pod').selectOption('uid-original')
  await form.getByLabel('Host or IP').fill('postgres.postgres.svc')
  return form
}

test.describe('TCP Probe', () => {
  test('disabled capability never offers a mutating action', async ({ page }) => {
    let posts = 0
    await page.route('**/api/probes/tcp', (route) => { posts++; return route.fulfill({ json: response }) })
    await openTab(page, 'TCP Probe')
    await expect(page.getByText(/TCP probes are disabled/)).toBeVisible()
    await expect(page.getByRole('button', { name: 'Review & run TCP probe' })).toBeDisabled()
    await expect(visibleForm(page).getByLabel('Probe namespace')).toBeDisabled()
    expect(posts).toBe(0)
  })

  test('capability failure fails closed with an accessible explanation', async ({ page }) => {
    await page.route('**/api/probes/capabilities', (route) => route.fulfill({ status: 503, body: 'capability unavailable' }))
    await openTab(page, 'TCP Probe')
    await expect(page.getByRole('status').filter({ hasText: 'Probe availability could not be verified' })).toContainText('capability unavailable')
    await expect(page.getByRole('button', { name: 'Review & run TCP probe' })).toBeDisabled()
  })

  test('explicit confirmation sends Pod UID and separates actual traffic from simulation', async ({ page }) => {
    const requests: TCPProbeRequest[] = []
    await page.route('**/api/probes/tcp', (route) => {
      requests.push(route.request().postDataJSON())
      return route.fulfill({ json: { ...response, simulation: VERDICT } })
    })
    const form = await enabled(page)
    await form.getByLabel('Candidate YAML').fill(LOOKS_CORRECT_CNP)
    page.once('dialog', async (dialog) => {
      expect(dialog.message()).toContain('changing the Pod spec but not its labels')
      expect(dialog.message()).toContain('entry remains until normal Pod replacement')
      expect(dialog.message()).toContain('does NOT automatically restart or delete')
      expect(dialog.message()).toContain('not database authentication')
      expect(dialog.message()).toContain('UID uid-original')
      await dialog.dismiss()
    })
    await form.getByRole('button', { name: 'Review & run TCP probe' }).click()
    expect(requests).toHaveLength(0)
    page.once('dialog', (dialog) => dialog.accept())
    await form.getByRole('button', { name: 'Review & run TCP probe' }).click()
    await expect(page.getByRole('region', { name: 'TCP transport result' })).toContainText('connected')
    expect(requests).toEqual([{ namespace: 'webapp', pod: 'webapp-123', uid: 'uid-original', host: 'postgres.postgres.svc', port: 5432, candidateYAML: LOOKS_CORRECT_CNP }])
    await expect(page.getByRole('region', { name: 'Observed Hubble flows' })).toContainText('FORWARDED')
    await expect(page.getByRole('region', { name: 'Candidate simulation' })).toContainText('UNCHANGED means no modeled change, not allowed')
  })

  for (const outcome of ['failed', 'inconclusive'] as const) {
    test(`${outcome} TCP and missing simulation are not presented as policy denial`, async ({ page }) => {
      await page.route('**/api/probes/tcp', (route) => route.fulfill({ json: { ...response, outcome, flows: [], warnings: ['Hubble unavailable'] } }))
      const form = await enabled(page)
      await form.getByLabel('Candidate YAML').fill(LOOKS_CORRECT_CNP)
      page.once('dialog', (dialog) => dialog.accept())
      await form.getByRole('button', { name: 'Review & run TCP probe' }).click()
      await expect(page.getByRole('region', { name: 'TCP transport result' })).toContainText(`result: ${outcome}`)
      await expect(page.getByRole('region', { name: 'TCP transport result' })).toContainText('does not by itself prove policy denial')
      await expect(page.getByText('Warning: Hubble unavailable')).toBeVisible()
      await expect(page.getByRole('region', { name: 'Candidate simulation' })).toContainText('Simulation unavailable or inconclusive')
      await expect(page.getByRole('region', { name: 'Observed Hubble flows' })).toContainText('No Hubble flows observed')
    })
  }

  test('non-2xx errors remain text and do not trigger automatic retries', async ({ page }) => {
    let posts = 0
    await page.route('**/api/probes/tcp', (route) => { posts++; return route.fulfill({ status: 409, body: 'Pod UID changed; refresh Pods' }) })
    const form = await enabled(page)
    page.once('dialog', (dialog) => dialog.accept())
    await form.getByRole('button', { name: 'Review & run TCP probe' }).click()
    await expect(page.getByRole('alert')).toContainText('Pod UID changed; refresh Pods')
    await expect(page.getByRole('alert')).toContainText('may already have been added')
    expect(posts).toBe(1)
    await expect(form.getByRole('button', { name: 'Review & run TCP probe' })).toBeEnabled()
  })

  test('without a candidate the payload omits YAML and does not imply a simulation', async ({ page }) => {
    let request: TCPProbeRequest | undefined
    await page.route('**/api/probes/tcp', (route) => {
      request = route.request().postDataJSON()
      return route.fulfill({ json: response })
    })
    const form = await enabled(page)
    page.once('dialog', (dialog) => dialog.accept())
    await form.getByRole('button', { name: 'Review & run TCP probe' }).click()
    await expect(page.getByRole('region', { name: 'Candidate simulation' })).toContainText('No candidate supplied; simulation not requested')
    expect(request).not.toHaveProperty('candidateYAML')
  })

  test('editing candidate after success preserves submitted YAML and marks results stale', async ({ page }) => {
    const requests: TCPProbeRequest[] = []
    await page.route('**/api/probes/tcp', (route) => {
      requests.push(route.request().postDataJSON())
      return route.fulfill({ json: { ...response, simulation: VERDICT } })
    })
    const form = await enabled(page)
    await form.getByLabel('Candidate YAML').fill(LOOKS_CORRECT_CNP)
    page.once('dialog', (dialog) => dialog.accept())
    await form.getByRole('button', { name: 'Review & run TCP probe' }).click()
    const submitted = page.getByRole('region', { name: 'Submitted probe attempt' })
    await expect(submitted).toContainText('UID uid-original')
    await submitted.locator('summary').click()
    await expect(submitted.locator('pre')).toHaveText(LOOKS_CORRECT_CNP)

    const editedCandidate = LOOKS_CORRECT_CNP.replace('kind: CiliumNetworkPolicy', 'kind: CiliumClusterwideNetworkPolicy')
    await form.getByLabel('Candidate YAML').fill(editedCandidate)
    await expect(submitted.getByRole('status')).toContainText('not the edited form')
    await expect(submitted.locator('pre')).toHaveText(LOOKS_CORRECT_CNP)
    await expect(page.getByRole('region', { name: 'Candidate simulation' })).toContainText('never subsequent textarea edits')
    expect(requests).toHaveLength(1)
    expect(requests[0].candidateYAML).toBe(LOOKS_CORRECT_CNP)
    await form.getByLabel('Candidate YAML').fill(LOOKS_CORRECT_CNP)
    await expect(submitted.getByRole('status')).toHaveCount(0)
  })

  test('changing Pod after uncertain failed mutation preserves the original Pod and target warning', async ({ page }) => {
    let posts = 0
    await page.route('**/api/probes/tcp', (route) => {
      posts++
      return route.fulfill({ status: 504, body: 'Timed out waiting for ephemeral container status' })
    })
    const form = await enabled(page)
    page.once('dialog', (dialog) => dialog.accept())
    await form.getByRole('button', { name: 'Review & run TCP probe' }).click()
    const alert = page.getByRole('alert')
    await expect(alert).toContainText('may already have been added')
    await page.route('**/api/probes/pods?*', (route) => route.fulfill({ json: { pods: [{ name: 'replacement-pod', uid: 'uid-replacement' }] } }))
    await form.getByLabel('Probe namespace').fill('other')
    await form.getByLabel('Running Pod').selectOption('uid-replacement')
    await form.getByLabel('Host or IP').fill('other-db.other.svc')
    await form.getByLabel('TCP port').fill('443')

    const submitted = page.getByRole('region', { name: 'Submitted probe attempt' })
    await expect(submitted).toContainText('Original Pod: webapp/webapp-123 · UID uid-original')
    await expect(submitted).toContainText('Original TCP target: postgres.postgres.svc:5432')
    await expect(submitted.getByRole('status')).toContainText('not the edited form')
    await expect(alert).toContainText('original Pod webapp/webapp-123 (UID uid-original)')
    await expect(alert).toContainText('Inspect that Pod')
    await expect(alert).not.toContainText('uid-replacement')
    expect(posts).toBe(1)
  })

  test('empty simulation and skipped baseline policies retain uncertainty', async ({ page }) => {
    await page.route('**/api/probes/tcp', (route) => route.fulfill({ json: {
      ...response, simulation: { ...VERDICT, rows: [], skippedPolicies: ['CNP:webapp/node-selectors'] },
    } }))
    const form = await enabled(page)
    await form.getByLabel('Candidate YAML').fill(LOOKS_CORRECT_CNP)
    page.once('dialog', (dialog) => dialog.accept())
    await form.getByRole('button', { name: 'Review & run TCP probe' }).click()
    const simulation = page.getByRole('region', { name: 'Candidate simulation' })
    await expect(simulation).toContainText('candidate impact is inconclusive')
    await expect(simulation).toContainText('Simulation does not account for it')
  })

  test('double submission and switching tabs cannot duplicate a pending mutation', async ({ page }) => {
    let posts = 0
    let release!: () => void
    const pending = new Promise<void>((resolve) => { release = resolve })
    await page.route('**/api/probes/tcp', async (route) => { posts++; await pending; await route.fulfill({ json: response }) })
    const form = await enabled(page)
    let confirmations = 0
    page.on('dialog', (dialog) => { confirmations++; return dialog.accept() })
    await form.evaluate((element) => {
      element.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
      element.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))
    })
    await expect.poll(() => posts).toBe(1)
    await expect(form.getByRole('button', { name: 'Running TCP probe…', exact: true })).toBeDisabled()
    await expect(form.getByLabel('Host or IP')).toBeDisabled()
    await page.getByRole('button', { name: 'Flows', exact: true }).click()
    await page.getByRole('button', { name: 'TCP Probe', exact: true }).click()
    release()
    await expect(page.getByRole('region', { name: 'TCP transport result' })).toContainText('connected')
    expect(posts).toBe(1)
    expect(confirmations).toBe(1)
  })

  test('input constraints disallow arbitrary commands and out-of-range ports', async ({ page }) => {
    const form = await enabled(page)
    const run = form.getByRole('button', { name: 'Review & run TCP probe' })
    for (const host of ['https://db', 'db;id', 'db:5432', '999.1.1.1']) {
      await form.getByLabel('Host or IP').fill(host)
      await expect(run).toBeDisabled()
    }
    await form.getByLabel('Host or IP').fill('::1')
    for (const port of ['0', '65536', '1e3']) {
      await form.getByLabel('TCP port').fill(port)
      await expect(run).toBeDisabled()
    }
    await form.getByLabel('TCP port').fill('443')
    await expect(run).toBeEnabled()
  })

  test('namespace changes ignore stale Pod inventories and require a fresh selection', async ({ page }) => {
    const form = await enabled(page)
    let release!: () => void
    const pending = new Promise<void>((resolve) => { release = resolve })
    await page.route('**/api/probes/pods?*', async (route) => {
      const namespace = new URL(route.request().url()).searchParams.get('namespace')
      if (namespace === 'slow') await pending
      await route.fulfill({ json: { pods: [{ name: `${namespace}-pod`, uid: `${namespace}-uid` }] } })
    })
    const slow = page.waitForRequest('**/api/probes/pods?namespace=slow')
    await form.getByLabel('Probe namespace').fill('slow')
    await slow
    await form.getByLabel('Probe namespace').fill('fast')
    await form.getByLabel('Running Pod').selectOption('fast-uid')
    release()
    await expect(form.getByLabel('Running Pod')).toHaveValue('fast-uid')
    await expect(form.getByLabel('Running Pod').locator('option')).toHaveText(['Select an existing Pod', 'fast-pod'])
  })

  test('Pod listing failure blocks execution and can be refreshed', async ({ page }) => {
    const form = await enabled(page)
    await page.route('**/api/probes/pods?*', (route) => route.fulfill({ status: 403, body: 'Pods permission denied' }))
    await form.getByRole('button', { name: 'Refresh running Pods' }).click()
    await expect(page.getByRole('alert')).toContainText('Pods permission denied')
    await expect(form.getByRole('button', { name: 'Review & run TCP probe' })).toBeDisabled()
  })

  test('probe panel fits a phone without horizontal page overflow', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 })
    await enabled(page)
    const dimensions = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, width: window.innerWidth }))
    expect(dimensions.scroll).toBeLessThanOrEqual(dimensions.width)
  })
})
