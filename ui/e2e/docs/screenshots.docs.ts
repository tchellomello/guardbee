// Documentation screenshots, regenerated from the mocked Lab scenario
// (e2e/fixtures/lab.ts) in the light theme. Each test writes one file under
// docs/images, named after the page that embeds it. Run with
// `mise run docs-screenshots` after a visible UI change, then review the
// images before committing them.

import type { Page } from '@playwright/test'
import type { ConnectionProbeResponse, VerdictResponse } from '../../src/api'
import { LOOKS_CORRECT_CNP, VERDICT } from '../fixtures/lab'
import { expect, openTab, test, visibleForm } from '../fixtures/test'

const out = (name: string) => `../docs/images/${name}.png`

// The light theme is the docs' theme, whatever the OS prefers.
test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    try { localStorage.clear() } catch { /* private mode */ }
  })
  await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'reduce' })
})

const MERGE_READY = `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: postgres-allow-webapp
  namespace: postgres
spec:
  endpointSelector:
    matchLabels:
      app: postgres
  ingress:
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: webapp
            app: webapp
      toPorts:
        - ports:
            - port: "5432"
              protocol: TCP
    - fromEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: observability
            app: prometheus
      toPorts:
        - ports:
            - port: "9187"
              protocol: TCP
    - fromEntities:
        - host
      toPorts:
        - ports:
            - port: "5432"
              protocol: TCP
`

const CLEAN: VerdictResponse = {
  ...VERDICT,
  // No skipped replies: the UI only calls a sample clean when every
  // sampled flow was judged unchanged.
  flowsSampled: 31,
  counts: { unchanged: 31, newlyDropped: 0, newlyAllowed: 0, notSimulated: 0, replySkipped: 0, total: 31 },
  rows: [],
}

async function runVerdict(page: Page, candidate: string) {
  await openTab(page, 'Verdict')
  const form = visibleForm(page)
  await form.locator('input').first().fill('postgres')
  await form.locator('textarea').fill(candidate)
  await page.getByRole('button', { name: 'Run verdict' }).click()
}

// Scroll so the newest run card starts at the top of the viewport, the way
// the Lab's screenshots frame a result.
async function frameRun(page: Page) {
  const run = page.getByText(/^Run #1$/i).first()
  await run.scrollIntoViewIfNeeded()
  await run.evaluate((el) => window.scrollBy(0, el.getBoundingClientRect().top - 24))
}

async function fetchFlows(page: Page, namespace: string) {
  await openTab(page, 'Flows')
  await visibleForm(page).locator('input').first().fill(namespace)
  await page.getByRole('button', { name: 'Fetch flows' }).click()
  await expect(page.locator('.react-flow__node:visible').first()).toBeVisible()
}

test('lab-01-flows', async ({ page }) => {
  await fetchFlows(page, 'postgres')
  await page.locator('section, div').filter({ hasText: /^Flow graph$/i }).last().scrollIntoViewIfNeeded()
  await frameRun(page)
  await page.screenshot({ path: out('lab-01-flows') })
})

test('lab-02-policy-editor', async ({ page }) => {
  await openTab(page, 'Policy Editor')
  await page.getByRole('button', { name: '⤢ Expand / Edit' }).first().click()
  await page.getByRole('dialog').locator('textarea').fill(LOOKS_CORRECT_CNP)
  await page.keyboard.press('Escape')
  // Wait for the engine's parse, then frame the top of the editor unfocused.
  await expect(page.getByText(/Valid CiliumNetworkPolicy spec/)).toBeVisible()
  await expect(page.locator('.react-flow__node:visible', { hasText: 'Ingress Source #1' })).toBeVisible()
  await page.evaluate(() => { (document.activeElement as HTMLElement | null)?.blur(); window.scrollTo(0, 0) })
  await page.screenshot({ path: out('lab-02-policy-editor') })
})

test('lab-03-cluster-picker', async ({ page }) => {
  await page.route('**/api/pods?*', (r) => r.fulfill({ json: { namespace: 'postgres', pods: [{ name: 'postgres-0', labels: { app: 'postgres' } }] } }))
  await openTab(page, 'Policy Editor')
  await page.getByRole('button', { name: '⤢ Expand / Edit' }).first().click()
  await page.getByRole('dialog').locator('textarea').fill(LOOKS_CORRECT_CNP)
  await page.keyboard.press('Escape')
  await page.locator('.react-flow__node:visible', { hasText: 'Target Workload' }).click()
  await page.getByRole('button', { name: /Pick From Cluster/ }).click()
  await expect(page.getByText('app=postgres').first()).toBeVisible()
  await page.screenshot({ path: out('lab-03-cluster-picker') })
})

test('lab-04-verdict-regression', async ({ page }) => {
  await runVerdict(page, LOOKS_CORRECT_CNP)
  await expect(page.getByText('17 real flow(s) would BREAK')).toBeVisible()
  await frameRun(page)
  await page.screenshot({ path: out('lab-04-verdict-regression') })
})

test('lab-05-add-to-policy', async ({ page }) => {
  await page.route('**/api/pods?*', (r) => {
    const ns = new URL(r.request().url()).searchParams.get('namespace') ?? ''
    const pods = ns === 'observability' ? [{ name: 'prometheus-5c8d7f9b6-q8w2e', labels: { app: 'prometheus' } }] : []
    return r.fulfill({ json: { namespace: ns, pods } })
  })
  await openTab(page, 'Policy Editor')
  await page.getByRole('button', { name: '⤢ Expand / Edit' }).first().click()
  await page.getByRole('dialog').locator('textarea').fill(LOOKS_CORRECT_CNP)
  await page.keyboard.press('Escape')
  await page.getByRole('button', { name: /Test in Verdict Simulator/ }).click()
  await page.getByRole('button', { name: 'Run verdict' }).click()
  const row = page.locator('table:visible tbody tr', { hasText: 'TCP:9187' })
  await row.getByRole('button', { name: '+ Add to Policy' }).click()
  await expect(page.getByRole('button', { name: 'Policy Editor', exact: true })).toHaveClass(/bg-signal/)
  // Add to Policy opens the new rule's editor straight away.
  await expect(page.getByText(/Editing: Ingress Source/i)).toBeVisible()
  await page.screenshot({ path: out('lab-05-add-to-policy'), animations: 'disabled', timeout: 10_000 })
})

test('lab-06-verdict-clean', async ({ page }) => {
  await page.route('**/api/verdict', (r) => r.fulfill({ json: CLEAN }))
  await runVerdict(page, MERGE_READY)
  await expect(page.getByText(/No regressions/i)).toBeVisible()
  await frameRun(page)
  await page.screenshot({ path: out('lab-06-verdict-clean') })
})

test('ui-flows-filters', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1400 })
  await openTab(page, 'Flows')
  const form = visibleForm(page)
  await form.locator('input').first().fill('webapp')
  await form.getByText(/Filters/).first().click()
  for (const quick of ['Dropped', 'Policy drops', 'From the internet']) await form.getByRole('button', { name: quick, exact: true }).click()
  await page.getByRole('button', { name: 'Fetch flows' }).click()
  await expect(page.locator('.react-flow__node:visible').first()).toBeVisible()
  await page.evaluate(() => window.scrollTo(0, 0))
  await page.screenshot({ path: out('ui-flows-filters') })
})

test('ui-flows-autocomplete', async ({ page }) => {
  await fetchFlows(page, 'postgres')
  await page.evaluate(() => window.scrollTo(0, 0))
  const form = visibleForm(page)
  await form.locator('input').first().fill('')
  await form.getByText(/Filters/).first().click()
  const from = form.getByPlaceholder('reserved:world').first()
  await from.click()
  await from.pressSequentially('app', { delay: 60 })
  await expect(page.getByRole('option', { name: /k8s:app=prometheus/ })).toBeVisible()
  await form.screenshot({ path: out('ui-flows-autocomplete') })
})

test('ui-blame-decided-by', async ({ page }) => {
  await page.setViewportSize({ width: 1600, height: 900 })
  await fetchFlows(page, 'postgres')
  const table = page.locator('table:visible').first()
  await table.scrollIntoViewIfNeeded()
  await table.screenshot({ path: out('ui-blame-decided-by') })
})

test('ui-blame-default-deny', async ({ page }) => {
  await page.setViewportSize({ width: 1600, height: 900 })
  await fetchFlows(page, 'webapp')
  const table = page.locator('table:visible').first()
  await table.scrollIntoViewIfNeeded()
  await table.screenshot({ path: out('ui-blame-default-deny') })
})

test('ui-verdict-layout', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1400 })
  await runVerdict(page, LOOKS_CORRECT_CNP)
  await expect(page.getByText('17 real flow(s) would BREAK')).toBeVisible()
  await expect(page.locator('.react-flow__node:visible').first()).toBeVisible()
  await page.evaluate(() => window.scrollTo(0, 0))
  await page.screenshot({ path: out('ui-verdict-layout') })
})

test('ui-mobile-filters', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await openTab(page, 'Flows')
  const form = visibleForm(page)
  await form.getByText(/Filters/).first().click()
  await form.getByRole('button', { name: 'Dropped', exact: true }).click()
  // Off the pill, and past its colour transition, so it shows as active.
  await page.mouse.move(0, 0)
  await expect(form.getByRole('button', { name: 'Dropped', exact: true })).toHaveAttribute('aria-pressed', 'true')
  await page.evaluate(() => window.scrollTo(0, 0))
  await page.screenshot({ path: out('ui-mobile-filters'), animations: 'disabled' })
})

// New: the connectivity test result, prometheus → postgres:9187 with the
// built-in BusyBox image, as the Lab's Step 5 walks through.
test('ui-connectivity-test', async ({ page }) => {
  const images = [
    { id: 'netshoot', name: 'netshoot', image: 'docker.io/nicolaka/netshoot@sha256:b09d9b21381f47a79b3cbcb30da25266dc17186ea00ae65e99fdc51396f48e70', protocols: ['TCP', 'UDP'], description: 'Network troubleshooting toolbox (nc, Python 3, dig, curl). Larger pull, supports TCP and UDP.', pinned: true },
    { id: 'busybox', name: 'BusyBox 1.37', image: 'docker.io/library/busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec', protocols: ['TCP'], description: 'Official minimal image (~2 MB) with nc and timeout. TCP only, no Python for UDP.', pinned: true },
  ]
  const flowRow = { time: '2026-11-21T17:51:07Z', verdict: 'FORWARDED', direction: 'EGRESS', source: 'observability/prometheus-5c8d7f9b6-q8w2e', destination: 'postgres/postgres-0', l4: 'TCP:9187' }
  const result: ConnectionProbeResponse = {
    namespace: 'observability', pod: 'prometheus-5c8d7f9b6-q8w2e', host: 'postgres.postgres.svc.cluster.local', port: 9187, protocol: 'TCP',
    outcome: 'connected', message: 'TCP connection established by nc (not an application health check)',
    containerName: 'guardbee-connection-31b7c266129c5883', image: images[1].image, imageId: 'busybox',
    context: 'kind-guardbee-lab', apiServer: 'https://127.0.0.1:6443', startedAt: '2026-11-21T17:51:05Z', durationMs: 3944,
    flows: [{ ...flowRow, count: 8 }, { ...flowRow, count: 1 }],
    simulation: { ...VERDICT, namespace: 'observability', flowsSampled: 9, counts: { unchanged: 0, newlyDropped: 9, newlyAllowed: 0, notSimulated: 0, replySkipped: 0, total: 9 }, rows: [{ ...VERDICT.rows[0], count: 9, baselineAllowed: true, candidateAllowed: false }] },
    warnings: [],
    notes: [
      { code: 'service-match', text: 'Hostname matched Service postgres/postgres: flows to its ClusterIPs or its 1 current backend addresses on the mapped target port count as evidence.' },
      { code: 'ephemeral-entry', text: 'The terminated ephemeral-container entry cannot be removed or restarted and remains until the Pod is replaced.' },
      { code: 'runtime-bound', text: "The image's timeout bounds command runtime to 8 seconds." },
      { code: 'best-effort-correlation', text: 'Hubble correlation is best-effort.' },
      { code: 'replace-mode', text: 'Candidate simulation replaces live policies with the same kind/namespace/name.' },
    ],
  }
  const stages = ['authorize', 'capture', 'inject', 'run', 'collect', 'simulate'].map((stage) => JSON.stringify({ stage }))
  await page.route('**/api/probes/capabilities', (r) => r.fulfill({ json: { enabled: true, protocols: ['TCP', 'UDP'], context: 'kind-guardbee-lab', image: images[0].image, images } }))
  await page.route('**/api/probes/pods?*', (r) => r.fulfill({ json: { pods: [{ name: 'prometheus-5c8d7f9b6-q8w2e', uid: 'uid-prom' }] } }))
  await page.route('**/api/probes/connection/stream', (r) => r.fulfill({ contentType: 'application/x-ndjson', body: [...stages, JSON.stringify({ result })].join('\n') + '\n' }))

  await page.setViewportSize({ width: 1440, height: 900 })
  await openTab(page, 'Verdict')
  const main = visibleForm(page)
  await main.locator('input').first().fill('observability')
  await main.locator('textarea').fill(LOOKS_CORRECT_CNP)
  const panel = page.getByRole('region', { name: 'Connectivity tests', exact: true })
  await panel.getByRole('button', { name: /Connectivity tests/ }).click()
  const form = page.getByRole('form', { name: 'Connection test configuration' })
  await form.getByRole('radio', { name: /BusyBox/ }).check()
  await form.getByLabel('Source Pod').selectOption('uid-prom')
  await form.getByLabel('Host or IP').fill('postgres.postgres.svc.cluster.local')
  await form.getByLabel('Port', { exact: true }).fill('9187')
  page.once('dialog', (d) => d.accept())
  await form.getByRole('button', { name: 'Review & run connection test' }).click()
  await expect(page.getByRole('region', { name: 'Candidate prediction' }).getByRole('heading')).toHaveText('BLOCKED')
  await panel.screenshot({ path: out('ui-connectivity-test') })
})
