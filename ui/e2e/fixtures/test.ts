// The e2e `test`: Playwright's own, plus a `cluster` fixture that mocks
// every endpoint needing a real cluster before the page loads, and records
// what the UI sent. Endpoints that don't need one (policy parse/validate,
// templates, compat, flow-filter options, version --client) are left to the
// real binary, so the UI is tested against the real engine wherever it can
// be.

import { test as base, expect, type Page, type Request } from '@playwright/test'
import { answerFlows, LOOKS_CORRECT_CNP, NAMESPACES, POLICIES, VERDICT } from './lab'

export interface Cluster {
  // Every request the UI made to a mocked endpoint, in order.
  requests: Request[]
  // Query strings of /api/flows and /api/flows/stream requests.
  flowQueries(): URLSearchParams[]
  streamQueries(): URLSearchParams[]
  // Keep /api/flows/stream open with no data (a quiet live stream) instead
  // of answering with the Lab flows.
  holdStreams(): void
}

export const test = base.extend<{ cluster: Cluster }>({
  cluster: [
    async ({ page }, use) => {
      const requests: Request[] = []
      let hold = false
      const record = (r: Request) => requests.push(r)

      await page.route('**/api/namespaces', (r) => {
        record(r.request())
        return r.fulfill({ json: { namespaces: NAMESPACES } })
      })
      await page.route('**/api/probes/capabilities', (r) => r.fulfill({ json: { enabled: false } }))
      await page.route('**/api/pods?*', (r) => {
        record(r.request())
        const ns = new URL(r.request().url()).searchParams.get('namespace') ?? ''
        return r.fulfill({ json: { namespace: ns, pods: [] } })
      })
      await page.route('**/api/flows?*', (r) => {
        record(r.request())
        const ns = new URL(r.request().url()).searchParams.get('namespace') ?? ''
        return r.fulfill({ json: { namespace: ns, flows: answerFlows(r.request().url()) } })
      })
      await page.route('**/api/flows/stream?*', (r) => {
        record(r.request())
        if (hold) return // never answered: the EventSource stays open
        const body = answerFlows(r.request().url())
          .map((f) => `data: ${JSON.stringify(f)}\n\n`)
          .join('')
        return r.fulfill({ status: 200, headers: { 'content-type': 'text/event-stream' }, body })
      })
      await page.route('**/api/verdict', (r) => {
        record(r.request())
        return r.fulfill({ json: VERDICT })
      })
      await page.route('**/api/verdict/stream?*', (r) => {
        record(r.request()) // held open, like a quiet live verdict
      })
      await page.route('**/api/policies?*', (r) => {
        record(r.request())
        return r.fulfill({ json: { namespace: '', policies: POLICIES } })
      })
      // The edit model comes from the real parser, not a hand-written copy
      // of its shape that could drift from it.
      await page.route('**/api/policies/edit?*', async (r) => {
        record(r.request())
        const res = await page.request.post('/api/policy/parse', {
          data: { namespace: 'postgres', candidateYAML: LOOKS_CORRECT_CNP },
        })
        const parsed = await res.json()
        return r.fulfill({ json: parsed.policy })
      })
      await page.route('**/api/policy/workloads', (r) => {
        record(r.request())
        return r.fulfill({
          json: {
            valid: true,
            workloads: [
              { namespace: 'postgres', name: 'postgres-0', serviceAccount: 'default', selected: true, ingress: true, egress: false },
              { namespace: 'postgres', name: 'pgbouncer-6d4f9', serviceAccount: 'default', selected: false, ingress: false, egress: false },
            ],
          },
        })
      })

      const queries = (path: string) =>
        requests.filter((r) => new URL(r.url()).pathname === path).map((r) => new URL(r.url()).searchParams)
      await use({
        requests,
        flowQueries: () => queries('/api/flows'),
        streamQueries: () => queries('/api/flows/stream'),
        holdStreams: () => {
          hold = true
        },
      })
    },
    { auto: true },
  ],
})

export { expect }

// Tabs stay mounted (CSS-hidden) when not shown, so every locator in a tab
// must be scoped to what's visible.
export async function openTab(page: Page, name: 'Verdict' | 'Flows' | 'Policies' | 'Policy Editor' | 'TCP Probe') {
  await page.goto('/')
  await page.getByRole('button', { name, exact: true }).click()
}

export const visibleForm = (page: Page) => page.locator('form:visible').first()

// Types like a person: per-key delay plus a pause longer than the UI's
// 150ms parse debounce, which instant fill() would never exercise.
export async function typeSlowly(page: Page, text: string) {
  for (const chunk of text.split(/(?<=\n)/)) {
    await page.keyboard.type(chunk, { delay: 25 })
    await page.waitForTimeout(220)
  }
}
