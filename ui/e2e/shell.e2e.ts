// The app shell around the tabs: header, Policies tab, global modals,
// theme, and the graph size limits shared by Flows and Verdict.

import { FLOWS } from './fixtures/lab'
import { expect, openTab, test, visibleForm } from './fixtures/test'

test('header shows the binary and pinned engine versions', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByText(/^dev-[0-9a-f]+(-dirty)? · cilium engine \d+\.\d+\.\d+$/)).toBeVisible()
})

test('responses carry anti-framing headers and same-origin /api calls are served', async ({ page }) => {
  const doc = await page.goto('/')
  expect(doc!.headers()).toMatchObject({
    'x-frame-options': 'DENY',
    'content-security-policy': "frame-ancestors 'none'",
    'x-content-type-options': 'nosniff',
  })
  const api = await page.evaluate(async () => {
    const r = await fetch('/api/compat')
    return { status: r.status, frame: r.headers.get('x-frame-options') }
  })
  expect(api).toEqual({ status: 200, frame: 'DENY' })
})

test('a request from another site is refused', async ({ page, baseURL }) => {
  // localhost and 127.0.0.1 are different sites, so this fetch is cross-site,
  // like an <img> or no-cors fetch from a hostile page. Its response is
  // opaque to the page; Playwright still sees the real status.
  await page.goto(baseURL!.replace('127.0.0.1', 'localhost'))
  const target = `${baseURL}/api/compat`
  const res = page.waitForResponse(target)
  await page.evaluate((u) => fetch(u, { mode: 'no-cors' }).catch(() => {}), target)
  expect((await res).status()).toBe(403)
})

test('Compatibility modal lists the version gates from the real backend', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: 'Version compatibility' }).click()
  await expect(page.getByRole('dialog').getByText('fromRequires/toRequires').first()).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)
})

test('theme toggle switches and survives a reload', async ({ page }) => {
  await page.goto('/')
  const toggle = page.getByRole('button', { name: /Switch to (light|dark) theme/ })
  const before = await toggle.getAttribute('aria-label')
  await toggle.click()
  await expect(toggle).not.toHaveAttribute('aria-label', before!)
  const after = await toggle.getAttribute('aria-label')
  await page.reload()
  await expect(page.getByRole('button', { name: /Switch to (light|dark) theme/ })).toHaveAttribute('aria-label', after!)
})

test.describe('Policies tab', () => {
  test('lists live policies and loads one into the Policy Editor', async ({ page }) => {
    await openTab(page, 'Policies')
    await page.getByRole('button', { name: 'List policies' }).click()
    await expect(page.getByText('postgres-allow-webapp')).toBeVisible()
    await expect(page.getByText('lockdown')).toBeVisible()
    await page.getByRole('button', { name: '✎ Edit in Policy Editor' }).first().click()
    await expect(page.getByRole('button', { name: 'Policy Editor', exact: true })).toHaveClass(/bg-signal/)
    await expect(page.locator('pre:visible').first()).toContainText('name: postgres-allow-webapp')
  })
})

test.describe('Graph size limits', () => {
  test('a large sample is not drawn until asked, and the table still lists it all', async ({ page }) => {
    const many = Array.from({ length: 400 }, (_, i) => ({ ...FLOWS[0], source: `webapp/w-${i}`, destination: `postgres/p-${i % 150}` }))
    await page.route('**/api/flows?*', (r) => r.fulfill({ json: { namespace: 'webapp', flows: many } }))
    await openTab(page, 'Flows')
    await page.getByRole('button', { name: 'Fetch flows' }).click()
    await expect(page.getByText(/^Graph not drawn:/)).toBeVisible()
    await expect(page.locator('.react-flow__node:visible')).toHaveCount(0)
    await expect(page.locator('table:visible tbody tr')).toHaveCount(400)
    await page.getByRole('button', { name: 'Draw anyway' }).click()
    await expect(page.locator('.react-flow__node:visible')).not.toHaveCount(0)
  })

  test('only the newest stacked runs draw their graph', async ({ page }) => {
    await openTab(page, 'Flows')
    await page.locator('label:visible', { hasText: 'Stack runs' }).click()
    for (let i = 0; i < 5; i++) {
      await page.getByRole('button', { name: 'Fetch flows' }).click()
      await expect(page.getByText(`Run #${i + 1}`)).toBeVisible()
    }
    await expect(page.getByText(/^Graph paused/)).toHaveCount(2)
    await page.getByRole('button', { name: 'Show graph' }).first().click()
    await expect(page.getByText(/^Graph paused/)).toHaveCount(1)
  })
})

test.describe('Layout', () => {
  for (const colorScheme of ['light', 'dark'] as const) {
    for (const width of [390, 1440, 2000]) {
      test(`no sideways scroll at ${width}px (${colorScheme})`, async ({ browser }) => {
        const page = await browser.newPage({ viewport: { width, height: 900 }, colorScheme })
        await page.goto('/')
        for (const tab of ['Verdict', 'Flows', 'Policies', 'Policy Editor']) {
          await page.getByRole('button', { name: tab, exact: true }).click()
          const form = visibleForm(page)
          if (await form.locator('summary', { hasText: 'Filters' }).count()) {
            await form.locator('summary', { hasText: 'Filters' }).click() // the widest state
          }
          const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
          expect(overflow, `${tab} overflows by ${overflow}px`).toBe(0)
        }
        await page.close()
      })
    }
  }
})
