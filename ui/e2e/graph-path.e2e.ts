import { LOOKS_CORRECT_CNP } from './fixtures/lab'
import { expect, openTab, test, visibleForm } from './fixtures/test'

// The Verdict and Flows graphs share the connectivity test's path look
// (GraphPathParts.tsx): round endpoint nodes named by peer kind; blocked links
// stop at a ✕ gate; only links that changed — or touch the selected node —
// move.
// Scoped by the visible graph, not :visible on each edge: a perfectly
// horizontal link has a zero-height box, which Playwright calls hidden.
const moving = 'path.probe-flow'
const gates = (page: import('@playwright/test').Page) => page.locator('.react-flow__edgelabel-renderer div:visible', { hasText: '✕' })

test.describe('Flow graph path look', () => {
  test('Verdict: only changed links move, blocked ones stop at a gate, selection moves its own links', async ({ page }) => {
    await openTab(page, 'Verdict')
    const form = visibleForm(page)
    await form.locator('input').first().fill('postgres')
    await form.locator('textarea').fill(LOOKS_CORRECT_CNP)
    await page.getByRole('button', { name: 'Run verdict' }).click()
    await expect(page.locator('.react-flow__node:visible').first()).toBeVisible()

    // Fixture: two NEWLY_DROPPED links (prometheus, host → postgres) and one
    // UNCHANGED (webapp → postgres) that must stay still.
    await expect(page.locator(".react-flow:visible").locator(moving)).toHaveCount(2)
    await expect(gates(page)).toHaveCount(2)
    await expect(page.locator('.react-flow__node:visible', { hasText: 'HOST' })).toHaveCount(1)
    await expect(page.locator('.react-flow__node:visible', { hasText: 'POD' })).toHaveCount(3)

    await page.locator('.react-flow__node:visible', { hasText: 'webapp' }).click()
    await expect(page.getByText('Isolating flows for:')).toBeVisible()
    // Now only the selected node's (unchanged) link moves; the rest is dimmed.
    await expect(page.locator(".react-flow:visible").locator(moving)).toHaveCount(1)
  })

  test('Flows: nothing moves until a node is selected; drops stop at a gate', async ({ page }) => {
    await openTab(page, 'Flows')
    await visibleForm(page).locator('input').first().fill('webapp')
    await page.getByRole('button', { name: 'Fetch flows' }).click()
    await expect(page.locator('.react-flow__node:visible').first()).toBeVisible()

    await expect(page.locator(".react-flow:visible").locator(moving)).toHaveCount(0)
    await expect(gates(page)).toHaveCount(1) // world → webapp, DROPPED on two ports
    await expect(page.locator('.react-flow__node:visible', { hasText: 'WORLD' })).toHaveCount(1)

    await page.locator('.react-flow__node:visible', { hasText: 'WORLD' }).click()
    await expect(page.locator(".react-flow:visible").locator(moving)).toHaveCount(1)
  })
})
