import type { Page } from '@playwright/test'
import { LOOKS_CORRECT_CNP } from './fixtures/lab'
import { expect, openTab, test, visibleForm } from './fixtures/test'

// DESIGN.md's rules, checked on the rendered tabs rather than in source:
// controls carry words, not emoji, and red stays reserved for verdicts.

// Pictographic emoji (📦 🚀 🎯 ⛔ 💾 ⏱ 🔒 🌐 🖥 …). Text symbols the console
// uses on purpose (✓ ✕ ✎ ⚠ ⎈ ⤢ ▾) are outside this set.
const EMOJI = /\p{Extended_Pictographic}/u
const TEXT_SYMBOLS = new Set(['✓', '✕', '✎', '⚠', '⎈', '⤢', '▾', '↺', 'ⓘ'])

async function emojiInVisibleControls(page: Page): Promise<string[]> {
  const texts = await page.locator('button:visible, [role="button"]:visible, .react-flow__node:visible').allInnerTexts()
  return texts.filter((t) => [...t].some((ch) => EMOJI.test(ch) && !TEXT_SYMBOLS.has(ch)))
}

test('no tab uses emoji in its controls', async ({ page }) => {
  await openTab(page, 'Verdict')
  const form = visibleForm(page)
  await form.locator('input').first().fill('postgres')
  await form.locator('textarea').fill(LOOKS_CORRECT_CNP)
  await page.getByRole('button', { name: 'Run verdict' }).click()
  await expect(page.getByText('17 real flow(s) would BREAK')).toBeVisible()
  expect(await emojiInVisibleControls(page)).toEqual([])

  await openTab(page, 'Flows')
  await visibleForm(page).locator('input').first().fill('postgres')
  await page.getByRole('button', { name: 'Fetch flows' }).click()
  await expect(page.locator('.react-flow__node:visible').first()).toBeVisible()
  expect(await emojiInVisibleControls(page)).toEqual([])

  await openTab(page, 'Policies')
  await page.getByRole('button', { name: 'List policies' }).click()
  await expect(page.getByText('lockdown')).toBeVisible()
  expect(await emojiInVisibleControls(page)).toEqual([])

  await openTab(page, 'Policy Editor')
  await page.getByRole('button', { name: '⤢ Expand / Edit' }).first().click()
  await page.getByRole('dialog').locator('textarea').fill(LOOKS_CORRECT_CNP)
  await page.keyboard.press('Escape')
  await expect(page.getByText(/Valid CiliumNetworkPolicy spec/)).toBeVisible()
  expect(await emojiInVisibleControls(page)).toEqual([])
})

test('the per-row block action on Flows is not drawn in the verdict red', async ({ page }) => {
  await openTab(page, 'Flows')
  await visibleForm(page).locator('input').first().fill('postgres')
  await page.getByRole('button', { name: 'Fetch flows' }).click()
  const action = page.getByRole('button', { name: /New block policy/i }).first()
  await expect(action).toBeVisible()
  const [color, drop, signal] = await action.evaluate((el) => {
    const probe = (v: string) => {
      const s = document.createElement('span')
      s.style.color = `var(${v})`
      document.body.append(s)
      const c = getComputedStyle(s).color
      s.remove()
      return c
    }
    return [getComputedStyle(el).color, probe('--color-drop'), probe('--color-signal')]
  })
  expect(color).not.toBe(drop)
  expect(color).toBe(signal)
})
