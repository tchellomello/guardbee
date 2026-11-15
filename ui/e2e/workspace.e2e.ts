import type { Page } from '@playwright/test'
import { LOOKS_CORRECT_CNP } from './fixtures/lab'
import { expect, test, visibleForm } from './fixtures/test'

const KEY = 'guardbee.workspace.policies'

// Seeds the browser's workspace before the app loads, as if saved earlier.
async function seed(page: Page, entries: object[]) {
  await page.addInitScript(
    ([key, value]) => {
      if (!localStorage.getItem(key)) localStorage.setItem(key, value)
    },
    [KEY, JSON.stringify(entries)] as const
  )
}

const entry = (name: string) => ({
  id: name,
  name,
  savedAt: '2026-11-15T10:00:00.000Z',
  origin: 'verdict',
  candidateYAML: LOOKS_CORRECT_CNP.replace('postgres-allow-webapp', name),
  namespace: 'postgres',
  allNamespaces: false,
})

const stored = (page: Page) => page.evaluate((k) => JSON.parse(localStorage.getItem(k) || '[]'), KEY)

// One saved entry's row: the nearest element holding both its name and
// its action buttons.
const rowOf = (page: Page, name: string) =>
  page
    .getByRole('dialog', { name: 'Saved policies' })
    .getByText(name, { exact: true })
    .locator('xpath=ancestor::*[.//button[normalize-space()="Rename"]][1]')

async function openWorkspace(page: Page) {
  await page.goto('/')
  await page.getByRole('button', { name: /^Saved policies/ }).click()
  return page.getByRole('dialog', { name: 'Saved policies' })
}

test.describe('Saved policies', () => {
  test('lists saved entries and opens one in Verdict', async ({ page }) => {
    await seed(page, [entry('allow-webapp'), entry('lockdown')])
    const dialog = await openWorkspace(page)
    await expect(dialog.getByText('allow-webapp')).toBeVisible()
    await expect(dialog.getByText('lockdown')).toBeVisible()

    await rowOf(page, 'lockdown').getByRole('button', { name: 'Open in Verdict' }).click()
    await expect(page.getByRole('dialog')).toHaveCount(0)
    await expect(visibleForm(page).locator('textarea')).toHaveValue(/name: lockdown/)
  })

  test('filters, renames, duplicates and deletes', async ({ page }) => {
    // The filter box only appears past 3 entries.
    await seed(page, [entry('allow-webapp'), entry('lockdown'), entry('db-egress'), entry('dns')])
    const dialog = await openWorkspace(page)

    await dialog.getByRole('textbox', { name: 'Filter saved policies' }).fill('lock')
    await expect(dialog.getByText('allow-webapp')).toHaveCount(0)
    await dialog.getByRole('textbox', { name: 'Filter saved policies' }).fill('')

    const row = (name: string) => rowOf(page, name)
    await row('allow-webapp').getByRole('button', { name: 'Rename' }).click()
    const newName = dialog.getByRole('textbox', { name: 'New name' })
    await newName.fill('allow-webapp-v2')
    await newName.press('Enter')
    await expect(row('allow-webapp-v2')).toBeVisible()

    await row('lockdown').getByRole('button', { name: 'Duplicate' }).click()
    await expect.poll(async () => (await stored(page)).length).toBe(5)

    await row('allow-webapp-v2').getByRole('button', { name: 'Delete' }).click()
    // The row turns into a confirmation (its Rename button is gone).
    await dialog
      .getByText('Delete "allow-webapp-v2"?', { exact: false })
      .locator('xpath=ancestor::*[.//button[normalize-space()="Cancel"]][1]')
      .getByRole('button', { name: 'Delete', exact: true })
      .click()
    await expect.poll(async () => (await stored(page)).map((e: { name: string }) => e.name).sort()).not.toContain(
      'allow-webapp-v2'
    )
  })

  test('downloads an entry as YAML', async ({ page }) => {
    await seed(page, [entry('allow-webapp')])
    const dialog = await openWorkspace(page)
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      dialog.getByRole('button', { name: 'Download .yaml' }).click(),
    ])
    expect(download.suggestedFilename()).toBe('allow-webapp.yaml')
  })
})
