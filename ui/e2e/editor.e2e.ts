import type { Page } from '@playwright/test'
import { LOOKS_CORRECT_CNP } from './fixtures/lab'
import { expect, openTab, test, typeSlowly } from './fixtures/test'

// The live "Candidate Policy Output" YAML the editor generates.
const outputYAML = (page: Page) => page.locator('pre:visible').first().innerText()
const placeholder = (page: Page, text: string) => page.locator(`input[placeholder="${text}"]:visible`)

async function openYamlModal(page: Page) {
  await page.getByRole('button', { name: '⤢ Expand / Edit' }).first().click()
  return page.getByRole('dialog').locator('textarea')
}

async function openIngressRule(page: Page) {
  await page.locator('.react-flow__node', { hasText: 'Ingress Traffic' }).click()
  await page.getByRole('button', { name: '+ Add Ingress Rule' }).click()
  await expect(placeholder(page, '10.0.0.0/8, 192.168.1.0/24')).toBeVisible()
}

// Typing as a person would, one key at a time, with a pause after each
// separator — long enough for the 150ms parse debounce to fire mid-edit.
async function typeInto(page: Page, field: ReturnType<Page['locator']>, text: string) {
  await field.click()
  await field.press('Control+A')
  await field.press('Backspace')
  for (const ch of text) {
    await page.keyboard.type(ch)
    await page.waitForTimeout(ch === ',' || ch === ' ' ? 250 : 30)
  }
  await page.waitForTimeout(250)
}

test.describe('Policy Editor — YAML modal', () => {
  // Regression: the text was rewritten to the model's canonical YAML after
  // every 150ms pause, eating partial keys and comments and moving the caret.
  test('keeps hand-typed text, comments and caret position', async ({ page }) => {
    await openTab(page, 'Policy Editor')
    const ta = await openYamlModal(page)
    await expect(ta).toBeFocused()
    const before = await ta.inputValue()
    const at = before.indexOf('my-service') + 'my-service'.length
    await ta.evaluate((el: HTMLTextAreaElement, i) => el.setSelectionRange(i, i), at)
    await typeSlowly(page, '-v2')
    await expect(ta).toHaveValue(before.slice(0, at) + '-v2' + before.slice(at))
    expect(await ta.evaluate((el: HTMLTextAreaElement) => el.selectionStart)).toBe(at + 3)

    await page.keyboard.press('Control+End')
    await typeSlowly(page, '  # reviewed\n')
    await expect(ta).toHaveValue(/# reviewed/)
    // The valid edit still reached the editor.
    await page.keyboard.press('Escape')
    expect(await outputYAML(page)).toContain('my-service-v2')
  })

  test('an edit made just before closing is not lost', async ({ page }) => {
    await openTab(page, 'Policy Editor')
    const ta = await openYamlModal(page)
    const v = await ta.inputValue()
    await ta.fill(v.replace('name: custom-policy', 'name: closed-fast'))
    await page.keyboard.press('Escape') // well within the parse debounce
    await expect.poll(() => outputYAML(page)).toContain('name: closed-fast')
  })

  test('a paste the editor understands can be saved from the modal', async ({ page }) => {
    await openTab(page, 'Policy Editor')
    const ta = await openYamlModal(page)
    await ta.fill(LOOKS_CORRECT_CNP)
    const dialog = page.getByRole('dialog')
    await dialog.getByRole('button', { name: /Save/ }).click()
    await dialog.getByRole('textbox', { name: 'Name to save this policy as' }).press('Enter')
    const saved = await page.evaluate(() => JSON.parse(localStorage.getItem('guardbee.workspace.policies') || '[]'))
    expect(saved[0]).toMatchObject({ name: 'postgres-allow-webapp', origin: 'editor', candidateYAML: LOOKS_CORRECT_CNP })
  })

  // Regression: a valid policy the editor can't represent left the old
  // draft in place, and the editor's Save silently stored that instead.
  test('a policy the editor cannot represent is kept and saved verbatim', async ({ page }) => {
    const scopedDeny = `apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: block-one-ip
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: web
  egressDeny:
    - toCIDR:
        - 98.67.213.35/32
      toPorts:
        - ports:
            - port: "443"
              protocol: TCP
`
    await openTab(page, 'Policy Editor')
    const ta = await openYamlModal(page)
    await ta.fill(scopedDeny)
    const dialog = page.getByRole('dialog')
    await expect(dialog.getByText("the visual editor can't represent it faithfully")).toBeVisible()
    await expect(ta).toHaveValue(scopedDeny)
    await dialog.getByRole('button', { name: /Save/ }).click()
    await dialog.getByRole('textbox', { name: 'Name to save this policy as' }).press('Enter')
    const saved = await page.evaluate(() => JSON.parse(localStorage.getItem('guardbee.workspace.policies') || '[]'))
    expect(saved[0]).toMatchObject({ name: 'block-one-ip', origin: 'verdict', candidateYAML: scopedDeny })
  })

  test('a multi-document paste says so instead of dropping the rest', async ({ page }) => {
    await openTab(page, 'Policy Editor')
    const ta = await openYamlModal(page)
    await ta.fill(LOOKS_CORRECT_CNP + '---\n' + LOOKS_CORRECT_CNP.replace('postgres-allow-webapp', 'second'))
    await expect(page.getByRole('dialog').getByText('this paste holds 2 policies')).toBeVisible()
  })

  test('invalid YAML shows the parser error and keeps Save disabled', async ({ page }) => {
    await openTab(page, 'Policy Editor')
    const ta = await openYamlModal(page)
    await ta.fill('apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nspec: [\n')
    const dialog = page.getByRole('dialog')
    await expect(dialog.locator('.text-drop').first()).toBeVisible()
    await expect(dialog.getByRole('button', { name: /Save/ })).toBeDisabled()
  })
})

test.describe('Policy Editor — form inputs', () => {
  // Regression: the field was redrawn from the parsed list on every
  // keystroke, so ", " vanished as typed and a second CIDR couldn't start.
  test('a CIDR list can be typed', async ({ page }) => {
    await openTab(page, 'Policy Editor')
    await openIngressRule(page)
    const cidr = placeholder(page, '10.0.0.0/8, 192.168.1.0/24')
    await typeInto(page, cidr, '10.0.0.0/8, 192.168.1.0/24')
    await expect(cidr).toHaveValue('10.0.0.0/8, 192.168.1.0/24')
    const yaml = await outputYAML(page)
    expect(yaml).toContain('"10.0.0.0/8"')
    expect(yaml).toContain('"192.168.1.0/24"')
  })

  // Regression: rows were keyed by label name, so they merged, reordered
  // and lost values while a key was being typed.
  test('target labels survive keys that collide or start with digits', async ({ page }) => {
    await openTab(page, 'Policy Editor')
    await page.locator('.react-flow__node', { hasText: 'Target Workload' }).click()
    const keys = placeholder(page, 'label key')
    const values = placeholder(page, 'value')
    await expect(keys).toHaveCount(1) // app=my-service
    await page.getByRole('button', { name: '+ Add Label' }).click()
    await page.getByRole('button', { name: '+ Add Label' }).click()
    await expect(keys).toHaveCount(3)

    await typeInto(page, keys.nth(1), 'app.kubernetes.io/part-of') // passes through "app"
    await typeInto(page, values.nth(1), 'shop')
    await typeInto(page, keys.nth(2), '42x')
    await typeInto(page, values.nth(2), 'y')
    await expect(keys).toHaveCount(3)
    expect(await keys.evaluateAll((els) => els.map((e) => (e as HTMLInputElement).value))).toEqual([
      'app',
      'app.kubernetes.io/part-of',
      '42x',
    ])
    expect(await values.nth(0).inputValue()).toBe('my-service')
    const yaml = await outputYAML(page)
    expect(yaml).toContain('app.kubernetes.io/part-of: "shop"')
    expect(yaml).toContain('42x: "y"')
  })

  // Regression: an empty key stored {}, throwing the typed value away.
  test('a peer label value survives retyping its key', async ({ page }) => {
    await openTab(page, 'Policy Editor')
    await openIngressRule(page)
    await page.getByRole('button', { name: '+ Blank Peer' }).click()
    const key = placeholder(page, 'label (app)')
    const value = placeholder(page, 'value (frontend)')
    await typeInto(page, key, 'app')
    await typeInto(page, value, 'web')
    await typeInto(page, key, 'tier') // clears the key first, then retypes
    await expect(value).toHaveValue('web')
    expect(await outputYAML(page)).toContain('tier: "web"')
  })
})
