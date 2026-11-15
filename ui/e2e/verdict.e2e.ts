import { LOOKS_CORRECT_CNP } from './fixtures/lab'
import { expect, openTab, test, typeSlowly, visibleForm } from './fixtures/test'

test.describe('Verdict tab', () => {
  test('runs a candidate and shows the regression, graph and rows', async ({ page, cluster }) => {
    await openTab(page, 'Verdict')
    const form = visibleForm(page)
    await form.locator('input').first().fill('postgres')
    await form.locator('textarea').fill(LOOKS_CORRECT_CNP)
    await page.getByRole('button', { name: 'Run verdict' }).click()

    await expect(page.getByText('17 real flow(s) would BREAK')).toBeVisible()
    await expect(page.getByText('context: kind-guardbee-lab')).toBeVisible()
    await expect(page.locator('.react-flow__node:visible').first()).toBeVisible()
    await expect(page.locator('table:visible tbody tr', { hasText: 'NEWLY_DROPPED' })).toHaveCount(2)

    const body = cluster.requests.find((r) => new URL(r.url()).pathname === '/api/verdict')!.postDataJSON()
    expect(body.namespace).toBe('postgres')
    expect(body.candidateYAML).toBe(LOOKS_CORRECT_CNP)
  })

  test('filters ride along in the verdict request', async ({ page, cluster }) => {
    await openTab(page, 'Verdict')
    const form = visibleForm(page)
    await form.locator('input').first().fill('postgres')
    await form.locator('textarea').fill(LOOKS_CORRECT_CNP)
    await form.locator('summary', { hasText: 'Filters' }).click()
    await form.getByRole('button', { name: 'From nodes' }).click()
    await form.getByPlaceholder('443').fill('5432')
    await page.getByRole('button', { name: 'Run verdict' }).click()
    await expect(page.getByText(/^only: from label reserved:host · port 5432$/)).toBeVisible()

    const body = cluster.requests.find((r) => new URL(r.url()).pathname === '/api/verdict')!.postDataJSON()
    expect(body.fromLabel).toEqual(['reserved:host'])
    expect(body.toPort).toEqual(['5432'])
  })

  test('the candidate textarea keeps exactly what is typed', async ({ page }) => {
    await openTab(page, 'Verdict')
    const ta = visibleForm(page).locator('textarea')
    await ta.click()
    await typeSlowly(page, 'apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: typed\n')
    await expect(ta).toHaveValue('apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: typed\n')
  })

  // Regression: the modal's keydown effect re-ran on every keystroke and
  // handed focus back to the button behind it — only the 1st key landed.
  test('the Expand modal keeps focus and every keystroke', async ({ page }) => {
    await openTab(page, 'Verdict')
    await visibleForm(page).locator('textarea').fill('kind: CiliumNetworkPolicy\n')
    await page.getByRole('button', { name: '⤢ Expand' }).click()
    const modalText = page.getByRole('dialog').locator('textarea')
    await expect(modalText).toBeFocused()
    await page.keyboard.press('End')
    await page.keyboard.press('Control+End')
    await typeSlowly(page, 'metadata:\n  name: from-modal\n')
    await expect(modalText).toBeFocused()
    await expect(modalText).toHaveValue('kind: CiliumNetworkPolicy\nmetadata:\n  name: from-modal\n')
    await page.keyboard.press('Escape')
    await expect(visibleForm(page).locator('textarea')).toHaveValue('kind: CiliumNetworkPolicy\nmetadata:\n  name: from-modal\n')
  })

  test('Save works right after a paste, before any run', async ({ page }) => {
    await openTab(page, 'Verdict')
    await visibleForm(page).locator('textarea').fill(LOOKS_CORRECT_CNP)
    await visibleForm(page).getByRole('button', { name: /Save/ }).click()
    const name = page.getByRole('textbox', { name: 'Name to save this policy as' })
    await expect(name).toHaveValue('postgres-allow-webapp') // from metadata.name
    await name.press('Enter')
    const saved = await page.evaluate(() => JSON.parse(localStorage.getItem('guardbee.workspace.policies') || '[]'))
    expect(saved).toHaveLength(1)
    expect(saved[0].candidateYAML).toBe(LOOKS_CORRECT_CNP)
  })

  test('shows which workloads a candidate selects', async ({ page }) => {
    await openTab(page, 'Verdict')
    await visibleForm(page).locator('textarea').fill(LOOKS_CORRECT_CNP)
    await page.getByRole('button', { name: 'Which workloads does it select?' }).click()
    await expect(page.getByText('1 of 2 running pods are selected')).toBeVisible()
  })

  test('live mode follows, and Stop ends it', async ({ page, cluster }) => {
    await openTab(page, 'Verdict')
    const form = visibleForm(page)
    await form.locator('input').first().fill('postgres')
    await form.locator('textarea').fill(LOOKS_CORRECT_CNP)
    await page.locator('label:visible', { hasText: 'Follow (live)' }).click()
    await page.getByRole('button', { name: 'Start following' }).click()
    await expect(page.getByText('live — judging as flows arrive')).toBeVisible()
    await page.getByRole('button', { name: 'Stop', exact: true }).click()
    await expect(page.getByText('live — judging as flows arrive')).toHaveCount(0)
    await page.waitForTimeout(500)
    const streams = cluster.requests.filter((r) => new URL(r.url()).pathname === '/api/verdict/stream')
    expect(streams).toHaveLength(1)
  })
})
