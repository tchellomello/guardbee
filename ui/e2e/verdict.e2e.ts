import { LOOKS_CORRECT_CNP, VERDICT } from './fixtures/lab'
import { expect, openTab, test, typeSlowly, visibleForm } from './fixtures/test'

test.describe('Verdict tab', () => {
  test('reset discards an outstanding verdict response', async ({ page }) => {
    let release!: () => void
    const pending = new Promise<void>((resolve) => { release = resolve })
    let started = false
    await page.route('**/api/verdict', async (route) => {
      started = true
      await pending
      await route.fulfill({ json: VERDICT })
    })
    await openTab(page, 'Verdict')
    const form = visibleForm(page)
    await form.locator('input').first().fill('postgres')
    await form.locator('textarea').fill(LOOKS_CORRECT_CNP)
    await page.getByRole('button', { name: 'Run verdict', exact: true }).click()
    await expect.poll(() => started).toBe(true)
    await form.getByRole('button', { name: 'Reset', exact: true }).click()
    const completed = page.waitForResponse('**/api/verdict')
    release()
    await completed
    await expect(form.locator('textarea')).toHaveValue('')
    await expect(page.getByText('17 real flow(s) would BREAK')).toHaveCount(0)
    await expect(page.getByRole('button', { name: 'Duplicate to form' })).toHaveCount(0)
  })

  test('completed runs retain their simulation mode when the form changes', async ({ page }) => {
    await openTab(page, 'Verdict')
    const form = visibleForm(page)
    await form.locator('input').first().fill('postgres')
    await form.locator('textarea').fill(LOOKS_CORRECT_CNP)
    await form.getByText('Replace matching live policies', { exact: true }).click()
    await page.getByRole('button', { name: 'Run verdict', exact: true }).click()
    await expect(page.getByText('mode: additive', { exact: true })).toBeVisible()
    await form.getByText('Replace matching live policies', { exact: true }).click()
    await expect(page.getByText('mode: additive', { exact: true })).toBeVisible()
  })

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

  test('an L7 rule change shows as L7_CHANGED with its rules, not as a drop', async ({ page }) => {
    const l7Row = {
      ...VERDICT.rows[2],
      change: 'L7_CHANGED' as const,
      explanation: "(still allowed at L4; the L7 proxy's request rules for it change)",
      l7Candidate: 'ingress: HTTP GET /healthz',
    }
    await page.route('**/api/verdict', (r) =>
      r.fulfill({
        json: {
          ...VERDICT,
          counts: { ...VERDICT.counts, unchanged: 0, l7Changed: 15 },
          rows: [VERDICT.rows[0], l7Row],
        },
      })
    )
    await openTab(page, 'Verdict')
    const form = visibleForm(page)
    await form.locator('input').first().fill('postgres')
    await form.locator('textarea').fill(LOOKS_CORRECT_CNP)
    await page.getByRole('button', { name: 'Run verdict', exact: true }).click()

    const l7 = page.locator('table:visible tbody tr', { hasText: 'L7_CHANGED' })
    await expect(l7).toHaveCount(1)
    await expect(l7.getByTestId('verdict-l7-rules')).toHaveText('L7 no L7 rules → ingress: HTTP GET /healthz')
    // An L4 allow/deny exception can't undo an L7 rule change: offered on the
    // drop, never on the L7 row.
    await expect(l7.getByRole('button', { name: /Allow \/ Deny/ })).toHaveCount(0)
    await expect(page.locator('table:visible tbody tr', { hasText: 'NEWLY_DROPPED' }).first().getByRole('button', { name: /Allow \/ Deny/ })).toBeVisible()

    await page.getByRole('button', { name: /L7 changed/ }).click()
    await expect(page.getByText('Proxy Rules Change')).toBeVisible()
  })

  test('a refused DNS query is a NEWLY_DROPPED row naming the query', async ({ page }) => {
    const dnsRow = {
      ...VERDICT.rows[0],
      side: 'egress' as const,
      protocol: 'UDP',
      port: 53,
      l7Request: 'DNS api.github.com.',
      l7Baseline: 'egress: DNS *',
      l7Candidate: 'egress: DNS *.example.com',
    }
    await page.route('**/api/verdict', (r) => r.fulfill({ json: { ...VERDICT, rows: [VERDICT.rows[0], dnsRow] } }))
    await openTab(page, 'Verdict')
    const form = visibleForm(page)
    await form.locator('input').first().fill('postgres')
    await form.locator('textarea').fill(LOOKS_CORRECT_CNP)
    await page.getByRole('button', { name: 'Run verdict', exact: true }).click()

    const dns = page.locator('table:visible tbody tr', { hasText: 'UDP:53' })
    await expect(dns.getByTestId('verdict-l7-rules')).toHaveText('L7 DNS api.github.com.; egress: DNS * → egress: DNS *.example.com')
    // An L4 exception would only lift DNS filtering for this peer.
    await expect(dns.getByRole('button', { name: /Allow \/ Deny/ })).toHaveCount(0)
  })

  test('a candidate warning (toFQDNs without rules.dns) is shown on the run', async ({ page }) => {
    const warning = 'CiliumNetworkPolicy webapp/egress uses toFQDNs, but the candidate has no egress rule with rules.dns'
    await page.route('**/api/verdict', (r) => r.fulfill({ json: { ...VERDICT, warnings: [warning] } }))
    await openTab(page, 'Verdict')
    const form = visibleForm(page)
    await form.locator('input').first().fill('postgres')
    await form.locator('textarea').fill(LOOKS_CORRECT_CNP)
    await page.getByRole('button', { name: 'Run verdict', exact: true }).click()
    await expect(page.getByTestId('verdict-warning')).toHaveText(warning)
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
