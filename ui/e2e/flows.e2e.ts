import { expect, openTab, test, visibleForm } from './fixtures/test'

test.describe('Flows tab', () => {
  test('fetches flows and shows them as rows and a graph', async ({ page }) => {
    await openTab(page, 'Flows')
    await visibleForm(page).locator('input').first().fill('webapp')
    await page.getByRole('button', { name: 'Fetch flows' }).click()
    // Two internet drops into webapp, and webapp's two flows to postgres.
    await expect(page.locator('table:visible tbody tr')).toHaveCount(4)
    await expect(page.locator('.react-flow__node:visible').first()).toBeVisible()
  })

  test('quick filters reach Hubble as query parameters', async ({ page, cluster }) => {
    await openTab(page, 'Flows')
    const form = visibleForm(page)
    await form.locator('input').first().fill('webapp')
    await form.locator('summary', { hasText: 'Filters' }).click()
    await form.getByRole('button', { name: 'Policy drops' }).click()
    await form.getByRole('button', { name: 'From the internet' }).click()
    await page.getByRole('button', { name: 'Fetch flows' }).click()

    await expect(page.locator('table:visible tbody tr')).toHaveCount(2) // POLICY_DENIED from the internet
    const q = cluster.flowQueries().at(-1)!
    expect(q.get('namespace')).toBe('webapp')
    expect(q.getAll('verdict')).toEqual(['DROPPED'])
    expect(q.getAll('dropReason')).toEqual(['POLICY_DENIED', 'POLICY_DENY'])
    expect(q.getAll('fromLabel')).toEqual(['reserved:world'])
    await expect(page.getByText(/^only: from label reserved:world · DROPPED · reason POLICY_DENIED, POLICY_DENY$/)).toBeVisible()
  })

  test('a quick filter toggles off again', async ({ page }) => {
    await openTab(page, 'Flows')
    const form = visibleForm(page)
    await form.locator('summary', { hasText: 'Filters' }).click()
    const dropped = form.getByRole('button', { name: 'Dropped', exact: true })
    await dropped.click()
    await expect(dropped).toHaveAttribute('aria-pressed', 'true')
    await expect(form.locator('select')).toHaveValue('DROPPED')
    await dropped.click()
    await expect(dropped).toHaveAttribute('aria-pressed', 'false')
    await expect(form.locator('select')).toHaveValue('')
  })

  // Regression: the section's open state was derived from "a filter is set",
  // so emptying the filter snapped it shut under the user.
  test('the filter section stays open when the filter becomes empty', async ({ page }) => {
    await openTab(page, 'Flows')
    const form = visibleForm(page)
    await form.locator('summary', { hasText: 'Filters' }).click()
    const port = form.getByPlaceholder('443')
    await port.click()
    await page.keyboard.type('8')
    await page.keyboard.press('Backspace')
    await expect(port).toBeVisible()
    await form.getByRole('button', { name: 'Dropped', exact: true }).click()
    await form.getByRole('button', { name: 'Clear' }).click()
    await expect(port).toBeVisible()
  })

  test('autocompletes pods and labels seen in fetched flows, by keyboard', async ({ page, cluster }) => {
    await openTab(page, 'Flows')
    await page.getByRole('button', { name: 'Fetch flows' }).click()
    await expect(page.locator('table:visible tbody tr').first()).toBeVisible()
    const form = visibleForm(page)
    await form.locator('summary', { hasText: 'Filters' }).click()

    const fromPod = form.getByPlaceholder('ns/web-')
    await fromPod.click()
    await fromPod.pressSequentially('webapp', { delay: 20 })
    const options = page.getByRole('listbox').getByRole('option')
    await expect(options.first()).toHaveText('webapp/webapp-') // workload prefix first
    await page.keyboard.press('Enter') // picks; must not submit the form
    await expect(fromPod).toHaveValue('webapp/webapp-')
    const fetchesBefore = cluster.flowQueries().length

    const fromLabel = form.getByPlaceholder('reserved:world')
    await fromLabel.click()
    await fromLabel.pressSequentially('app=pro', { delay: 20 })
    await expect(options).toHaveText(['k8s:app=prometheus']) // an identity label Hubble reported
    await page.keyboard.press('Escape')
    await expect(options).toHaveCount(0)
    expect(cluster.flowQueries().length).toBe(fetchesBefore)
  })

  test('a list field completes after the last comma', async ({ page }) => {
    await openTab(page, 'Flows')
    await page.getByRole('button', { name: 'Fetch flows' }).click()
    await expect(page.locator('table:visible tbody tr').first()).toBeVisible()
    const form = visibleForm(page)
    await form.locator('summary', { hasText: 'Filters' }).click()
    const port = form.getByPlaceholder('443')
    await port.click()
    await port.pressSequentially('5432, 91', { delay: 20 })
    await page.keyboard.press('Enter')
    await expect(port).toHaveValue('5432, 9187')
  })

  test('follow streams flows live', async ({ page, cluster }) => {
    await openTab(page, 'Flows')
    await visibleForm(page).locator('input').first().fill('postgres')
    await page.locator('label:visible', { hasText: 'Follow (live)' }).click()
    await page.getByRole('button', { name: 'Follow flows' }).click()
    await expect(page.locator('table:visible tbody tr')).toHaveCount(6)
    expect(cluster.streamQueries()[0].get('namespace')).toBe('postgres')
  })

  // Regression: Stop and Follow were one re-rendered <button>; the Stop
  // click's default action then ran on the restored type="submit" button
  // and restarted the stream it had just stopped.
  for (const how of ['click', 'Enter key'] as const) {
    test(`Stop following stops for good (${how})`, async ({ page, cluster }) => {
      cluster.holdStreams()
      await openTab(page, 'Flows')
      await page.locator('label:visible', { hasText: 'Follow (live)' }).click()
      await page.getByRole('button', { name: 'Follow flows' }).click()
      await expect(page.getByText(/waiting for matching flows/)).toBeVisible()
      expect(cluster.streamQueries()).toHaveLength(1)

      const stop = page.getByRole('button', { name: 'Stop following' })
      if (how === 'click') await stop.click()
      else {
        await stop.focus()
        await page.keyboard.press('Enter')
      }
      await expect(page.getByRole('button', { name: 'Follow flows' })).toBeVisible()
      await expect(page.getByText(/live ·/)).toHaveCount(0)
      await page.waitForTimeout(500)
      expect(cluster.streamQueries()).toHaveLength(1)
    })
  }

  test('a filter the backend rejects shows its reason, even while following', async ({ page }) => {
    // No mock involved: the real /api/flows/stream validates the filter.
    await page.unroute('**/api/flows/stream?*')
    await openTab(page, 'Flows')
    const form = visibleForm(page)
    await form.locator('summary', { hasText: 'Filters' }).click()
    await form.getByPlaceholder('POLICY_DENIED').fill('NOT_A_REASON')
    await page.locator('label:visible', { hasText: 'Follow (live)' }).click()
    await page.getByRole('button', { name: 'Follow flows' }).click()
    await expect(page.getByText('invalid --drop-reason-desc value "NOT_A_REASON"', { exact: false })).toBeVisible()
  })
})
