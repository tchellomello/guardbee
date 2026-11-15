// End-to-end tests: the real `guardbee ui` binary (built by `mise run
// build`, so the UI is the embedded production bundle, not a dev server)
// driven in Chromium. Cluster-backed endpoints are mocked per test
// (e2e/fixtures/test.ts). Run with `mise run e2e`.

import { defineConfig, devices } from '@playwright/test'

const PORT = 47995

export default defineConfig({
  testDir: './e2e',
  // *.e2e.ts, not *.spec.ts/*.test.ts: keeps these out of vitest's unit run.
  testMatch: '**/*.e2e.ts',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : [['list']],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    viewport: { width: 1440, height: 900 },
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } } }],
  webServer: {
    // GUARDBEE_BIN runs the suite against another build, e.g. an older
    // release, to check a regression spec really catches its bug.
    command: `${process.env.GUARDBEE_BIN ?? '../guardbee'} ui --kubeconfig e2e/fixtures/dummy.kubeconfig --addr 127.0.0.1:${PORT}`,
    url: `http://127.0.0.1:${PORT}/api/version?client=1`,
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
})
