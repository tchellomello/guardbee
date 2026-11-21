// Regenerates the documentation screenshots in docs/images from the same
// mocked Lab scenario the e2e suite uses (e2e/fixtures), always in the light
// theme. Not part of `mise run e2e`: run `mise run docs-screenshots`.

import { defineConfig } from '@playwright/test'
import base from './playwright.config'

export default defineConfig({
  ...base,
  testMatch: '**/*.docs.ts',
  fullyParallel: false,
  retries: 0,
  reporter: [['list']],
  use: { ...base.use, colorScheme: 'light', screenshot: 'off', trace: 'off' },
  projects: [{ name: 'docs', use: { browserName: 'chromium', viewport: { width: 1440, height: 900 }, colorScheme: 'light' } }],
})
