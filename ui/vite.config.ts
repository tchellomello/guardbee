import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  test: {
    // Pure-function unit tests only (policy.ts's YAML generator and rule
    // detectors) — no DOM/React rendering, so the default Node environment
    // is enough and jsdom/happy-dom aren't needed as dependencies.
    include: ['src/**/*.test.ts'],
  },
  build: {
    rollupOptions: {
      output: {
        // Split vendor deps from app code so the warning-prone 500kB chunk
        // is react/react-dom/@xyflow/react (which barely ever changes), not
        // this project's own code — keeps both chunks under Vite's default
        // size warning and lets the browser cache the vendor chunk across
        // rebuilds of this tool's own code.
        manualChunks(id) {
          if (id.includes('node_modules')) {
            return 'vendor'
          }
        },
      },
    },
  },
  server: {
    // During `npm run dev`, proxy API calls to the real Go backend (started
    // separately with `guardbee ui`) instead of needing CORS
    // on the Go server — the production build is served by that same Go
    // binary directly (go:embed), so this proxy only matters for local
    // frontend development.
    proxy: {
      '/api': 'http://127.0.0.1:4747',
    },
  },
})
