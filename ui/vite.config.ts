import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
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
