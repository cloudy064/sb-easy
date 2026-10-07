import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  base: './',
  plugins: [vue(), {
    name: 'development-only-csp',
    transformIndexHtml(html, context) {
      // Vite injects styles and uses a local HMR socket only during development.
      // The production build keeps the strict packaged-resource policy.
      return context.server ? html.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'")
        .replace("connect-src 'none'", "connect-src 'self' ws://127.0.0.1:51824") : html
    },
  }],
  server: { port: 51824, strictPort: true },
  build: { outDir: 'dist', emptyOutDir: true, assetsInlineLimit: 0 },
})
