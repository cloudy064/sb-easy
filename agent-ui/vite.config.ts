import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  plugins: [svelte()],
  server: {
    port: 51823,
    proxy: {
      '/api': 'http://127.0.0.1:51822',
      '/health': 'http://127.0.0.1:51822',
    },
  },
})
