import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
export default defineConfig({
  plugins: [vue()],
  define: { 'process.env.NODE_ENV': '"production"', __VUE_OPTIONS_API__: true, __VUE_PROD_DEVTOOLS__: false, __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: false },
  build: { outDir: 'dist-capture', emptyOutDir: true,
    lib: { entry: 'src/capture-extension.ts', formats: ['es'], fileName: () => 'view.js', cssFileName: 'view' },
  },
})
