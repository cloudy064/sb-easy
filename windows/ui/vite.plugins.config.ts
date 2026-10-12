import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
export default defineConfig(({ mode }) => {
  if (!['statistics','network-tools','http-debug'].includes(mode)) throw new Error('Select an official extension mode')
  return { plugins: [vue()], define: { 'process.env.NODE_ENV': '"production"', __VUE_OPTIONS_API__: true, __VUE_PROD_DEVTOOLS__: false, __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: false }, build: { outDir: `dist-${mode}`, emptyOutDir: true,
    lib: { entry: `src/${mode}-extension.ts`, formats: ['es'], fileName: () => 'view.js', cssFileName: 'view' } } }
})
