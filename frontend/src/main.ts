import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import './assets/main.css'
import { initTheme } from './composables/theme'
import { initLocale } from './composables/i18n'

initTheme()
initLocale()

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.mount('#app')
