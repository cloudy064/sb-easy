import { ref } from 'vue'

export type Theme = 'light' | 'dark'

const STORAGE_KEY = 'sb-easy-theme'
const theme = ref<Theme>('light')

export function applyTheme(t: Theme) {
  theme.value = t
  document.documentElement.setAttribute('data-theme', t)
  localStorage.setItem(STORAGE_KEY, t)
}

/** Read the stored preference (or OS preference) and apply it. Call once at boot. */
export function initTheme() {
  const stored = localStorage.getItem(STORAGE_KEY) as Theme | null
  const prefersDark = window.matchMedia?.('(prefers-color-scheme: dark)').matches
  applyTheme(stored ?? (prefersDark ? 'dark' : 'light'))
}

export function useTheme() {
  function toggle() {
    applyTheme(theme.value === 'dark' ? 'light' : 'dark')
  }
  return { theme, toggle }
}
