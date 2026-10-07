<script setup lang="ts">
defineProps<{ name: string }>()
const paths: Record<string, string> = {
  overview: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
  proxies: 'M4 6h16M4 12h16M4 18h16M8 4v4M16 10v4M10 16v4',
  connections: 'M4 7h13l-3-3M20 17H7l3 3M17 7l-3 3M7 17l3-3',
  profiles: 'M6 3h9l4 4v14H6zM14 3v5h5M9 12h7M9 16h5',
  rules: 'M5 5h3v3H5zM5 11h3v3H5zM5 17h3v3H5zM12 6h8M12 12h8M12 18h5',
  activity: 'M3 12h4l3-8 4 16 3-8h4',
  settings: 'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8M9 3h6l1 3 3 1 2 5-2 5-3 1-1 3H9l-1-3-3-1-2-5 2-5 3-1z',
  refresh: 'M20 7v5h-5M4 17v-5h5M6 6a8 8 0 0 1 13 3M5 15a8 8 0 0 0 13 3',
  arrow: 'M5 12h14M14 7l5 5-5 5',
  power: 'M12 3v9M6 6a9 9 0 1 0 12 0',
  search: 'M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14M15 15l6 6',
  up: 'M12 20V4M6 10l6-6 6 6', down: 'M12 4v16M6 14l6 6 6-6',
  check: 'M5 12l4 4L19 6', shield: 'M12 3l8 3v6c0 5-8 9-8 9s-8-4-8-9V6zM8 12l3 3 5-6',
}
</script>
<template><svg viewBox="0 0 24 24" aria-hidden="true"><path :d="paths[name] ?? paths.activity" /></svg></template>
