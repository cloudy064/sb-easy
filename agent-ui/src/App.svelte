<script lang="ts">
  import { onMount } from 'svelte'
  import { api } from './lib/api'
  import type { AgentStatus } from './lib/types'
  import Login from './Login.svelte'
  import Console from './Console.svelte'

  let authenticated: boolean | null = null
  let initialStatus: AgentStatus | null = null

  onMount(async () => {
    try {
      initialStatus = await api<AgentStatus>('/api/status')
      authenticated = true
    } catch {
      authenticated = false
    }
  })
</script>

{#if authenticated === null}
  <main class="boot"><div class="spinner"></div><span>正在连接本地 Agent…</span></main>
{:else if authenticated}
  <Console {initialStatus} onSessionExpired={() => (authenticated = false)} />
{:else}
  <Login onAuthenticated={() => (authenticated = true)} />
{/if}
