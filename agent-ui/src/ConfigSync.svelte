<script lang="ts">
  import { onMount } from 'svelte'
  import { api, ApiError } from './lib/api'
  export let onSessionExpired: () => void
  interface State {
    base_version: number
    patch_version: number
    local_version: number
    patch: Record<string, unknown>
    agent_settings: Record<string, unknown>
    server_patch: Record<string, unknown>
    server_agent_settings: Record<string, unknown>
    config: Record<string, unknown>
    pending: boolean
    conflict: boolean
    last_error?: string
  }
  let state: State | null = null
  let latest: State | null = null
  let draft = '{}'
  let settings = '{}'
  let busy = false
  let error = ''
  let changed = false

  async function load() {
    if (busy) return
    busy = true
    error = ''
    try {
      const next = await api<State>('/api/config-state')
      if (changed && state && (next.base_version !== state.base_version || next.patch_version !== state.patch_version || next.local_version !== state.local_version)) {
        latest = next
      } else {
        state = next
        latest = null
      }
      if (!changed) {
        draft = JSON.stringify(next.patch, null, 2)
        settings = JSON.stringify(next.agent_settings, null, 2)
      }
    } catch (e) { handleError(e) } finally { busy = false }
  }
  function handleError(e: unknown) {
    if (e instanceof ApiError && e.status === 401) onSessionExpired()
    error = e instanceof Error ? e.message : '配置同步失败'
  }
  function parseObject(text: string) {
    const value = JSON.parse(text)
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('请输入 JSON 对象')
    return value
  }
  async function save(resolve?: 'use_server' | 'retry_local') {
    if (!state || busy) return
    busy = true
    error = ''
    try {
      const next = await api<State>('/api/config-state', { method: 'PUT', body: JSON.stringify({
        base_version: state.base_version, patch_version: state.patch_version, local_version: state.local_version,
        patch: resolve === 'use_server' ? state.server_patch : parseObject(draft),
        agent_settings: resolve === 'use_server' ? state.server_agent_settings : parseObject(settings),
        ...(resolve ? { resolve } : {}),
      }) })
      state = next
      latest = null
      changed = false
      draft = JSON.stringify(next.patch, null, 2)
      settings = JSON.stringify(next.agent_settings, null, 2)
    } catch (e) { handleError(e) } finally { busy = false }
  }
  function reset() { draft = '{}'; settings = '{}'; changed = true }
  function reviewLatest() { if (latest) { state = latest; latest = null } }
  function useLatest() {
    if (!latest) return
    state = latest
    latest = null
    draft = JSON.stringify(state.patch, null, 2)
    settings = JSON.stringify(state.agent_settings, null, 2)
    changed = false
  }
  onMount(() => { void load() })
</script>

<article class="card sync-card">
  <div class="card-heading"><div><p class="eyebrow">SERVER CONFIGURATION</p><h2>基础配置与设备差异</h2></div><button class="secondary" disabled={busy} on:click={load}>检查更新</button></div>
  <p>服务器统一保存默认配置和设备 patch。此处的修改会定时上传；未覆盖的字段继续跟随默认配置。</p>
  {#if error}<p role="alert">{error}</p>{/if}
  {#if state}
    <p class="sync-status">{!state.base_version ? '等待首次从服务器同步' : state.conflict ? '存在冲突 · 本地修改已保留' : state.pending ? '等待同步到服务器' : '已同步到服务器'} · 基础版本 {state.base_version} · 设备版本 {state.patch_version}</p>
    {#if state.last_error}<p role="alert">{state.last_error}</p>{/if}
    <label>设备 patch<textarea bind:value={draft} on:input={() => changed = true} disabled={busy} rows="12" spellcheck="false"></textarea></label>
    <p>null 删除字段；从 patch 移除字段恢复继承。数组整体替换，覆盖后的列表不再合并默认列表。</p>
    <details><summary>设备运行设置</summary><textarea bind:value={settings} on:input={() => changed = true} disabled={busy} rows="8" spellcheck="false"></textarea></details>
    <div class="form-actions"><button class="primary" disabled={busy || !state.base_version || state.conflict || !!latest} on:click={() => save()}>保存并等待同步</button><button class="secondary" disabled={busy} on:click={reset}>恢复默认（填入空 patch）</button></div>
    {#if latest}
      <p>编辑期间配置已有更新，当前草稿已保留。请核对最新版本后继续。</p>
      <pre>{JSON.stringify({ patch: latest.patch, agent_settings: latest.agent_settings }, null, 2)}</pre>
      <div class="form-actions"><button class="secondary" on:click={reviewLatest}>已核对，继续编辑草稿</button><button class="secondary" on:click={useLatest}>载入最新版本</button></div>
    {:else if state.conflict}
      <p>服务器配置已有更新。核对下面的服务器版本后，可以保留当前草稿重试，或采用服务器版本。</p>
      <pre>{JSON.stringify({ patch: state.server_patch, agent_settings: state.server_agent_settings }, null, 2)}</pre>
      <div class="form-actions"><button class="primary" disabled={busy} on:click={() => save('retry_local')}>已核对，提交当前草稿</button><button class="secondary" disabled={busy} on:click={() => save('use_server')}>采用服务器版本</button></div>
    {/if}
    <p>已同步表示服务器已保存。实际配置应用失败时会保留上一份可用配置，请同时检查总览中的运行状态。</p>
  {/if}
</article>

<style>
  .sync-card { padding: 1.5rem; }
  .sync-card p { line-height: 1.6; font-size: .85rem; }
  .sync-card label { display: block; margin-top: 1rem; }
  .sync-card textarea { width: 100%; box-sizing: border-box; display: block; margin-top: .5rem; font-family: monospace; }
  .sync-card details { margin-top: 1rem; }
  .sync-card pre { max-height: 24rem; overflow: auto; }
</style>
