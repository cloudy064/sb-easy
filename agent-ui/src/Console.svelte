<script lang="ts">
  import { onMount } from 'svelte'
  import { api, ApiError } from './lib/api'
  import type { AgentSettings, AgentStatus, ClashProxy, ProxyPayload } from './lib/types'

  export let initialStatus: AgentStatus | null = null
  export let onSessionExpired: () => void

  type Page = 'overview' | 'proxies' | 'settings' | 'config'
  type ProxyGroup = [string, ClashProxy]

  let page: Page = 'overview'
  let status: AgentStatus = initialStatus ?? {}
  let settings: AgentSettings = {}
  let config: Record<string, unknown> = {}
  let proxyPayload: ProxyPayload = { proxies: {} }
  let loading = true
  let search = ''
  let switchingGroup = ''
  let switchingNode = ''
  let actionBusy = ''
  let statusRefreshBusy = false
  let toast = ''
  let toastError = false
  let localEgress = true
  let defaultOutbound = ''
  let serverOverrides = '{}'
  let outboundOverrides = '{}'
  let saving = false
  let routeUrl = 'https://www.example.com/'
  let routeBusy = false
  let routeResult: Record<string, unknown> | null = null

  $: proxies = proxyPayload.proxies ?? {}
  $: groups = Object.entries(proxies).filter((entry): entry is ProxyGroup => Array.isArray(entry[1]?.all))
  $: visibleGroups = filterGroups(groups, search)
  $: telemetry = status.telemetry ?? {}

  function notify(message: string, error = false) {
    toast = message
    toastError = error
    window.setTimeout(() => {
      if (toast === message) toast = ''
    }, 2600)
  }

  async function guarded<T>(operation: () => Promise<T>): Promise<T | undefined> {
    try {
      return await operation()
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) {
        onSessionExpired()
        return undefined
      }
      throw error
    }
  }

  async function loadAll() {
    loading = true
    try {
      const result = await guarded(() =>
        Promise.all([
          api<AgentStatus>('/api/status'),
          api<AgentSettings>('/api/settings'),
          api<Record<string, unknown>>('/api/config'),
          api<ProxyPayload>('/api/proxies'),
        ]),
      )
      if (!result) return
      ;[status, settings, config, proxyPayload] = result
      loadSettingsForm()
    } catch (error) {
      notify(error instanceof Error ? error.message : '加载失败', true)
    } finally {
      loading = false
    }
  }

  function loadSettingsForm() {
    localEgress = settings.local_proxy_egress ?? true
    defaultOutbound = settings.default_proxy_outbound ?? ''
    serverOverrides = JSON.stringify(settings.outbound_server_overrides ?? {}, null, 2)
    outboundOverrides = JSON.stringify(settings.outbound_overrides ?? {}, null, 2)
  }

  function filterGroups(values: ProxyGroup[], value: string): ProxyGroup[] {
    const query = value.trim().toLowerCase()
    if (!query) return values
    return values
      .map(([name, group]) => {
        if (`${name} ${group.type ?? ''}`.toLowerCase().includes(query)) return [name, group] as ProxyGroup
        const all = (group.all ?? []).filter((node) => `${node} ${proxies[node]?.type ?? ''}`.toLowerCase().includes(query))
        return all.length ? [name, { ...group, all }] as ProxyGroup : null
      })
      .filter((value): value is ProxyGroup => value !== null)
  }

  function latestDelay(proxy?: ClashProxy): number | null {
    const history = proxy?.history ?? []
    const delay = Number(history[history.length - 1]?.delay)
    return Number.isFinite(delay) && delay > 0 ? Math.round(delay) : null
  }

  function delayTone(delay: number | null) {
    if (delay === null) return ''
    if (delay < 200) return 'good'
    if (delay < 500) return 'medium'
    return 'bad'
  }

  function formatBytes(value = 0, rate = false) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB']
    let amount = Math.max(0, Number(value) || 0)
    let index = 0
    while (amount >= 1024 && index < units.length - 1) {
      amount /= 1024
      index += 1
    }
    return `${amount.toFixed(index ? 1 : 0)} ${units[index]}${rate ? '/s' : ''}`
  }

  async function switchProxy(group: string, name: string) {
    if (switchingGroup) return
    switchingGroup = group
    switchingNode = name
    try {
      await guarded(() => api('/api/proxies', { method: 'PUT', body: JSON.stringify({ group, name }) }))
      if (proxies[group]) proxies[group].now = name
      proxyPayload = { ...proxyPayload, proxies: { ...proxies } }
      notify(`已切换：${group} → ${name}`)
      const fresh = await guarded(() => api<ProxyPayload>('/api/proxies'))
      if (fresh) proxyPayload = fresh
    } catch (error) {
      notify(error instanceof Error ? error.message : '节点切换失败', true)
    } finally {
      switchingGroup = ''
      switchingNode = ''
    }
  }

  async function refreshStatus() {
    if (statusRefreshBusy) return
    statusRefreshBusy = true
    try {
      const next = await guarded(() => api<AgentStatus>('/api/status'))
      if (next) status = next
    } catch {
      // Automatic refresh is best effort. The manual refresh button still
      // surfaces complete load errors to the user.
    } finally {
      statusRefreshBusy = false
    }
  }

  async function runAction(action: string) {
    actionBusy = action
    try {
      await guarded(() => api(`/api/actions/${action}`, { method: 'POST' }))
      notify(`操作已排队：${action}`)
    } catch (error) {
      notify(error instanceof Error ? error.message : '操作失败', true)
    } finally {
      actionBusy = ''
    }
  }

  async function saveSettings() {
    saving = true
    try {
      const body = {
        local_proxy_egress: localEgress,
        default_proxy_outbound: defaultOutbound.trim() || null,
        outbound_server_overrides: JSON.parse(serverOverrides || '{}'),
        outbound_overrides: JSON.parse(outboundOverrides || '{}'),
      }
      const updated = await guarded(() => api<AgentSettings>('/api/settings', { method: 'PUT', body: JSON.stringify(body) }))
      if (updated) settings = updated
      notify('设置已保存，配置刷新已排队')
    } catch (error) {
      notify(error instanceof Error ? error.message : '设置保存失败', true)
    } finally {
      saving = false
    }
  }

  async function testRoute() {
    routeBusy = true
    routeResult = null
    try {
      const result = await guarded(() => api<Record<string, unknown>>('/api/route-test', { method: 'POST', body: JSON.stringify({ url: routeUrl }) }))
      if (result) routeResult = result
    } catch (error) {
      notify(error instanceof Error ? error.message : '路由测试失败', true)
    } finally {
      routeBusy = false
    }
  }

  async function logout() {
    await guarded(() => api('/api/logout', { method: 'POST' }))
    onSessionExpired()
  }

  onMount(() => {
    loadAll()
    const timer = window.setInterval(() => {
      if (page === 'overview' && document.visibilityState === 'visible') {
        void refreshStatus()
      }
    }, 10_000)
    return () => window.clearInterval(timer)
  })
</script>

<div class="console">
  <aside class="sidebar">
    <div class="brand"><span class="brand-mark">SB</span><div><b>sb-easy</b><small>Agent Console</small></div></div>
    <nav>
      <button class:active={page === 'overview'} on:click={() => (page = 'overview')}><span>◫</span>总览</button>
      <button class:active={page === 'proxies'} on:click={() => (page = 'proxies')}><span>⇄</span>代理</button>
      <button class:active={page === 'settings'} on:click={() => (page = 'settings')}><span>⌁</span>本机设置</button>
      <button class:active={page === 'config'} on:click={() => (page = 'config')}><span>&#123; &#125;</span>运行配置</button>
    </nav>
    <div class="sidebar-foot">
      <div class="runtime-state"><i class:online={status.running === true}></i><div><b>{status.running ? 'sing-box 运行中' : '状态异常'}</b><small>{status.version ? `Agent v${status.version}` : '本地设备'}</small></div></div>
      <button class="quiet" on:click={logout}>退出登录</button>
    </div>
  </aside>

  <main class="workspace">
    <header class="topbar">
      <div><p class="eyebrow">LOCAL AGENT</p><h1>{page === 'overview' ? '总览' : page === 'proxies' ? '代理策略' : page === 'settings' ? '本机设置' : '运行配置'}</h1></div>
      <div class="top-actions"><span class="status-pill"><i class:online={status.running === true}></i>{status.running ? '运行中' : '需检查'}</span><button class="secondary" on:click={loadAll}>刷新</button></div>
    </header>

    <div class="content">
      {#if loading}
        <div class="loading"><div class="spinner"></div>正在读取本机状态…</div>
      {:else if page === 'overview'}
        <section class="overview-grid">
          <article class="hero card"><p class="eyebrow">SERVICE STATUS</p><div class="hero-row"><div><h2>{status.running ? '代理服务正常运行' : '代理服务需要检查'}</h2><p>{status.server ?? '尚未连接中心服务'}</p></div><span class:online={status.running === true} class="hero-orb"></span></div></article>
          <article class="card sync-card"><p class="eyebrow">CONFIG SYNC</p><dl><div><dt>最近同步</dt><dd>{status.last_cycle ? new Date(status.last_cycle).toLocaleString() : '等待首次同步'}</dd></div><div><dt>规则来源</dt><dd>{status.rule_source ?? 'profile'}</dd></div><div><dt>配置指纹</dt><dd class="mono">{status.etag ?? '—'}</dd></div><div><dt>状态刷新</dt><dd>仅总览可见时 · 每 10 秒</dd></div></dl></article>
          <div class="metrics">
            <article><span>实时上传</span><b>{telemetry.available ? formatBytes(telemetry.up, true) : '—'}</b></article>
            <article><span>实时下载</span><b>{telemetry.available ? formatBytes(telemetry.down, true) : '—'}</b></article>
            <article><span>活跃连接</span><b>{telemetry.available ? telemetry.conn_count ?? 0 : '—'}</b></article>
            <article><span>累计流量</span><b>{telemetry.available ? formatBytes((telemetry.up_total ?? 0) + (telemetry.down_total ?? 0)) : '—'}</b></article>
          </div>
          <article class="card actions-card"><div><p class="eyebrow">RUNTIME CONTROL</p><h3>运行控制</h3><p>操作会进入 Agent 队列，并由服务进程安全执行。</p></div><div class="action-list"><button class="secondary" class:busy={actionBusy === 'refresh'} disabled={!!actionBusy} on:click={() => runAction('refresh')}>重新拉取配置</button><button class="secondary" class:busy={actionBusy === 'reload'} disabled={!!actionBusy} on:click={() => runAction('reload')}>Reload</button><button class="danger" class:busy={actionBusy === 'restart'} disabled={!!actionBusy} on:click={() => runAction('restart')}>Restart</button></div></article>
          {#if status.last_error}<div class="error-banner">最近错误：{status.last_error}</div>{/if}
        </section>
      {:else if page === 'proxies'}
        <section>
          <div class="page-tools"><div><h2>策略组与节点</h2><p>{groups.length} 个策略组；手动组可直接切换，自动组显示实时选择。</p></div><input class="search" bind:value={search} placeholder="搜索策略组、节点或协议" /></div>
          {#if proxyPayload.error}<div class="error-banner">实时 Clash API 暂不可用，仅显示配置快照：{proxyPayload.error}</div>{/if}
          <div class="proxy-groups">
            {#each visibleGroups as [groupName, group] (groupName)}
              {@const manual = (group.type ?? '').toLowerCase() === 'selector'}
              <article class="proxy-group card">
                <header><div><div class="group-title"><h3>{groupName}</h3><span>{manual ? '手动选择' : '自动策略'}</span></div><p>{group.all?.length ?? 0} 个节点 · {group.type ?? '未知类型'}</p></div><div class="current-choice">当前 · {group.now || '尚未选择'}</div></header>
                <div class="proxy-grid">
                  {#each group.all ?? [] as node (node)}
                    {@const detail = proxies[node]}
                    {@const delay = latestDelay(detail)}
                    {@const current = group.now === node}
                    <button
                      class:current
                      class:busy={switchingGroup === groupName && switchingNode === node}
                      class="proxy-node"
                      disabled={!manual || !!proxyPayload.error || current || switchingGroup === groupName}
                      title={current ? '当前节点' : !manual ? '自动策略组由 sing-box 选择' : proxyPayload.error ? 'Clash API 当前不可用' : switchingGroup === groupName ? '正在切换节点' : `切换到 ${node}`}
                      on:click={() => switchProxy(groupName, node)}
                    >
                      <div><b title={node}>{node}</b>{#if current}<span class="current-dot">● 当前</span>{/if}</div>
                      <small><span>{detail?.type ?? 'unknown'}</span><span class={delayTone(delay)}>{delay === null ? '—' : `${delay} ms`}</span></small>
                    </button>
                  {/each}
                </div>
              </article>
            {:else}
              <div class="empty">没有匹配的代理策略组</div>
            {/each}
          </div>
        </section>
      {:else if page === 'settings'}
        <section class="settings-grid">
          <form class="card settings-card" on:submit|preventDefault={saveSettings}>
            <p class="eyebrow">NODE LOCAL</p><h2>本地出站调整</h2><p>这些设置只保存在当前设备，保存后会重新拉取并验证配置。</p>
            <label class="toggle-row"><span><b>使用本机代理出口</b><small>移除代理节点上的管理隧道 detour</small></span><input type="checkbox" bind:checked={localEgress} /></label>
            <label>默认代理出站 tag<input bind:value={defaultOutbound} placeholder="留空则沿用 Profile" /></label>
            <label>服务器地址覆盖（tag → server）<textarea bind:value={serverOverrides} rows="7" spellcheck="false"></textarea></label>
            <label>完整出站覆盖（tag → outbound）<textarea bind:value={outboundOverrides} rows="10" spellcheck="false"></textarea></label>
            <div class="form-actions"><button class="primary" class:busy={saving} disabled={saving}>{saving ? '正在保存…' : '保存并应用'}</button><button type="button" class="secondary" on:click={loadSettingsForm}>恢复</button></div>
          </form>
          <aside class="card help-card"><p class="eyebrow">NOTES</p><h3>配置说明</h3><dl><div><dt>默认代理</dt><dd>必须属于最终 selector，否则配置校验会拒绝应用。</dd></div><div><dt>地址覆盖</dt><dd>适合设备本地 DNS、入口或网络差异。</dd></div><div><dt>安全应用</dt><dd>新配置验证失败时不会覆盖当前可用配置。</dd></div></dl></aside>
        </section>
      {:else}
        <section class="config-stack">
          <article class="card route-card"><div><p class="eyebrow">LIVE ROUTE</p><h2>URL 实际路由测试</h2><p>建立一次短连接，读取最终规则、选择链和出站。</p></div><form on:submit|preventDefault={testRoute}><input bind:value={routeUrl} required /><button class="primary" class:busy={routeBusy} disabled={routeBusy}>{routeBusy ? '测试中…' : '测试走向'}</button></form>{#if routeResult}<pre>{JSON.stringify(routeResult, null, 2)}</pre>{/if}</article>
          <article class="card config-card"><div class="card-heading"><div><p class="eyebrow">SING-BOX</p><h2>当前运行配置</h2></div><span>{Array.isArray(config.outbounds) ? config.outbounds.length : 0} 个出站</span></div><pre>{JSON.stringify(config, null, 2)}</pre></article>
        </section>
      {/if}
    </div>
  </main>

  {#if toast}<div class:error={toastError} class="toast">{toast}</div>{/if}
</div>
