<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import type { NativeBridge } from '../lib/bridge'
import type { ExtensionId, ExtensionInfo, StoreItem, StoreProgress, StoreCatalog } from '../lib/protocol'
const props = defineProps<{ bridge: NativeBridge }>()
const emit = defineEmits<{ changed: [items: ExtensionInfo[]]; open: [id: ExtensionId] }>()
const items = ref<ExtensionInfo[]>([]), catalog = ref<StoreItem[]>([])
const busy = ref(false), error = ref(''), confirm = ref<ExtensionId | null>(null), tab = ref<'store' | 'installed'>('store')
const progress = ref<StoreProgress | null>(null), loaded = ref(false)
const trust = ref<StoreCatalog | null>(null), catalogFile = ref<HTMLInputElement | null>(null)
const rollbackConfirm = ref<ExtensionId | null>(null), catalogNotice = ref('')
let timer: ReturnType<typeof setTimeout> | undefined, disposed = false
const installing = computed(() => ['downloading','verifying','ready','installing'].includes(progress.value?.phase ?? ''))
const installedCount = computed(() => items.value.filter(i => i.installed).length)
const visible = computed(() => catalog.value.filter(c => c.id === 'network-tools' ? tab.value === 'installed' && state(c.id)?.installed : tab.value === 'store' || state(c.id)?.installed))
const percent = computed(() => Math.min(100, Math.round(100 * (progress.value?.received ?? 0) / (progress.value?.total || 1))))
const phaseLabel = computed(() => progress.value?.phase === 'verifying' ? '正在校验安装包' : progress.value?.phase === 'ready' ? '校验通过，等待停止扩展' : progress.value?.phase === 'installing' ? '正在安装' : '正在下载')
function state(id: string) { return items.value.find(i => i.id === id) }
function features(id: ExtensionId) { return id === 'http-debug' ? ['HTTPS 明文会话','修改与重放','mitmproxy 引擎'] : id === 'capture' ? ['应用与域名筛选','PCAP 导出','独立进程'] : id === 'statistics' ? ['按应用与域名汇总','本地历史','独立进程'] : ['活动连接','规则详情','脱敏日志'] }
function message(code: string) {
  return ({ STORE_DOWNLOAD: '下载失败，请检查网络后重试。', STORE_INTEGRITY: '安装包未通过完整性校验，已停止安装。请重试。', STORE_STORAGE: '无法写入扩展文件，请检查磁盘空间和目录权限后重试。', CATALOG_REQUIRED: '请先导入发布者签名的最新目录。', CATALOG_UNTRUSTED: '目录未通过受信发布者签名校验。', CATALOG_EXPIRED: '目录已过期，请获取新的签名目录。', STORE_REVOKED: '这个版本已撤销，请选择有效更新或回退版本。', STORE_DOWNGRADE: '该版本不能作为更新安装；请使用明确的回退操作。', BUSY: '操作正在进行，请稍后重试。' } as Record<string,string>)[code] || '安装未完成，请重试。'
}
async function refreshCatalog() { trust.value = await props.bridge.request('extensions.catalog'); catalog.value = trust.value.items }
async function refreshInstalled() {
  items.value = (await props.bridge.request('extensions.list')).extensions; emit('changed', items.value)
}
async function poll() {
  try {
    progress.value = await props.bridge.request('extensions.progress')
    if (progress.value.phase === 'complete') { await refreshInstalled(); await refreshCatalog() }
  } catch (e) { error.value = e instanceof Error ? e.message : '无法读取安装进度' }
  finally { if (!disposed && installing.value) timer = setTimeout(poll, 700) }
}
async function refresh() {
  error.value = ''
  try {
    await refreshCatalog()
    await refreshInstalled(); loaded.value = true
    if (timer) clearTimeout(timer)
    await poll()
  } catch (e) { error.value = e instanceof Error ? e.message : '无法读取扩展商店' }
}
async function install(id: ExtensionId) {
  busy.value = true; error.value = ''
  try { progress.value = await props.bridge.request('extensions.install', { id }); if (timer) clearTimeout(timer); await poll() }
  catch (e) { error.value = e instanceof Error ? e.message : '无法开始安装' }
  finally { busy.value = false }
}
async function change(id: ExtensionId, action: 'enable' | 'disable' | 'remove') {
  busy.value = true; error.value = ''
  try { items.value = (await props.bridge.request('extensions.change', { id, action }, { timeoutMs: 45_000 })).extensions; confirm.value = null; emit('changed', items.value); progress.value = null }
  catch (e) { error.value = e instanceof Error ? e.message : '扩展操作失败' }
  finally { try { await refreshInstalled(); await refreshCatalog() } catch { /* Keep the operation's error. */ } busy.value = false }
}
async function importCatalog(event: Event) {
  const input = event.target as HTMLInputElement, file = input.files?.[0]; input.value = ''
  if (!file) return
  if (!file.size || file.size > 900 * 1024) { error.value = '目录文件必须小于 900 KiB。'; return }
  busy.value = true; error.value = ''; catalogNotice.value = ''
  try { trust.value = await props.bridge.request('extensions.catalog_update', { envelope: await file.text() }, { timeoutMs: 45_000 }); catalog.value = trust.value.items; await refreshInstalled(); catalogNotice.value = '签名目录已验证，撤销信息已应用。' }
  catch (e) { error.value = e instanceof Error ? e.message : '签名目录导入失败' }
  finally { busy.value = false }
}
async function rollback(id: ExtensionId) {
  busy.value = true; error.value = ''
  try { items.value = (await props.bridge.request('extensions.rollback', { id }, { timeoutMs: 45_000 })).extensions; emit('changed', items.value); rollbackConfirm.value = null; progress.value = null; await refreshCatalog() }
  catch (e) { error.value = e instanceof Error ? e.message : '回退失败' }
  finally { busy.value = false }
}
onMounted(refresh)
onUnmounted(() => { disposed = true; if (timer) clearTimeout(timer) })
</script>
<template>
  <section class="panel store-panel">
    <header class="store-header"><div><span class="store-eyebrow">SB-EASY STORE</span><h2>让代理保持简单，<br>把需要的能力装进来。</h2><p>发现、安装与管理扩展，都在这里完成。</p></div><div class="store-mark" aria-hidden="true">＋</div></header>
    <nav class="store-tabs" aria-label="扩展分类"><button :class="{ active: tab === 'store' }" :aria-pressed="tab === 'store'" @click="tab = 'store'">浏览扩展</button><button :class="{ active: tab === 'installed' }" :aria-pressed="tab === 'installed'" @click="tab = 'installed'">已安装 <span>{{ installedCount }}</span></button><button class="store-refresh" :disabled="busy || installing" @click="refresh">刷新</button></nav>
    <p v-if="error" role="alert" class="notice error">{{ error }}</p>
    <div class="catalog-status">
      <input ref="catalogFile" data-testid="plugin-catalog-file" type="file" accept=".json,application/json" hidden @change="importCatalog">
      <p v-if="loaded && !trust?.trust_configured" data-testid="plugin-trust-unavailable" class="notice">当前版本未配置扩展发布者，在线安装和更新暂不可用。</p>
      <p v-else-if="loaded && !trust?.catalog_fresh" class="notice">导入发布者提供的有效签名目录后，即可安装和更新扩展。</p>
      <p v-else-if="loaded" class="store-meta">签名目录已验证 · 序号 {{ trust?.sequence }} · 更新安装后需重新启用</p>
      <button class="secondary-button" data-testid="plugin-catalog-import" :disabled="busy || installing || !trust?.trust_configured" @click="catalogFile?.click()">导入签名目录</button>
      <p v-if="catalogNotice" role="status" class="store-meta">{{ catalogNotice }}</p>
    </div>
    <p v-if="!loaded && !error" class="store-empty">正在加载商店…</p>
    <div v-if="loaded && !visible.length" class="store-empty"><h3>还没有安装扩展</h3><p>基础代理已经可以独立使用。需要更多功能时，再来挑选。</p><button class="secondary-button" @click="tab = 'store'">浏览扩展</button></div>
    <article v-for="item in visible" :key="item.id" class="store-card">
      <div class="card-top"><div class="extension-icon" aria-hidden="true"><svg viewBox="0 0 32 32" fill="none"><path d="M4 17h5l3-9 6 17 3-10 2 2h5" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg></div><div><div class="title-row"><h3>{{ item.name }}</h3><span class="official">官方</span></div><p class="store-meta">{{ item.publisher }} · v{{ item.version }} · {{ (item.size / 1024 / 1024).toFixed(1) }} MB</p></div><span v-if="state(item.id)?.installed" class="install-status">{{ state(item.id)?.failed ? '需要重新启用' : state(item.id)?.enabled ? '已启用' : '已停用' }}</span></div>
      <p v-if="item.id === 'network-tools'" class="notice">活动连接、规则和日志已内置。这个旧扩展可以卸载，不影响这些功能。</p>
      <p class="description">{{ item.description }}</p><div class="features"><span v-for="feature in features(item.id)" :key="feature">{{ feature }}</span></div>
      <p v-if="item.revoked" role="alert" class="notice error">已安装版本已被发布者撤销，不能启用。请更新或回退到仍有效的版本。</p>
      <p v-else-if="state(item.id)?.installed && item.verified === false" role="alert" class="notice error">扩展文件未通过验证，不能启用。请重新安装有效的签名版本。</p>
      <p v-if="item.pending_health" class="notice">新版本已安装并保持停用。启用时将检查独立进程；失败时尝试恢复之前的有效版本。</p>
      <p v-if="item.update_available" class="store-meta">可更新：v{{ item.installed_version }} → v{{ item.version }}</p>
      <details class="permissions"><summary>权限与数据使用</summary><p>{{ item.permissions }} 卸载后保留已保存的文件和设置。</p></details>
      <div v-if="installing && progress?.id === item.id" class="download-state" role="status"><div><span>{{ phaseLabel }}</span><span>{{ percent }}%</span></div><progress :value="percent" max="100" aria-label="扩展安装进度"/><p>可以离开此页面，代理会继续运行。</p></div>
      <p v-if="progress?.phase === 'failed' && progress.id === item.id" role="alert" class="notice error">{{ message(progress.error) }}</p>
      <footer v-if="item.id === 'network-tools'"><span>现已作为默认功能提供</span><div class="extension-actions"><button class="primary-button" @click="emit('open', item.id)">查看活动连接</button><button class="text-button" :disabled="busy || installing" @click="confirm = confirm === item.id ? null : item.id">卸载旧扩展</button></div></footer>
      <footer v-else-if="!state(item.id)?.installed"><span>安装后由你决定何时启用</span><button class="primary-button install-button" :disabled="busy || installing || !loaded || !item.install_available || !trust?.trust_configured" @click="install(item.id)">{{ installing && progress?.id === item.id ? '安装中…' : progress?.phase === 'failed' && progress.id === item.id ? '重试安装' : '安装扩展' }}<span v-if="!installing" aria-hidden="true">↓</span></button></footer>
      <footer v-else><span>{{ state(item.id)?.enabled ? '已启用，可打开扩展设置' : '已安装，尚未启用' }}</span><div class="extension-actions"><button v-if="state(item.id)?.enabled && !state(item.id)?.failed" class="primary-button" @click="emit('open', item.id)">打开</button><button v-if="item.install_available && (item.update_available || item.verified === false)" class="secondary-button" :disabled="busy || installing" @click="install(item.id)">{{ item.update_available ? '更新扩展' : '重新安装' }}</button><button class="secondary-button" :disabled="busy || installing || (!state(item.id)?.enabled && (item.revoked || item.verified === false))" @click="change(item.id, state(item.id)?.enabled && !state(item.id)?.failed ? 'disable' : 'enable')">{{ state(item.id)?.failed ? '重新启用' : state(item.id)?.enabled ? '停用' : '启用' }}</button><button v-if="item.rollback_available" class="text-button" :disabled="busy || installing" @click="rollbackConfirm = rollbackConfirm === item.id ? null : item.id">回退版本</button><button class="text-button" :disabled="busy || installing" @click="confirm = confirm === item.id ? null : item.id">卸载</button></div></footer>
      <div v-if="rollbackConfirm === item.id" class="notice" role="region" aria-label="扩展回退确认"><p>停止当前扩展并恢复之前验证过且仍有效的版本。回退后保持停用，已有文件和设置保留。</p><button class="secondary-button" :disabled="busy || installing" @click="rollback(item.id)">确认回退</button><button class="text-button" @click="rollbackConfirm = null">取消</button></div>
      <div v-if="confirm === item.id" class="notice"><p>{{ item.id === 'network-tools' ? '只移除旧扩展文件，内置活动连接、规则和日志继续可用。' : '卸载会停止该扩展并移除功能入口，已有文件和设置保留，代理继续运行。' }}</p><button class="secondary-button" :disabled="busy || installing" @click="change(item.id, 'remove')">确认卸载</button><button class="text-button" @click="confirm = null">取消</button></div>
    </article>
    <p class="store-note">验证发布者与安装包 · 按需启用 · HTTP 调试更新前会恢复代理路由</p>
  </section>
</template>
<style scoped>
.store-panel{padding:28px;max-width:940px}.store-header{display:flex;justify-content:space-between;align-items:center;padding:8px 0 28px;gap:24px}.store-eyebrow{font-size:10px;letter-spacing:2.4px;font-weight:700;color:var(--secondary)}.store-header h2{font-size:25px;line-height:1.5;letter-spacing:-.6px;margin:12px 0}.store-header p{font-size:13px;color:var(--secondary);margin:0}.store-mark{display:grid;place-items:center;width:92px;height:92px;border-radius:28px;background:linear-gradient(145deg,#e1eee7,#f1f5ed);color:#47785d;font-size:54px;font-weight:200;transform:rotate(-8deg);flex-shrink:0}.store-tabs{display:flex;flex-direction:row;gap:24px;border-bottom:1px solid var(--border);margin-bottom:24px}.store-tabs button{background:none;border:0;border-bottom:2px solid transparent;padding:12px 0;font-size:13px;color:var(--secondary);cursor:pointer}.store-tabs button.active{border-color:#48745d;color:var(--ink);font-weight:600}.store-tabs span{font-size:11px;background:var(--border);border-radius:10px;padding:2px 6px;margin-left:4px}.store-tabs .store-refresh{margin-left:auto}.store-card+.store-card{margin-top:18px}.store-card{border:1px solid var(--border);border-radius:16px;padding:24px}.card-top{display:flex;align-items:center;gap:14px}.extension-icon{width:48px;height:48px;border-radius:14px;background:#e8f0eb;color:#467259;padding:8px;flex-shrink:0}.extension-icon svg{width:100%;height:100%}.title-row{display:flex;align-items:center;gap:10px}.title-row h3{font-size:17px;margin:0}.official{font-size:10px;color:#47785d;background:#edf3ee;padding:3px 6px;border-radius:4px}.store-meta{font-size:11px;color:var(--secondary);margin:6px 0 0}.install-status{margin-left:auto;font-size:11px;color:var(--secondary)}.description{font-size:13px;line-height:1.9;margin:22px 0 14px;color:var(--secondary)}.features{display:flex;flex-wrap:wrap;gap:8px}.features span{font-size:11px;border:1px solid var(--border);padding:5px 9px;border-radius:6px;color:var(--secondary)}.permissions{margin-top:20px;font-size:12px;color:var(--secondary);line-height:1.8}.permissions summary{cursor:pointer}.permissions p{margin:8px 0}footer{border-top:1px solid var(--border);margin-top:24px;padding-top:18px;display:flex;justify-content:space-between;align-items:center;gap:16px}footer>span{font-size:11px;color:var(--secondary)}.install-button{display:flex;align-items:center;gap:28px}.extension-actions{display:flex;gap:10px;align-items:center}.store-note{text-align:center;color:var(--secondary);font-size:11px;margin:22px 0 0}.store-empty{text-align:center;padding:44px 12px;color:var(--secondary);font-size:13px}.store-empty h3{color:var(--ink);font-size:16px}.download-state{margin-top:20px;font-size:12px}.download-state>div{display:flex;justify-content:space-between}.download-state progress{width:100%;height:5px;accent-color:#48745d;margin-top:10px}.download-state p{color:var(--secondary);font-size:11px}@media(max-width:700px){.store-panel{padding:18px}.store-header h2{font-size:21px}.store-mark{width:66px;height:66px;border-radius:20px}.store-card+.store-card{margin-top:18px}.store-card{padding:18px}footer{flex-wrap:wrap}.install-status{max-width:76px}}
</style>
