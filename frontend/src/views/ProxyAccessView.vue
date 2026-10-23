<template>
  <main class="access-page"><div class="card"><div class="flex-between"><h2>{{ tr('代理订阅领取', 'Proxy subscription access') }}</h2><button class="btn-ghost" @click="toggleLocale">{{ locale === 'zh' ? 'EN' : '中文' }}</button></div>
    <p class="text-sm text-muted">{{ tr('使用管理员提供的领取密钥，为每台设备创建独立订阅。', 'Use the claim credential from your administrator to create a separate subscription for each device.') }}</p>
    <form v-if="!account" @submit.prevent="load"><div class="form-group"><label>{{ tr('领取密钥', 'Claim credential') }}</label><input v-model="token" type="password" required autocomplete="off" spellcheck="false"></div><button class="btn-primary" :disabled="busy">{{ tr('打开', 'Open') }}</button></form>
    <template v-else><h3>{{ account.name }}</h3><div class="stats"><span>{{ tr('实测用量', 'Reported usage') }}: {{ bytes(account.reported_bytes) }}</span><span>{{ tr('已分配额度', 'Allocated quota') }}: {{ bytes(account.allocated_bytes) }} / {{ account.quota_bytes ? bytes(account.quota_bytes) : tr('不限量', 'Unlimited') }}</span><span>{{ tr('到期时间', 'Expiry') }}: {{ account.expires_at ? new Date(account.expires_at * 1000).toLocaleString() : tr('不限期', 'No expiry') }}</span></div>
      <p class="text-sm text-muted">{{ tr('已分配额度含节点尚未用完的授权。重启可能保守扣留未使用额度；请联系管理员重置。', 'Allocated quota includes grants that nodes have not used. A restart can retain unused quota; contact your administrator for a reset.') }}</p>
      <form @submit.prevent="create"><div class="form-group"><label for="new-device-name">{{ tr('新设备名称', 'New device name') }}</label><input id="new-device-name" v-model="name" maxlength="128" required placeholder="Phone"></div><div class="form-group"><label for="new-device-expiry">{{ tr('设备到期时间（留空继承用户期限）', 'Device expiry (empty inherits the user expiry)') }}</label><input id="new-device-expiry" v-model="expiry" type="datetime-local"></div><button class="btn-primary" :disabled="busy || activeDevices >= account.max_devices">{{ tr('领取设备订阅', 'Create device subscription') }} ({{ activeDevices }}/{{ account.max_devices }})</button></form>
      <div v-for="device in account.devices.filter(d => d.enabled)" :key="device.id" class="device-row"><span>{{ device.name }}<br><small>{{ tr('到期', 'Expires') }}: {{ device.expires_at ? new Date(device.expires_at * 1000).toLocaleString() : tr('继承用户期限', 'User expiry') }}{{ activeDevice(device) ? '' : tr('（已到期）', ' (expired)') }}</small></span><button class="btn-danger btn-sm" :disabled="busy" @click="revoke(device)">{{ tr('撤销', 'Revoke') }}</button></div>
      <div v-if="subscription" class="subscription"><h3>{{ tr('设备订阅链接', 'Device subscription link') }}</h3><p class="text-sm">{{ tr('只在本次显示。复制到支持 sing-box JSON 订阅的客户端，并妥善保存。', 'Shown only now. Copy it to a client that supports sing-box JSON subscriptions and keep it private.') }}</p><textarea :value="subscription" readonly rows="4" aria-label="Subscription URL"/><button class="btn-secondary" @click="copy">{{ copied ? tr('已复制', 'Copied') : tr('复制链接', 'Copy link') }}</button></div>
      <p class="text-sm text-muted">{{ tr('撤销最迟 60 秒生效。同一凭证被复制不代表新的可识别物理设备。', 'Revocation takes effect within 60 seconds. Copying a credential does not identify a separate physical device.') }}</p><button class="btn-ghost" @click="close">{{ tr('关闭并清除本页凭证', 'Close and clear this page') }}</button>
    </template><p v-if="error" class="error-message" role="alert">{{ error }}</p>
  </div></main>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useI18n } from '../composables/i18n'
const { locale, toggle: toggleLocale } = useI18n()
const tr = (zh: string, en: string) => locale.value === 'zh' ? zh : en
interface Device { id: string; name: string; enabled: boolean; expires_at: number }
interface Account { name: string; quota_bytes: number; reported_bytes: number; allocated_bytes: number; expires_at: number; max_devices: number; devices: Device[] }
const token = ref(''), name = ref(''), error = ref(''), subscription = ref(''), copied = ref(false), busy = ref(false), account = ref<Account | null>(null)
const expiry = ref(''), now = ref(Math.floor(Date.now() / 1000))
let clock: ReturnType<typeof setInterval>
const activeDevice = (device: Device) => device.enabled && (!device.expires_at || device.expires_at > now.value)
const activeDevices = computed(() => account.value?.devices.filter(activeDevice).length || 0)
function bytes(n: number) { if (n < 1024) return `${n} B`; const p = Math.min(Math.floor(Math.log(n) / Math.log(1024)), 4); return `${(n / 1024 ** p).toFixed(2)} ${['B', 'KiB', 'MiB', 'GiB', 'TiB'][p]}` }
async function request(path: string, method = 'POST', body?: object) { if (location.protocol !== 'https:' && !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname)) throw new Error(tr('领取凭证需要 HTTPS 连接。', 'Claim credentials require an HTTPS connection.')); const response = await fetch(`/api/proxy-self/${path}`, { method, headers: { Authorization: `Bearer ${token.value}`, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined, cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' }); const data = await response.json(); if (!response.ok) throw new Error(data.error || tr('请求失败', 'Request failed')); return data }
async function perform(action: () => Promise<void>) { if (busy.value) return; busy.value = true; error.value = ''; try { await action() } catch (e: any) { error.value = e.message || tr('连接失败', 'Connection failed') } finally { busy.value = false } }
async function load() { await perform(async () => { account.value = await request('status') }) }
async function create() { await perform(async () => { const data = await request('devices', 'POST', { name: name.value, expires_at: expiry.value ? Math.floor(new Date(expiry.value).getTime() / 1000) : 0 }); subscription.value = `${location.origin}/api/proxy-self/subscription?token=${encodeURIComponent(data.subscription_token)}`; copied.value = false; name.value = ''; expiry.value = ''; account.value = await request('status') }) }
async function revoke(device: Device) { if (!window.confirm(tr(`撤销 ${device.name} 的访问权限？`, `Revoke access for ${device.name}?`))) return; await perform(async () => { await request(`devices/${device.id}`, 'DELETE'); account.value = await request('status'); subscription.value = '' }) }
async function copy() { await perform(async () => { await navigator.clipboard.writeText(subscription.value); copied.value = true }) }
function close() { token.value = ''; account.value = null; subscription.value = ''; name.value = ''; expiry.value = ''; error.value = '' }
onMounted(() => { clock = setInterval(() => { now.value = Math.floor(Date.now() / 1000) }, 1000); const params = new URLSearchParams(location.hash.slice(1)); const supplied = params.get('token'); if (supplied) { token.value = supplied; history.replaceState(history.state, '', location.pathname + location.search); void load() } })
onUnmounted(() => clearInterval(clock))
</script>

<style scoped>
.access-page { min-height:100vh; padding:3rem 1rem; background:var(--paper-bg); }.access-page>.card { max-width:680px; margin:auto; padding:2rem; }.stats { display:flex; flex-direction:column; gap:.6rem; margin:1rem 0; }.device-row { display:flex; justify-content:space-between; gap:1rem; align-items:center; padding:.8rem 0; border-bottom:1px solid var(--paper-border); }.subscription { padding:1rem 0; } textarea { width:100%; margin:.6rem 0; font-family:monospace; }.error-message { color:var(--bad); margin:1rem 0; } h3 { margin-top:1rem; }
</style>
