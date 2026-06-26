<template>
  <div class="modal-overlay" @click.self="$emit('close')">
    <div class="modal modal-wide">
      <h3>{{ isCreate ? t('devices.add.host') : t('hosts.edit') + ' — ' + (host?.name || '') }}</h3>

      <div class="hm-body">
        <!-- Settings -->
        <div class="section-block">
          <h4>{{ t('hosts.name') }}</h4>
          <div class="form-group"><input v-model="f.name" required placeholder="e.g. edge-hk-01" /></div>
          <div class="form-group"><label>{{ t('hosts.profile') }}</label>
            <NmSelect v-model="f.profile_id" :options="profileOptions" />
          </div>
          <div class="cap-checks">
            <label class="chk"><input type="checkbox" v-model="f.caps.runs_singbox" /> {{ t('hosts.cap.singbox') }}</label>
            <label class="chk"><input type="checkbox" v-model="f.caps.is_wg_member" /> {{ t('hosts.cap.wg') }}</label>
          </div>
          <div class="grid2">
            <div v-if="isCreate" class="form-group"><label>{{ t('hosts.wgaddr') }}</label><input v-model="f.wg_address" placeholder="10.59.32.10/32" /></div>
            <div class="form-group"><label>{{ t('hosts.clash') }}</label><input v-model="f.clash_api" placeholder="http://10.59.32.10:9090" /></div>
          </div>
          <div class="form-group"><label>{{ t('hosts.endpoint') }}</label><input v-model="f.wg_endpoint" placeholder="203.0.113.10:51820" /></div>
          <p class="text-xs text-muted" style="margin-top:-0.4rem">{{ t('hosts.endpoint.hint') }}</p>
        </div>

        <!-- Proxy assignment (existing hosts only) -->
        <div v-if="!isCreate" class="section-block">
          <h4>{{ t('hosts.proxies') }}</h4>
          <p class="text-xs text-muted" style="margin-top:-0.3rem">{{ t('hosts.proxies.hint') }}</p>
          <div class="proxy-pick">
            <label v-for="n in nodesStore.nodes" :key="n.id" class="proxy-pick-item">
              <input type="checkbox" :value="n.id" v-model="selectedNodes" />
              <span class="truncate">{{ n.tag }}</span>
              <span class="text-xs text-muted">{{ n.node_type }}</span>
            </label>
            <p v-if="nodesStore.nodes.length === 0" class="text-sm text-muted">No proxies yet.</p>
          </div>
          <div class="flex-between">
            <span class="text-xs text-muted">{{ selectedNodes.length === 0 ? t('hosts.proxies.all') : selectedNodes.length + ' selected' }}</span>
            <button class="btn-ghost btn-xs" @click="saveOutbounds">{{ t('action.save') }} {{ t('hosts.proxies') }}</button>
          </div>
        </div>

        <!-- Agent install (non-self existing hosts) -->
        <div v-if="!isCreate && host && !host.capabilities.is_self" class="section-block">
          <h4>{{ t('hosts.install') }}</h4>
          <p class="text-xs text-muted" style="margin-top:-0.3rem">{{ t('hosts.install.hint') }}</p>
          <div class="cmd-box" v-if="installCommand"><code>{{ installCommand }}</code></div>
          <div class="flex-center gap-2" style="justify-content:flex-end;margin-top:.5rem">
            <button class="btn-ghost btn-xs" @click="revealInstall">{{ installCommand ? 'Refresh' : t('hosts.install') }}</button>
            <button v-if="installCommand" class="btn-ghost btn-xs" @click="copyInstall">{{ copied ? t('action.copied') : t('action.copy') }}</button>
            <button v-if="installCommand" class="btn-ghost btn-xs" @click="rotate">{{ t('hosts.rotate') }}</button>
          </div>
        </div>
      </div>

      <div class="modal-actions hm-actions">
        <div class="flex-center gap-2">
          <button v-if="!isCreate && host && host.capabilities.is_wg_member && host.wg_address" class="btn-ghost btn-sm" @click="store.downloadWgConfig(host)">{{ t('hosts.wgconfig') }}</button>
          <button v-if="!isCreate && host && !host.capabilities.is_self" class="btn-danger btn-sm" @click="doDelete">{{ t('action.delete') }}</button>
        </div>
        <div class="flex-center gap-2">
          <button class="btn-secondary" @click="$emit('close')">{{ t('action.close') }}</button>
          <button class="btn-primary" @click="save">{{ isCreate ? t('hosts.create') : t('action.save') }}</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useI18n } from '../composables/i18n'
import { useHostsStore } from '../stores/hosts'
import { useProxyNodesStore } from '../stores/proxyNodes'
import type { Host } from '../types'

const props = defineProps<{ host: Host | null }>()
const emit = defineEmits<{ (e: 'close'): void; (e: 'saved'): void }>()

const { t } = useI18n()
const store = useHostsStore()
const nodesStore = useProxyNodesStore()

const isCreate = computed(() => !props.host)
const profileOptions = computed(() => store.profiles.map(p => ({ value: p.id, label: p.name })))
const selectedNodes = ref<string[]>([])
const installCommand = ref('')
const copied = ref(false)

const f = ref({
  name: props.host?.name ?? '',
  profile_id: props.host?.profile_id ?? 'default',
  caps: {
    runs_singbox: props.host?.capabilities.runs_singbox ?? true,
    is_wg_member: props.host?.capabilities.is_wg_member ?? true,
  },
  wg_address: '',
  wg_endpoint: props.host?.wg_endpoint ?? '',
  clash_api: props.host?.clash_api ?? '',
})

onMounted(async () => {
  await Promise.all([store.fetchProfiles(), nodesStore.fetchNodes()])
  if (props.host) selectedNodes.value = await store.getOutbounds(props.host.id)
})

async function save() {
  if (isCreate.value) {
    await store.createHost({
      name: f.value.name,
      profile_id: f.value.profile_id,
      capabilities: { ...f.value.caps },
      wg_address: f.value.wg_address || undefined,
      wg_endpoint: f.value.wg_endpoint || undefined,
      clash_api: f.value.clash_api || undefined,
    })
  } else if (props.host) {
    const caps = { ...props.host.capabilities, ...f.value.caps }
    await store.updateHost(props.host.id, {
      name: f.value.name,
      profile_id: f.value.profile_id,
      capabilities: caps,
      wg_endpoint: f.value.wg_endpoint,
      clash_api: f.value.clash_api,
    } as any)
    await store.fetchHosts()
  }
  emit('saved')
}

async function saveOutbounds() {
  if (!props.host) return
  await store.setOutbounds(props.host.id, selectedNodes.value)
}

async function revealInstall() {
  if (!props.host) return
  const { agent_token, server } = await store.revealToken(props.host.id)
  installCommand.value = buildCommand(server, agent_token)
  copied.value = false
}
async function rotate() {
  if (!props.host) return
  const token = await store.rotateToken(props.host.id)
  const { server } = await store.revealToken(props.host.id)
  installCommand.value = buildCommand(server, token)
}
function buildCommand(server: string, token: string) {
  const base = server.startsWith('http') ? server : `http://${server}:51821`
  return `SB_EASY_SERVER=${base} AGENT_TOKEN=${token} sb-easy-agent`
}
function copyInstall() {
  navigator.clipboard?.writeText(installCommand.value)
  copied.value = true
  setTimeout(() => (copied.value = false), 1500)
}

async function doDelete() {
  if (!props.host) return
  await store.deleteHost(props.host.id)
  emit('saved')
}
</script>

<style scoped>
.modal-wide { max-width: 640px; width: 94vw; }
.hm-body { max-height: 60vh; overflow-y: auto; padding-right: 0.25rem; }
.section-block { border: none; box-shadow: var(--nm-shadow-sm-in); border-radius: var(--radius-sm); padding: 0.9rem; margin-bottom: 1rem; }
.section-block h4 { font-size: 0.8rem; font-weight: 650; color: var(--ink-primary); margin: 0 0 0.6rem; }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
.cap-checks { display: flex; gap: 1.25rem; margin-bottom: 0.85rem; }
.chk { display: flex; align-items: center; gap: 0.5rem; font-size: 0.82rem; color: var(--ink-secondary); }
.cmd-box { background: var(--paper-bg); border: none; box-shadow: var(--nm-shadow-sm-in); border-radius: var(--radius-sm); padding: 0.75rem; margin-top: 0.5rem; font-family: var(--font-mono); font-size: 0.72rem; word-break: break-all; color: var(--ink-primary); }
.proxy-pick { max-height: 240px; overflow-y: auto; display: flex; flex-direction: column; gap: 2px; margin: 0.5rem 0; }
.proxy-pick-item { display: flex; align-items: center; gap: 0.6rem; padding: 0.4rem 0.5rem; border-radius: var(--radius-sm); font-size: 0.84rem; }
.proxy-pick-item:hover { background: var(--paper-bg); }
.hm-actions { display: flex; justify-content: space-between; align-items: center; }
</style>
