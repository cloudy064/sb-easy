<script setup lang="ts">
import { computed, ref } from 'vue'
import type { LocalRoutingGroup, RoutingGroup } from '../lib/protocol'
const props = defineProps<{ groups: RoutingGroup[]; nodes: { tag: string; label?: string }[]; disabled: boolean; pending: string }>()
const emit = defineEmits<{ save: [group: LocalRoutingGroup]; remove: [id: string] }>()
const editing = ref(false), id = ref(''), label = ref(''), domains = ref(''), processes = ref(''), mode = ref<'default' | 'node'>('default'), node = ref(''), confirmDelete = ref('')
const local = computed(() => props.groups.filter(group => group.local))
function open(group?: RoutingGroup) {
  id.value = group?.id ?? `custom-${crypto.randomUUID().slice(0, 12)}`
  label.value = group?.label ?? ''; domains.value = group?.domains?.join('\n') ?? ''; processes.value = group?.processes?.join('\n') ?? ''
  mode.value = group?.mode === 'node' ? 'node' : 'default'; node.value = group?.outbound ?? ''; editing.value = true
}
function lines(value: string) { return [...new Set(value.split(/[\n,]/).map(item => item.trim()).filter(Boolean))] }
const valid = computed(() => label.value.trim() && (lines(domains.value).length || lines(processes.value).length) && (mode.value !== 'node' || node.value))
function save() {
  if (!valid.value || props.disabled) return
  emit('save', { id: id.value, label: label.value.trim(), domains: lines(domains.value).map(item => item.toLowerCase()), processes: lines(processes.value), mode: mode.value, ...(mode.value === 'node' ? { node: node.value } : {}) })
}
</script>
<template>
  <section class="panel local-group-editor" aria-labelledby="local-group-title">
    <div class="section-heading"><div><h2 id="local-group-title">自定义分组</h2><p class="input-hint">按域名或进程匹配，优先于中心的一般分流规则；中心同步会保留本机分组。</p></div><button class="secondary-button" :disabled="disabled" @click="open()">新增分组</button></div>
    <div v-for="group in local" :key="group.id" class="local-group-row"><div><strong>{{ group.label }}</strong><p>{{ group.domains?.length || 0 }} 个域名 · {{ group.processes?.length || 0 }} 个进程 · {{ group.mode === 'node' ? group.outbound : '跟随默认代理' }}</p></div><div class="local-group-actions"><button class="text-button" :disabled="disabled" @click="open(group)">编辑</button><button v-if="confirmDelete !== group.id" class="text-button" :disabled="disabled" @click="confirmDelete = group.id">删除</button><template v-else><button class="text-button" :disabled="disabled" @click="emit('remove', group.id); confirmDelete = ''">确认删除</button><button class="text-button" @click="confirmDelete = ''">取消</button></template></div></div>
    <p v-if="!local.length && !editing" class="input-hint">例如将工作网站、聊天应用分别指向不同出口。</p>
    <form v-if="editing" class="local-group-form" @submit.prevent="save">
      <label>分组名称<input v-model="label" maxlength="128" required placeholder="工作服务" :disabled="disabled" /></label>
      <div class="local-group-fields"><label>域名后缀<textarea v-model="domains" rows="4" placeholder="example.com&#10;api.example.net" :disabled="disabled" /><small>每行一个域名，包含其子域名；组间不允许重复或嵌套。</small></label><label>Windows 进程名称<textarea v-model="processes" rows="4" placeholder="ChatGPT.exe&#10;Code.exe" :disabled="disabled" /><small>每行一个可执行文件名称。域名和进程任一匹配即可。</small></label></div>
      <label>分组出口<select v-model="mode" :disabled="disabled"><option value="default">跟随默认代理</option><option value="node">指定节点</option></select></label>
      <label v-if="mode === 'node'">节点<select v-model="node" required :disabled="disabled"><option disabled value="">选择节点</option><option v-for="item in nodes" :key="item.tag" :value="item.tag">{{ item.label || item.tag }}</option></select></label>
      <div class="form-footer"><button class="primary-button" :disabled="disabled || !valid">{{ pending === id ? '保存中…' : '保存分组' }}</button><button type="button" class="secondary-button" :disabled="disabled" @click="editing = false">收起</button></div>
      <p class="input-hint">保存后会校验 DNS 和数据流是否使用同一出口；正在连接时会重新应用配置。</p>
    </form>
  </section>
</template>
<style scoped>
.local-group-editor{margin-top:18px;padding:22px}.local-group-row{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid var(--border)}.local-group-row p{font-size:12px;color:var(--muted);margin:6px 0 0}.local-group-actions{display:flex;gap:12px;flex:none}.local-group-form{display:grid;gap:16px;margin-top:18px}.local-group-form label{display:grid;gap:8px;font-size:13px}.local-group-fields{display:grid;grid-template-columns:1fr 1fr;gap:16px}.local-group-form input,.local-group-form textarea,.local-group-form select{padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--ink);min-width:0;width:100%;font:inherit}.local-group-form small{font-size:11px;color:var(--muted)}@media(max-width:720px){.local-group-fields{grid-template-columns:1fr}}
</style>
