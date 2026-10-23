<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import type { HealthPolicy, HealthSnapshot, RoutingGroup } from '../lib/protocol'
const props = defineProps<{ policy: HealthPolicy; snapshot?: HealthSnapshot; groups: RoutingGroup[]; nodes: { tag: string; type: string; label?: string }[]; disabled: boolean; running: boolean }>()
const emit = defineEmits<{ save: [policy: HealthPolicy]; automatic: [group: string, candidates: string[]]; check: [] }>()
const draft = reactive<HealthPolicy>({ ...props.policy })
const dirty = ref(false)
watch(() => props.policy, value => { if (!dirty.value) Object.assign(draft, value) }, { deep: true })
const group = ref('default')
const selected = ref<string[]>([])
const editableGroups = computed(() => props.groups.filter(g => g.editable))
const eligibleNodes = computed(() => props.nodes.filter(n => !['direct', 'block', 'dns', 'selector', 'urltest', 'wireguard'].includes(n.type)))
const selectedGroup = computed(() => editableGroups.value.find(g => g.id === group.value))
watch(selectedGroup, value => { selected.value = [...(value?.automatic_candidates ?? [])] }, { immediate: true })
watch(editableGroups, value => { if (!value.some(g => g.id === group.value)) group.value = value[0]?.id ?? '' })
const missing = computed(() => selected.value.filter(tag => !eligibleNodes.value.some(n => n.tag === tag)))
const hasAutomatic = computed(() => props.groups.some(g => g.mode === 'automatic'))
const statusText = computed(() => !props.policy.enabled ? '已关闭健康探测' : !props.running ? '连接后开始探测' : props.snapshot?.checking ? `正在探测 ${props.snapshot.completed} / ${props.snapshot.total}` : props.snapshot?.checked_at ? `最近完成：${new Date(props.snapshot.checked_at).toLocaleString('zh-CN', { hour12: false })}` : '等待后台探测')
function save() { emit('save', { ...draft }); dirty.value = false }
function errorLabel(code: string) {
  return ({ FIXED_EXIT_UNHEALTHY: '固定出口探测失败，保持指定出口', AUTOMATIC_ALL_FAILED: '候选全部失败，保持当前出口', ROUTING_NODE_UNAVAILABLE: '节点已不可用', HEALTH_SWITCH_FAILED: '切换失败，保持当前出口', CORE_ERROR: '内核未能完成切换' } as Record<string, string>)[code] || code
}
function nodeLabel(tag: string) { return props.nodes.find(n => n.tag === tag)?.label || tag }
</script>

<template>
  <section class="panel health-panel" aria-labelledby="health-title">
    <div class="section-heading"><div><h2 id="health-title">出口健康与自动选择</h2><p class="section-description">固定出口探测失败时只提示；自动组只会在你勾选的候选节点中切换。全部失败时保持当前出口。</p></div></div>
    <form class="health-policy" @submit.prevent="save" @input="dirty = true" @change="dirty = true">
      <label class="health-toggle"><input v-model="draft.enabled" type="checkbox" :disabled="disabled || hasAutomatic" />后台健康探测</label>
      <small v-if="hasAutomatic" class="input-hint">先将所有自动组改为固定出口，才能关闭探测。</small>
      <div class="health-fields">
        <label class="health-wide">HTTPS 探测地址<input v-model="draft.probe_url" type="url" required maxlength="2048" :disabled="disabled" /></label>
        <label>间隔（秒）<input v-model.number="draft.interval_seconds" type="number" min="30" max="86400" required :disabled="disabled" /></label>
        <label>超时（毫秒）<input v-model.number="draft.timeout_millis" type="number" min="500" max="30000" required :disabled="disabled" /></label>
        <label>切换策略<select v-model="draft.selection" :disabled="disabled"><option value="failover">仅故障时切换</option><option value="fastest">选择更快的候选</option></select></label>
        <label>速度改善阈值（毫秒）<input v-model.number="draft.tolerance_millis" type="number" min="0" max="10000" required :disabled="disabled || draft.selection !== 'fastest'" /></label>
      </div>
      <button class="secondary-button" type="submit" :disabled="disabled || !dirty" data-testid="health-save">保存健康设置</button>
    </form>
    <form v-if="editableGroups.length" class="health-automatic" @submit.prevent="emit('automatic', group, [...selected])">
      <h3>指定自动组候选</h3>
      <label>分流组<select v-model="group" :disabled="disabled" data-testid="health-group"><option v-for="item in editableGroups" :key="item.id" :value="item.id">{{ item.label }}{{ item.mode === 'automatic' ? ' · 自动' : '' }}</option></select></label>
      <div class="health-candidates" role="group" aria-label="允许自动选择的候选节点">
        <label v-for="node in eligibleNodes" :key="node.tag"><input v-model="selected" type="checkbox" :value="node.tag" :disabled="disabled || (!selected.includes(node.tag) && selected.length >= 32)" /><span>{{ node.label || node.tag }}<small>{{ node.type.toUpperCase() }}</small></span></label>
        <label v-for="tag in missing" :key="tag"><input v-model="selected" type="checkbox" :value="tag" :disabled="disabled" /><span>{{ nodeLabel(tag) }}<small>已不可用，请取消勾选</small></span></label>
        <p v-if="!eligibleNodes.length" class="input-hint">尚无可探测的代理节点。</p>
      </div>
      <p class="input-hint">已选 {{ selected.length }} / 32 个；直连与嵌套分组不能作为候选。保存时会验证配置并重新连接，已有连接可能中断。</p>
      <button class="secondary-button" :disabled="disabled || !policy.enabled || selected.length < 1 || selected.length > 32 || missing.length > 0" data-testid="health-automatic-save">保存自动候选组</button>
      <p class="input-hint">在首页的出口选择器中指定节点，即可退出自动选择。</p>
    </form>
    <div class="health-results" aria-live="polite"><div class="health-status"><span>{{ statusText }}</span><button type="button" class="text-button" :disabled="disabled || !running || !policy.enabled || snapshot?.checking" @click="emit('check')">立即探测</button></div>
      <p v-if="snapshot?.error_code" class="error-notice">{{ errorLabel(snapshot.error_code) }}</p>
      <div v-for="state in snapshot?.groups ?? []" :key="state.id" class="health-group-status"><strong>{{ groups.find(g => g.id === state.id)?.label || state.id }}</strong><span>{{ state.automatic ? '自动' : '固定' }} · {{ nodeLabel(state.selected) }}</span><small v-if="state.error_code" class="health-failure">{{ errorLabel(state.error_code) }}</small></div>
      <details v-if="snapshot?.results.length"><summary>查看 {{ snapshot.results.length }} 个节点探测结果</summary><div v-for="result in snapshot.results" :key="result.tag" class="health-node-status"><span>{{ nodeLabel(result.tag) }}</span><span :class="{ 'health-failure': !result.success }">{{ result.success ? `${result.delay_ms} ms` : errorLabel(result.error_code) }}</span></div></details>
    </div>
  </section>
</template>

<style scoped>
.health-panel { margin-top:24px; padding:24px; }.health-policy,.health-automatic { display:grid; gap:14px; }.health-fields { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; }.health-fields label,.health-automatic>label { display:grid; gap:7px; color:var(--secondary); font-size:12px; }.health-wide { grid-column:1/-1; }.health-toggle { display:flex; align-items:center; gap:9px; font-size:13px; }.health-policy input:not([type=checkbox]),.health-policy select,.health-automatic select { width:100%; min-width:0; box-sizing:border-box; padding:10px; color:var(--ink); background:var(--paper); border:1px solid var(--border); border-radius:8px; }.health-policy>button,.health-automatic>button { justify-self:start; }.health-automatic,.health-results { border-top:1px solid var(--border); margin-top:22px; padding-top:20px; }.health-automatic h3 { margin:0; font-size:14px; }.health-candidates { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; max-height:260px; overflow:auto; }.health-candidates label { display:flex; align-items:flex-start; gap:9px; padding:10px; border:1px solid var(--border); border-radius:8px; font-size:12px; overflow-wrap:anywhere; }.health-candidates small { display:block; color:var(--muted); margin-top:5px; font-size:10px; }.health-status { display:flex; align-items:center; justify-content:space-between; gap:10px; font-size:12px; color:var(--secondary); }.health-group-status { display:grid; grid-template-columns:130px 1fr; gap:6px; margin-top:12px; font-size:12px; overflow-wrap:anywhere; }.health-group-status small { grid-column:2; }.health-failure { color:var(--danger,#b64545); }.health-results details { margin-top:15px; font-size:12px; }.health-node-status { display:flex; justify-content:space-between; gap:15px; padding:8px 0; overflow-wrap:anywhere; }@media(max-width:680px) { .health-fields,.health-candidates { grid-template-columns:1fr; }.health-group-status { grid-template-columns:1fr; }.health-group-status small { grid-column:1; } }
</style>
