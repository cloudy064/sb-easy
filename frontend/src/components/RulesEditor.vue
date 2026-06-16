<template>
  <div class="rules-editor">
    <div class="flex-between re-head">
      <span class="text-xs text-muted">{{ rows.length }} rule(s) · matched top-to-bottom, first match wins · fall-through → route.final</span>
      <button class="btn-ghost btn-xs" @click="addRule">+ rule</button>
    </div>

    <div v-for="(row, i) in rows" :key="row.id" class="rule-row">
      <div class="rule-ord">
        <button class="btn-ghost btn-xs" :disabled="i === 0" @click="move(i, -1)">↑</button>
        <button class="btn-ghost btn-xs" :disabled="i === rows.length - 1" @click="move(i, 1)">↓</button>
        <span class="rule-idx">{{ i + 1 }}</span>
      </div>

      <!-- Structured row -->
      <div v-if="row.mode === 'form'" class="rule-fields">
        <select v-model="row.matcher" @change="commit">
          <option value="">(any)</option>
          <option v-for="m in MATCHERS" :key="m.key" :value="m.key">{{ m.label }}</option>
        </select>

        <label v-if="matcherKind(row.matcher) === 'bool'" class="chk">
          <input type="checkbox" v-model="row.bool" @change="commit" /> true
        </label>
        <input
          v-else-if="row.matcher"
          v-model="row.value"
          @input="commit"
          :placeholder="matcherKind(row.matcher) === 'num' ? '80, 443' : 'comma, separated'"
        />

        <span class="rule-arrow">→</span>

        <select v-model="row.target" @change="commit">
          <option value="outbound">outbound</option>
          <option value="sniff">sniff</option>
          <option value="resolve">resolve</option>
          <option value="hijack-dns">hijack-dns</option>
          <option value="reject">reject</option>
        </select>
        <input
          v-if="row.target === 'outbound'"
          v-model="row.outbound"
          @input="commit"
          list="re-ob-suggest"
          placeholder="auto"
          style="max-width:120px"
        />

        <button class="btn-ghost btn-xs re-icon" title="Edit as raw JSON" @click="toRaw(i)">{ }</button>
        <button class="btn-danger btn-xs" @click="remove(i)">✕</button>
      </div>

      <!-- Raw row (lossless escape for anything the form can't represent) -->
      <div v-else class="rule-raw">
        <textarea
          v-model="row.rawText"
          @input="commit"
          rows="2"
          spellcheck="false"
          :class="{ 'raw-err': row.rawErr }"
          placeholder='{ "rule_set": ["geosite-cn"], "outbound": "direct" }'
        ></textarea>
        <button class="btn-danger btn-xs" @click="remove(i)">✕</button>
      </div>
    </div>

    <datalist id="re-ob-suggest">
      <option v-for="o in outboundSuggestions" :key="o" :value="o" />
    </datalist>

    <p v-if="!rows.length" class="text-xs text-muted">No rules — all traffic goes to <code>route.final</code>.</p>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'

// The parent passes its reactive `route.rules` array; we mutate it in place on
// every change (splice) so the parent's profile model — and its Save snapshot —
// always reflect the editor. Rules with anything the structured form can't
// represent are kept as raw JSON rows, so editing is fully lossless.
const props = defineProps<{ rules: any[]; outboundSuggestions: string[] }>()

const MATCHERS = [
  { key: 'domain', label: 'domain', kind: 'list' },
  { key: 'domain_suffix', label: 'domain_suffix', kind: 'list' },
  { key: 'domain_keyword', label: 'domain_keyword', kind: 'list' },
  { key: 'domain_regex', label: 'domain_regex', kind: 'list' },
  { key: 'ip_cidr', label: 'ip_cidr', kind: 'list' },
  { key: 'source_ip_cidr', label: 'source_ip_cidr', kind: 'list' },
  { key: 'ip_is_private', label: 'ip_is_private', kind: 'bool' },
  { key: 'port', label: 'port', kind: 'num' },
  { key: 'source_port', label: 'source_port', kind: 'num' },
  { key: 'process_name', label: 'process_name', kind: 'list' },
  { key: 'protocol', label: 'protocol', kind: 'list' },
  { key: 'rule_set', label: 'rule_set', kind: 'list' },
  { key: 'clash_mode', label: 'clash_mode', kind: 'str' },
] as const

const MATCHER_KEYS = MATCHERS.map((m) => m.key)
const ACTION_TARGETS = ['sniff', 'resolve', 'hijack-dns', 'reject']

function matcherKind(key: string): string {
  return MATCHERS.find((m) => m.key === key)?.kind ?? 'list'
}

interface Row {
  id: number
  mode: 'form' | 'raw'
  // form fields
  matcher: string
  value: string
  bool: boolean
  target: string
  outbound: string
  // raw fields
  rawText: string
  rawErr: boolean
}

let seq = 0
const rows = ref<Row[]>(props.rules.map(ruleToRow))

/** Decide whether a sing-box rule fits the structured form, and build a Row. */
function ruleToRow(rule: any): Row {
  const base: Row = {
    id: seq++, mode: 'form', matcher: '', value: '', bool: false,
    target: 'outbound', outbound: '', rawText: '', rawErr: false,
  }
  if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
    return { ...base, mode: 'raw', rawText: JSON.stringify(rule) }
  }
  const keys = Object.keys(rule)
  const matcherKeys = keys.filter((k) => MATCHER_KEYS.includes(k as any))
  // Target: an action verb, or a bare outbound (optionally action:"route").
  let target = ''
  if (typeof rule.action === 'string' && ACTION_TARGETS.includes(rule.action)) target = rule.action
  else if (typeof rule.outbound === 'string' && (rule.action === undefined || rule.action === 'route')) target = 'outbound'

  // Keys we account for in the structured form; anything else → raw.
  const accounted = new Set([...matcherKeys, 'outbound', 'action'])
  const hasExtra = keys.some((k) => !accounted.has(k))
  if (!target || matcherKeys.length > 1 || hasExtra) {
    return { ...base, mode: 'raw', rawText: JSON.stringify(rule) }
  }

  const mk = matcherKeys[0] ?? ''
  const row: Row = { ...base, matcher: mk, target }
  if (mk) {
    const v = rule[mk]
    if (matcherKind(mk) === 'bool') row.bool = v === true
    else if (Array.isArray(v)) row.value = v.join(', ')
    else row.value = String(v ?? '')
  }
  if (target === 'outbound') row.outbound = rule.outbound ?? ''
  return row
}

/** Build a sing-box rule from a structured Row. */
function rowToRule(row: Row): any {
  if (row.mode === 'raw') {
    try {
      row.rawErr = false
      return JSON.parse(row.rawText)
    } catch {
      row.rawErr = true
      return undefined // keep last-valid config; drop only this rule from output
    }
  }
  const rule: any = {}
  if (row.matcher) {
    const kind = matcherKind(row.matcher)
    if (kind === 'bool') rule[row.matcher] = !!row.bool
    else if (kind === 'num') rule[row.matcher] = splitNums(row.value)
    else if (kind === 'str') rule[row.matcher] = row.value.trim()
    else rule[row.matcher] = splitList(row.value)
  }
  if (row.target === 'outbound') rule.outbound = row.outbound || 'auto'
  else rule.action = row.target
  return rule
}

function splitList(s: string): string[] {
  return s.split(',').map((x) => x.trim()).filter(Boolean)
}
function splitNums(s: string): number[] {
  return s.split(',').map((x) => parseInt(x.trim(), 10)).filter((n) => !Number.isNaN(n))
}

/** Serialize rows back into the parent's rules array (in place). */
function commit() {
  const out = rows.value.map(rowToRule).filter((r) => r !== undefined)
  props.rules.splice(0, props.rules.length, ...out)
}

function addRule() {
  rows.value.push({
    id: seq++, mode: 'form', matcher: 'domain_suffix', value: '', bool: false,
    target: 'outbound', outbound: 'auto', rawText: '', rawErr: false,
  })
  commit()
}
function remove(i: number) {
  rows.value.splice(i, 1)
  commit()
}
function move(i: number, dir: number) {
  const j = i + dir
  if (j < 0 || j >= rows.value.length) return
  const [r] = rows.value.splice(i, 1)
  rows.value.splice(j, 0, r)
  commit()
}
function toRaw(i: number) {
  const row = rows.value[i]
  const rule = rowToRule(row)
  row.mode = 'raw'
  row.rawText = JSON.stringify(rule ?? {}, null, 0)
  commit()
}
</script>

<style scoped>
.rules-editor { display: flex; flex-direction: column; gap: 0.4rem; }
.re-head { margin-bottom: 0.25rem; }
.rule-row { display: flex; align-items: flex-start; gap: 0.5rem; }
.rule-ord { display: flex; align-items: center; gap: 0.15rem; padding-top: 0.3rem; flex-shrink: 0; }
.rule-idx { font-family: var(--font-mono); font-size: 0.65rem; color: var(--ink-muted); width: 1.2rem; text-align: right; }
.rule-fields { display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; flex: 1;
  border: 1px dashed var(--paper-border); border-radius: var(--radius-sm); padding: 0.4rem 0.5rem; }
.rule-fields > select { min-width: 90px; }
.rule-fields > input { flex: 1; min-width: 90px; }
.rule-arrow { color: var(--ink-muted); font-size: 0.85rem; }
.re-icon { font-family: var(--font-mono); }
.rule-raw { display: flex; gap: 0.4rem; flex: 1; align-items: flex-start; }
.rule-raw textarea {
  flex: 1; font-family: var(--font-mono); font-size: 0.72rem; line-height: 1.5;
  background: var(--paper-bg); border: 1px solid var(--paper-border);
  border-radius: var(--radius-sm); padding: 0.4rem 0.55rem; color: var(--ink-primary); resize: vertical;
}
.rule-raw textarea.raw-err { border-color: var(--bad); }
.chk { display: flex; align-items: center; gap: 0.35rem; font-size: 0.78rem; color: var(--ink-secondary); white-space: nowrap; }
.chk input { width: auto; }
</style>
