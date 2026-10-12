<script setup lang="ts">
import { ref } from 'vue'
import type { SubscriptionsSummary } from '../lib/protocol'
defineProps<{ summary?: SubscriptionsSummary; disabled: boolean; filter: string; busy: boolean }>()
const emit = defineEmits<{ add: [name: string, url: string]; refresh: [id: string, name: string]; remove: [id: string]; filter: [value: string] }>()
const adding = ref(false), name = ref(''), url = ref(''), removing = ref('')
function submit() { const address = url.value.trim(); if (!name.value.trim() || !address) return; url.value = ''; emit('add', name.value.trim(), address) }
</script>
<template>
  <section class="subscriptions-panel panel">
    <div class="section-heading"><div><h2>订阅来源</h2><p class="routing-subtitle">服务器订阅由共享配置管理。本机订阅只在这台电脑使用。</p></div><button class="secondary-button" :disabled="disabled" @click="adding = !adding">{{ adding ? '收起' : '+ 添加本机订阅' }}</button></div>
    <form v-if="adding" class="subscription-form" @submit.prevent="submit">
      <label>订阅名称<input v-model="name" maxlength="100" required :disabled="disabled" placeholder="例如：备用线路" /></label>
      <label>订阅地址<input v-model="url" type="url" required maxlength="8192" autocomplete="off" :spellcheck="false" :disabled="disabled" placeholder="https://…" /></label>
      <p>支持 Clash YAML、sing-box JSON、Base64 或明文分享链接。节点会先校验再保存；配置中的路由和 DNS 不会导入。运行中添加、更新或删除订阅会自动重新加载内核，连接可能短暂中断。</p>
      <button class="primary-button" :disabled="disabled || !name.trim() || !url.trim()">{{ busy ? '正在处理…' : '下载并添加' }}</button>
    </form>
    <div class="subscription-filters"><button class="source-choice" :class="{ selected: !filter }" @click="emit('filter', '')">全部节点</button><button class="source-choice" :class="{ selected: filter === 'unknown' }" @click="emit('filter', 'unknown')">其他 / 未知来源</button></div>
    <p v-if="!summary?.sources_available" class="collection-note">服务器尚未提供订阅归属。更新服务端并同步配置后显示，不会根据节点名称猜测来源。</p>
    <div class="subscription-grid">
      <article v-for="sub in summary?.managed ?? []" :key="`managed-${sub.id}`" class="subscription-source" :class="{ selected: filter === `managed:${sub.id}` }"><button @click="emit('filter', `managed:${sub.id}`)"><strong>{{ sub.name }}</strong><span>服务器订阅 · {{ sub.tags.length }} 个节点</span></button></article>
      <article v-for="sub in summary?.local ?? []" :key="`local-${sub.id}`" class="subscription-source" :class="{ selected: filter === `local:${sub.id}` }"><button @click="emit('filter', `local:${sub.id}`)"><strong>{{ sub.name }}</strong><span>本机订阅 · {{ sub.tags.length }} 个节点</span></button><div class="subscription-actions"><button class="text-button" :disabled="disabled" @click="emit('refresh', sub.id, sub.name)">更新</button><button class="text-button" :disabled="disabled" @click="removing = sub.id">删除</button></div><div v-if="removing === sub.id" class="subscription-confirm"><p>删除本机订阅及其节点？正在使用的节点需先切换到其他出口。</p><button class="text-button" :disabled="disabled" @click="emit('remove', sub.id); removing = ''">确认删除</button><button class="text-button" @click="removing = ''">取消</button></div></article>
    </div>
    <p v-if="!summary?.local.length" class="collection-note">还没有本机订阅。添加后可在首页选择其中的节点。</p>
  </section>
</template>
