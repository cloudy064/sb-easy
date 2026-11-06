<template>
  <section class="tailscale-settings">
    <label class="ts-check ts-title"><input v-model="form.enabled" type="checkbox" /> {{ t('tailscale.enable') }}</label>
    <p class="text-xs text-muted">{{ t('tailscale.summary') }}</p>
    <div v-if="form.enabled" class="ts-fields">
      <p class="text-xs text-muted">{{ t('tailscale.address.hint') }}</p>
      <div class="form-group">
        <label>{{ t('tailscale.auth_key') }}</label>
        <input v-model="form.auth_key" type="password" autocomplete="new-password" spellcheck="false" :disabled="form.clear_auth_key" placeholder="tskey-auth-…" />
        <p class="text-xs text-muted">{{ form.has_auth_key ? t('tailscale.key.saved') : t('tailscale.key.hint') }}</p>
      </div>
      <label v-if="form.has_auth_key" class="ts-check"><input v-model="form.clear_auth_key" type="checkbox" /> {{ t('tailscale.key.clear') }}</label>
      <details class="ts-advanced">
        <summary>{{ t('tailscale.advanced') }}</summary>
        <div class="form-group">
          <label>{{ t('tailscale.hostname') }}</label>
          <input v-model="form.hostname" placeholder="sb-easy-device" />
          <p class="text-xs text-muted">{{ t('tailscale.hostname.hint') }}</p>
        </div>
        <div class="form-group">
          <label>{{ t('tailscale.control_url') }}</label>
          <input v-model="form.control_url" type="url" placeholder="https://controlplane.tailscale.com" />
        </div>
        <label class="ts-check"><input v-model="form.accept_routes" type="checkbox" /> {{ t('tailscale.accept_routes') }}</label>
        <div class="form-group">
          <label>{{ t('tailscale.route_cidrs') }}</label>
          <textarea v-model="form.route_cidrs" rows="2" spellcheck="false" placeholder="192.168.50.0/24" />
          <p class="text-xs text-muted">{{ t('tailscale.routes.hint') }}</p>
        </div>
        <div class="form-group">
          <label>{{ t('tailscale.advertise_routes') }}</label>
          <textarea v-model="form.advertise_routes" rows="2" spellcheck="false" placeholder="192.168.50.0/24" />
          <p class="text-xs text-muted">{{ t('tailscale.advertise.hint') }}</p>
        </div>
        <label class="ts-check"><input v-model="form.advertise_exit_node" type="checkbox" /> {{ t('tailscale.advertise_exit_node') }}</label>
      </details>
      <p class="text-xs text-muted">{{ t('tailscale.coexist.hint') }}</p>
    </div>
  </section>
</template>

<script setup lang="ts">
import { useI18n } from '../composables/i18n'
import type { TailscaleForm } from '../lib/tailscale'

const form = defineModel<TailscaleForm>({ required: true })
const { t } = useI18n()
</script>

<style scoped>
.tailscale-settings { border: 1px solid var(--paper-border); border-radius: var(--radius-sm); padding: 0.9rem; margin-bottom: 1rem; }
.ts-title { font-weight: 650; color: var(--ink-primary); }
.ts-check { display: flex; align-items: center; gap: .5rem; font-size: .82rem; margin-bottom: .7rem; }
.ts-check input { width: auto; flex-shrink: 0; }
.ts-fields { margin-top: .8rem; }
.ts-fields > p { margin-bottom: .85rem; }
.form-group p { margin-top: .4rem; line-height: 1.5; }
.ts-advanced { margin: .9rem 0; }
.ts-advanced summary { cursor: pointer; font-size: .82rem; margin-bottom: .9rem; color: var(--ink-secondary); }
textarea { width: 100%; resize: vertical; font-family: var(--font-mono); }
</style>
