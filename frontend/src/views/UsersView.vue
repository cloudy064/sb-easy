<template>
  <div>
    <div class="page-header flex-between">
      <div>
        <h2>{{ t('page.users.title') }}</h2>
        <p class="text-sm text-muted" style="margin-top:0.25rem">{{ t('page.users.desc') }}</p>
      </div>
      <button class="btn-primary" @click="showCreate = true">Add User</button>
    </div>

    <!-- Users -->
    <div class="card mb-6">
      <h3 class="card-title">Accounts</h3>
      <div v-if="users.length === 0" class="text-sm text-muted">No users.</div>
      <div v-else class="tbl">
        <div class="tbl-row tbl-head"><span>Username</span><span>Role</span><span>Created</span><span></span></div>
        <div v-for="u in users" :key="u.id" class="tbl-row">
          <span class="font-medium">{{ u.username }}</span>
          <span><span class="badge" :class="u.role === 'admin' ? 'badge-blue' : 'badge-gray'">{{ u.role }}</span></span>
          <span class="text-muted text-xs">{{ u.created_at }}</span>
          <span class="flex-center gap-2" style="justify-content:flex-end">
            <button class="btn-ghost btn-sm" @click="pwTarget = u">Reset password</button>
            <button class="btn-danger btn-sm" @click="deleteUser(u)" :disabled="u.username === auth.username">Delete</button>
          </span>
        </div>
      </div>
    </div>

    <!-- Audit log -->
    <div class="card">
      <div class="flex-between mb-4">
        <h3 class="card-title" style="margin:0;border:none;padding:0">Audit Log</h3>
        <button class="btn-ghost btn-sm" @click="loadAudit">Refresh</button>
      </div>
      <div v-if="audit.length === 0" class="text-sm text-muted">No audit entries yet.</div>
      <div v-else class="tbl">
        <div class="tbl-row audit-row tbl-head"><span>Time</span><span>Actor</span><span>Action</span><span>Target</span></div>
        <div v-for="a in audit" :key="a.id" class="tbl-row audit-row">
          <span class="text-xs text-muted">{{ a.ts }}</span>
          <span>{{ a.actor }}</span>
          <span><span class="badge" :class="methodClass(a.action)">{{ a.action }}</span></span>
          <span class="font-mono text-xs truncate" :title="a.target">{{ a.target }}</span>
        </div>
      </div>
    </div>

    <!-- Create user -->
    <div v-if="showCreate" class="modal-overlay" @click.self="showCreate = false">
      <div class="modal">
        <h3>Add User</h3>
        <form @submit.prevent="createUser">
          <div class="form-group"><label>Username</label><input v-model="form.username" required /></div>
          <div class="form-group"><label>Password</label><input v-model="form.password" type="password" required placeholder="≥ 4 characters" /></div>
          <div class="form-group"><label>Role</label>
            <NmSelect v-model="form.role" :options="roleOptions" />
          </div>
          <p v-if="createErr" class="text-sm" style="color:var(--bad)">{{ createErr }}</p>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="showCreate = false">Cancel</button>
            <button type="submit" class="btn-primary">Create</button>
          </div>
        </form>
      </div>
    </div>

    <!-- Reset password -->
    <div v-if="pwTarget" class="modal-overlay" @click.self="pwTarget = null">
      <div class="modal">
        <h3>Reset password — {{ pwTarget.username }}</h3>
        <form @submit.prevent="resetPassword">
          <div class="form-group"><label>New password</label><input v-model="newPw" type="password" required placeholder="≥ 4 characters" /></div>
          <div class="modal-actions">
            <button type="button" class="btn-secondary" @click="pwTarget = null">Cancel</button>
            <button type="submit" class="btn-primary">Update</button>
          </div>
        </form>
      </div>
    </div>

    <div v-if="toast" class="toast"><div class="toast-item" :class="toastCls">{{ toast }}</div></div>
  </div>
</template>

<script setup lang="ts">
import { useI18n } from '../composables/i18n'
const { t } = useI18n()
import { ref, onMounted } from 'vue'
import client from '../api/client'
import { useAuthStore } from '../stores/auth'

interface User { id: string; username: string; role: string; created_at: string }
interface Audit { id: number; ts: string; actor: string; action: string; target: string }

const auth = useAuthStore()
const users = ref<User[]>([])
const audit = ref<Audit[]>([])
const showCreate = ref(false)
const form = ref({ username: '', password: '', role: 'viewer' })
const roleOptions = [
  { value: 'viewer', label: 'viewer (read-only)' },
  { value: 'admin', label: 'admin (full access)' },
]
const createErr = ref('')
const pwTarget = ref<User | null>(null)
const newPw = ref('')
const toast = ref('')
const toastCls = ref('toast-success')

function notify(msg: string, ok = true) {
  toast.value = msg
  toastCls.value = ok ? 'toast-success' : 'toast-error'
  setTimeout(() => (toast.value = ''), 2400)
}

async function loadUsers() {
  const { data } = await client.get('/users')
  users.value = data
}
async function loadAudit() {
  const { data } = await client.get('/users/audit')
  audit.value = data
}

async function createUser() {
  createErr.value = ''
  try {
    await client.post('/users', form.value)
    showCreate.value = false
    form.value = { username: '', password: '', role: 'viewer' }
    await loadUsers()
    notify('User created')
  } catch (e: any) {
    createErr.value = e.response?.data?.error || 'Failed to create user'
  }
}

async function deleteUser(u: User) {
  try {
    await client.delete(`/users/${u.id}`)
    await loadUsers()
    notify('User deleted')
  } catch (e: any) {
    notify(e.response?.data?.error || 'Delete failed', false)
  }
}

async function resetPassword() {
  if (!pwTarget.value) return
  try {
    await client.post(`/users/${pwTarget.value.id}/password`, { password: newPw.value })
    pwTarget.value = null
    newPw.value = ''
    notify('Password updated')
  } catch (e: any) {
    notify(e.response?.data?.error || 'Update failed', false)
  }
}

function methodClass(m: string) {
  if (m === 'DELETE') return 'badge-red'
  if (m === 'POST') return 'badge-green'
  return 'badge-yellow'
}

onMounted(() => { loadUsers(); loadAudit() })
</script>

<style scoped>
.card-title {
  font-size: 0.88rem; font-weight: 650; color: var(--ink-primary);
  margin-bottom: 0.85rem; padding-bottom: 0.65rem; border-bottom: 1px solid var(--paper-border);
}
.tbl { font-size: 0.85rem; }
.tbl-row {
  display: grid;
  grid-template-columns: 1.5fr 1fr 1.5fr 1.5fr;
  gap: 0.75rem; align-items: center;
  padding: 0.5rem 0; border-bottom: 1px solid var(--paper-border);
}
.audit-row { grid-template-columns: 1.6fr 1fr 0.8fr 2.4fr; }
.tbl-head { font-weight: 600; color: var(--ink-muted); text-transform: uppercase; font-size: 0.65rem; letter-spacing: 0.04em; }
.font-medium { font-weight: 550; }
</style>
