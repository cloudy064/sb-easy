<script lang="ts">
  import { api } from './lib/api'

  export let onAuthenticated: () => void

  let username = 'admin'
  let password = ''
  let busy = false
  let error = ''

  async function submit() {
    busy = true
    error = ''
    try {
      await api('/api/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      })
      history.replaceState({}, '', '/')
      onAuthenticated()
    } catch (reason) {
      error = reason instanceof Error ? reason.message : '登录失败，请重试'
    } finally {
      busy = false
    }
  }
</script>

<main class="login-page">
  <section class="login-shell">
    <div class="login-intro">
      <div class="brand"><span class="brand-mark">SB</span><div><b>sb-easy</b><small>Agent Console</small></div></div>
      <div>
        <p class="eyebrow">LOCAL CONTROL</p>
        <h1>管理这台设备的代理服务</h1>
        <p>UI 是独立静态应用；凭据和运行数据只与当前 Agent 通信。</p>
      </div>
      <span class="local-state"><i></i>本地服务已连接</span>
    </div>
    <form class="login-form" on:submit|preventDefault={submit}>
      <div><p class="eyebrow">WELCOME BACK</p><h2>登录控制台</h2><p>输入本地管理凭据继续。</p></div>
      <label>用户名<input bind:value={username} autocomplete="username" required /></label>
      <label>密码<input bind:value={password} type="password" autocomplete="current-password" required /></label>
      <button class="primary wide" class:busy disabled={busy}>{busy ? '正在验证…' : '登录'}</button>
      <div class="form-error" role="alert">{error}</div>
    </form>
  </section>
</main>
