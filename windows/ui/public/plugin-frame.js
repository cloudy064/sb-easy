// This document runs in an opaque sandbox. It never receives the HTTP session.
(() => {
  'use strict'
  const match = /^#(capture|statistics|network-tools|http-debug)\/([a-f0-9]{32})$/.exec(location.hash)
  if (!match || parent === window) return
  const [, id, channel] = match
  const parentOrigin = new URL(location.href).origin
  const pending = new Map()
  let initialized = false, sequence = 0
  function post(data) { parent.postMessage({ ...data, channel }, parentOrigin) }
  function stylesheet(href) {
    const link = document.createElement('link')
    link.rel = 'stylesheet'; link.href = href; document.head.appendChild(link)
  }
  const bridge = {
    available: true,
    request(method, params = {}, options = {}) {
      if (pending.size >= 16) return Promise.reject(new Error('待处理扩展请求过多'))
      const requestId = `extension-${++sequence}`
      return new Promise((resolve, reject) => {
        const timeoutMs = Math.min(45000, Math.max(1, options.timeoutMs || 5000))
        const timer = setTimeout(() => { pending.delete(requestId); reject(new Error('扩展请求超时，请先刷新状态')) }, timeoutMs + 1000)
        pending.set(requestId, { resolve, reject, timer })
        post({ type: 'request', id: requestId, method, params, timeoutMs })
      })
    },
  }
  window.addEventListener('message', async event => {
    if (event.source !== parent || event.origin !== parentOrigin || !event.data || event.data.channel !== channel) return
    const data = event.data
    if (data.type === 'response') {
      const request = pending.get(data.id)
      if (!request) return
      clearTimeout(request.timer); pending.delete(data.id)
      if (data.ok === true) request.resolve(data.result)
      else request.reject(new Error(typeof data.error?.message === 'string' ? data.error.message : '扩展请求未完成'))
      return
    }
    if (data.type !== 'initialize' || initialized) return
    initialized = true
    try {
      document.documentElement.dataset.theme = ['light', 'dark', 'system'].includes(data.theme) ? data.theme : 'system'
      for (const href of Array.isArray(data.styles) ? data.styles : []) {
        const url = new URL(href)
        if (url.origin === parentOrigin && url.pathname.startsWith('/assets/') && url.pathname.endsWith('.css')) stylesheet(url.href)
      }
      stylesheet(`/extensions/${id}/view.css`)
      const extension = await import(`${parentOrigin}/extensions/${id}/view.js`)
      extension.mount(document.getElementById('extension'), { bridge, server: typeof data.server === 'string' ? data.server : '' })
      new ResizeObserver(() => post({ type: 'height', height: document.documentElement.scrollHeight })).observe(document.body)
    } catch { post({ type: 'error' }) }
  })
  post({ type: 'ready' })
})()
