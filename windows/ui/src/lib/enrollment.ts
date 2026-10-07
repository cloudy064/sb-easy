export interface EnrollmentPreview {
  serverOrigin: string
  secure: boolean
}

// Return only non-sensitive display data. The one-time code never enters this
// result, storage, diagnostic messages, or a URL used by the browser itself.
export function previewEnrollment(raw: string): EnrollmentPreview {
  if (!raw.trim() || raw.length > 16_384) throw new Error('请粘贴完整的 sb-easy 注册链接')
  let uri: URL
  try { uri = new URL(raw.trim()) } catch { throw new Error('注册链接格式无效') }
  if (uri.protocol !== 'sbeasy:' || uri.hostname !== 'enroll' || uri.username || uri.password ||
      uri.port || uri.hash || (uri.pathname !== '' && uri.pathname !== '/')) {
    throw new Error('请使用 sbeasy://enroll 注册链接')
  }
  const servers = uri.searchParams.getAll('server')
  const codes = uri.searchParams.getAll('code')
  if (servers.length !== 1 || codes.length !== 1 || !/^[0-9a-f]{64}$/i.test(codes[0])) {
    throw new Error('注册链接缺少有效的服务器地址或一次性注册码')
  }
  let server: URL
  try { server = new URL(servers[0]) } catch { throw new Error('服务器地址格式无效') }
  if (!['https:', 'http:'].includes(server.protocol) || server.username || server.password || server.search || server.hash) {
    throw new Error('服务器必须是有效的 HTTP 或 HTTPS 地址')
  }
  return { serverOrigin: server.toString().replace(/\/+$/, ''), secure: server.protocol === 'https:' }
}
