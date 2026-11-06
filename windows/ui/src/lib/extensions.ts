import { isRecord, validParams, type ExtensionId, type Method } from './protocol.js'

const permissions: Record<ExtensionId, ReadonlySet<string>> = {
  capture: new Set(['capture.snapshot', 'capture.validate', 'capture.configure', 'capture.rotate', 'capture.read', 'capture.delete', 'capture.upload']),
  statistics: new Set(['traffic.snapshot', 'traffic.clear']),
  'network-tools': new Set(['runtime.snapshot', 'config.inspect', 'logs.snapshot']),
  'http-debug': new Set(['httpdebug.snapshot', 'httpdebug.start', 'httpdebug.stop', 'httpdebug.attach', 'httpdebug.open', 'httpdebug.export', 'httpdebug.trust', 'httpdebug.untrust']),
}

export function validExtensionRequest(id: ExtensionId, value: unknown): value is { id: string; method: Exclude<Method, 'enrollment.apply'>; params: never; timeoutMs?: number } {
  return isRecord(value) && typeof value.id === 'string' && /^[a-zA-Z0-9-]{1,128}$/.test(value.id) &&
    typeof value.method === 'string' && permissions[id].has(value.method) && validParams(value.method as Method, value.params) &&
    (value.timeoutMs === undefined || (typeof value.timeoutMs === 'number' && Number.isFinite(value.timeoutMs) && value.timeoutMs >= 1 && value.timeoutMs <= 45_000))
}

export function validFrameMessage(event: Pick<MessageEvent, 'origin' | 'source' | 'data'>, frame: Window | null, channel: string): boolean {
  return frame !== null && event.source === frame && event.origin === 'null' &&
    isRecord(event.data) && event.data.channel === channel
}
