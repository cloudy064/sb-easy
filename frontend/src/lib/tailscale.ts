import type { HostTailscale, TailscaleUpdate } from '../types'

export interface TailscaleForm {
  enabled: boolean
  hostname: string
  control_url: string
  auth_key: string
  clear_auth_key: boolean
  has_auth_key: boolean
  accept_routes: boolean
  route_cidrs: string
  advertise_routes: string
  advertise_exit_node: boolean
}

export function tailscaleForm(value?: HostTailscale): TailscaleForm {
  return {
    enabled: value?.enabled ?? false,
    hostname: value?.hostname ?? '',
    control_url: value?.control_url ?? '',
    auth_key: '',
    clear_auth_key: false,
    has_auth_key: value?.has_auth_key ?? false,
    accept_routes: value?.accept_routes ?? false,
    route_cidrs: (value?.route_cidrs ?? []).join('\n'),
    advertise_routes: (value?.advertise_routes ?? []).join('\n'),
    advertise_exit_node: value?.advertise_exit_node ?? false,
  }
}

function splitRoutes(value: string): string[] {
  return [...new Set(value.split(/[\s,]+/).filter(Boolean))]
}

export function tailscaleUpdate(form: TailscaleForm): TailscaleUpdate {
  const update: TailscaleUpdate = {
    enabled: form.enabled,
    hostname: form.hostname.trim(),
    control_url: form.control_url.trim(),
    accept_routes: form.accept_routes,
    route_cidrs: splitRoutes(form.route_cidrs),
    advertise_routes: splitRoutes(form.advertise_routes),
    advertise_exit_node: form.advertise_exit_node,
  }
  // Empty inputs preserve the stored key. Only an explicit clear sends empty.
  if (form.clear_auth_key) update.auth_key = ''
  else if (form.auth_key.trim()) update.auth_key = form.auth_key.trim()
  return update
}
