// The admin web's calls to Insight's own /api. The session is an HttpOnly
// cookie, so nothing here holds a token; a 401 sends the admin to sign in.
// An error the API gives a code is said in the admin's language
// (i18n.ts, errors.*); one without, as the server words it.

import { i18n } from './i18n'

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public code = '',
  ) {
    super(message)
  }
}

function errorText(
  body: { error?: string; code?: string; params?: Record<string, string> },
  fallback: string,
) {
  const { t, te } = i18n.global
  if (!body.code || !te('errors.' + body.code)) return body.error ?? fallback
  return t('errors.' + body.code, { ...body.params })
}

let onSignedOut: () => void = () => {}

export function whenSignedOut(f: () => void) {
  onSignedOut = f
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch('api' + path, {
    method,
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
  })
  if (res.status === 401 && !path.startsWith('/login')) onSignedOut()
  if (!res.ok) {
    let msg = res.statusText
    let code = ''
    try {
      const answer = await res.json()
      msg = errorText(answer, msg)
      code = answer.code ?? ''
    } catch {
      // not JSON
    }
    throw new ApiError(res.status, msg, code)
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

export interface Me {
  id: number
  username: string
  totpEnabled: boolean
  lastLoginAt: number
}

export interface NodeState {
  id: number
  name: string
  state: string
}

export interface Status {
  version: string
  registered: boolean
  panel?: string
  claimCode?: string
  feed: {
    state: 'waiting' | 'ok' | 'unsupported' | 'no-scope' | 'error'
    error?: string
    lastPoll: string
    gaps: number
    lastGap: string
    nodes: NodeState[] | null
    pending: number
  }
  asnLoaded: boolean
  cityLoaded: boolean
  attribution: string
  outages: number[]
  degraded: number
  probed: number
  tunnels: { state: 'waiting' | 'ok' | 'unsupported' | 'no-scope' | 'error'; error?: string }
  tunnelsDown: string[]
  // The countries Insight keeps regions for: the operator's own markets.
  homeCountries: string[]
}

export interface Cell {
  asn: number
  org: string
  country: string
  region?: string
  nodeId: number
  inbound: string
  network: string
  accepted: number
  authed: number
  failed: number
  earlyClose: number
  rttMs: number
  rttN: number
  retransPpm: number
  up: number
  down: number
  degraded: boolean
  // 'endpoint': a WireGuard endpoint's cell, which counts only the
  // handshakes that worked — never a failure. Absent for an inbound's cell
  // and for an OpenVPN or OpenConnect endpoint's, which count like one.
  kind?: 'endpoint'
}

// What a node serves, by the tag its cells carry.
export interface Shape {
  tag: string
  kind: 'inbound' | 'endpoint'
  type: string
  transport?: string
  security?: string
  fronted: boolean
}

export interface TunnelOnNode {
  id: number
  name: string
  mode: string
  enabled: boolean
  relayId: number
  relayName: string
  originIds: number[] | null
  originNames: string[] | null
  state: 'up' | 'down' | 'unknown'
  since?: number
  unlinked?: number[] | null
  role: 'relay' | 'origin'
  hours: { attempts: number; up: number; failed: number; flapped: number }
}

export interface NodeInfo {
  nodeId: number
  name: string
  address: string
  asn: number
  org: string
  country: string
  region: string
  city: string
  overrideAsn: number
  overrideOrg: string
  overrideCountry: string
  overrideCity: string
  updatedAt: number
  effective: { asn: number; org: string; country: string; city: string }
  // On the Nodes page only.
  inbounds?: Shape[]
  tunnels?: TunnelOnNode[]
}

export interface Matrix {
  hours: number
  cells: Cell[]
  nodes: NodeInfo[]
}

// Mode A: the admin's own model. The key is never sent back, only keySet.
export interface AISettings {
  enabled: boolean
  url: string
  model: string
  proxy: string
  dailyTokens: number
  keySet: boolean
  usedToday: number
  running: boolean
  countries: string[]
}

export interface AISettingsInput {
  enabled: boolean
  url: string
  model: string
  key: string
  clearKey: boolean
  proxy: string
  dailyTokens: number
}

export interface AIFinding {
  code: string
  severity: 'info' | 'warn' | 'critical'
  asn: number
  node: number
  inbound: string
  to_node: number
  to_inbound: string
  confidence: number
}

export interface AIReport {
  id: number
  country: string
  trigger: 'daily' | 'anomaly' | 'manual'
  at: number
  model: string
  tokens: number
  status: 'ok' | 'error' | 'budget' | 'empty'
  error: string
  rows: number
  dropped: number
  findings: string
}

// One node and inbound's probe evidence over the last six hours.
export interface Endpoint {
  nodeId: number
  inbound: string
  score: number
  replayed: number
  followUpFail: number
  followNormal: number
  noRoute: number
  quicStray: number
  failed: number
  accepted: number
  probed: boolean
  probedAt: number
  lastEvidence: number
  updatedAt: number
  // Whether a path alert on it followed its last probed alert; null while
  // that is still open.
  followed: boolean | null
}

export interface Alert {
  id: number
  kind:
    | 'path.degraded'
    | 'path.recovered'
    | 'asn.outage'
    | 'asn.recovered'
    | 'endpoint.probed'
    | 'tunnel.down'
    | 'tunnel.up'
  nodeId: number
  tunnel?: string
  inbound: string
  asn: number
  org: string
  network: string
  reason: string
  detail: string
  at: number
}

export interface Suggestion {
  asn: number
  org: string
  nodeId: number
  inbound: string
  network: string
  alternatives: { nodeId: number; inbound: string; network: string; success: number }[]
}

export interface Override {
  asn: number
  org: string
  country: string
  city: string
}

// Mode B (internal/cloud).
export interface CloudBatch {
  hour: number
  cells: number
  createdAt: number
  attempts: number
  nextAt: number
  sentAt: number
  lastError: string
  // The cloud refused this batch for good; it stays unsent.
  refused: boolean
}

export interface CloudCell {
  asn: number
  cc: string
  region: string
  org: string
  node_asn: number
  node_cc: string
  node_org: string
  proto: string
  transport: string
  security: string
  front: string
  network: string
  verdict: 'ok' | 'degraded' | 'asn_outage' | 'tunnel_down' | 'node_blocked'
  accepted: number
  authed: number
}

export interface CloudFinding {
  code:
    | 'asn_outage'
    | 'strategy_blocked'
    | 'strategy_degraded'
    | 'strategy_works'
    | 'throttled'
    | 'hosting_blocked'
    | 'probing'
    | 'all_clear'
  severity: 'info' | 'warn' | 'critical'
  asn: number
  org: string
  strategy: string
  node_asn: number
  confidence: number
}

export interface CloudReport {
  v: number
  extracted_at: number
  tier: 'full' | 'disruption'
  countries: {
    cc: string
    from: number
    to: number
    contributors: string
    findings: CloudFinding[]
  }[]
}

export interface CloudState {
  on: boolean
  url: string
  fingerprint: string
  registered: boolean
  // Off with a key the panel may still hold: its removal is retried.
  removing: boolean
  error?: string
  pending: number
  failed: number
  lastSent: CloudBatch | null
  recent: CloudBatch[]
  report: { report: CloudReport | null; checkedAt: number; latest: number; error?: string }
}

// The settings page (internal/settings): a secret only as whether one is set.
export interface Settings {
  saved: boolean
  telegramTokenSet: boolean
  telegramChat: string
  telegramProxy: string
  telegramApi: string
  language: 'en' | 'fa' | 'ru' | 'zh'
  metricsTokenSet: boolean
  metricsMin: number
  install: {
    port: string
    basePath: string
    publicUrl: string
    https: string
    database: string
    adminUsername: string
    regionCountries: string[]
    asnUrl: string
    cityUrl: string
    trustedProxies: string
  }
}

export interface SettingsInput {
  telegramToken: string
  clearTelegramToken: boolean
  telegramChat: string
  telegramProxy: string
  telegramApi: string
  language: string
  metricsToken: string
  clearMetricsToken: boolean
}

export const api = {
  login: (username: string, password: string) =>
    call<Me | { mfa: true; token: string }>('POST', '/login', { username, password }),
  loginMFA: (token: string, code: string) => call<Me>('POST', '/login/mfa', { token, code }),
  logout: () => call<void>('POST', '/logout'),
  me: () => call<Me>('GET', '/me'),
  password: (current: string, next: string) =>
    call<void>('PUT', '/me/password', { current, new: next }),
  totpEnrol: () => call<{ secret: string; uri: string }>('POST', '/me/2fa/totp'),
  totpConfirm: (code: string) => call<void>('POST', '/me/2fa/totp/confirm', { code }),
  totpDisable: (password: string) => call<void>('DELETE', '/me/2fa', { password }),
  status: () => call<Status>('GET', '/status'),
  matrix: (hours: number, by: 'asn' | 'region') =>
    call<Matrix>('GET', `/matrix?hours=${hours}&by=${by}`),
  nodes: () => call<NodeInfo[]>('GET', '/nodes'),
  override: (id: number, o: Override) => call<NodeInfo>('PUT', `/nodes/${id}/override`, o),
  alerts: (before?: number) =>
    call<Alert[]>('GET', '/alerts?limit=100' + (before ? `&before=${before}` : '')),
  suggestions: () => call<Suggestion[]>('GET', '/suggestions'),
  endpoints: () => call<Endpoint[]>('GET', '/endpoints'),
  ai: () => call<AISettings>('GET', '/ai'),
  saveAI: (s: AISettingsInput) => call<AISettings>('PUT', '/ai', s),
  aiReports: () =>
    call<{ reports: AIReport[]; orgs: Record<string, string> }>('GET', '/ai/reports'),
  runAI: (country: string) => call<{ started: boolean }>('POST', '/ai/run', { country }),
  cloud: () => call<CloudState>('GET', '/cloud'),
  setCloud: (on: boolean) => call<CloudState>('PUT', '/cloud', { on }),
  cloudBatch: (hour: number) => call<{ cells: CloudCell[] }>('GET', `/cloud/batches/${hour}`),
  cloudReport: () => call<CloudState>('POST', '/cloud/report'),
  settings: () => call<Settings>('GET', '/settings'),
  saveSettings: (s: SettingsInput) => call<Settings>('PUT', '/settings', s),
  resetSettings: () => call<Settings>('DELETE', '/settings'),
  testTelegram: () => call<{ sent: boolean }>('POST', '/settings/telegram/test'),
}
