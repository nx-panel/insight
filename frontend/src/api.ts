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
  retransPpm: number
  up: number
  down: number
  degraded: boolean
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
}

export interface Matrix {
  hours: number
  cells: Cell[]
  nodes: NodeInfo[]
}

export interface Alert {
  id: number
  kind: 'path.degraded' | 'path.recovered' | 'asn.outage' | 'asn.recovered'
  nodeId: number
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
}
