// Small formatting shared by the views.

import { asnName } from './asn'
import { i18n } from './i18n'

export function pct(part: number, whole: number) {
  if (!whole) return '—'
  return new Intl.NumberFormat(i18n.global.locale.value, {
    style: 'percent',
    maximumFractionDigits: 0,
  }).format(part / whole)
}

export function num(n: number, digits = 0) {
  return new Intl.NumberFormat(i18n.global.locale.value, { maximumFractionDigits: digits }).format(
    n,
  )
}

export function when(unixOrIso: number | string) {
  const d = typeof unixOrIso === 'number' ? new Date(unixOrIso * 1000) : new Date(unixOrIso)
  if (isNaN(d.getTime()) || d.getFullYear() < 2000) return '—'
  return new Intl.DateTimeFormat(i18n.global.locale.value, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(d)
}

export function asnLabel(asn: number, org: string) {
  if (!asn) return i18n.global.t('matrix.otherAsn')
  return org ? `AS${asn} · ${org}` : `AS${asn}`
}

// asnTagged is a network's AS number with its short name beside it, the
// number alone when it has no name.
export function asnTagged(asn: number, org: string) {
  if (!asn) return i18n.global.t('matrix.otherAsn')
  return org ? `AS${asn} (${asnName(asn, org)})` : `AS${asn}`
}

// asnShort is a network's short name (asn.ts), the "other" bucket's in the
// admin's language. The full name and number are asnLabel's, for a tooltip.
export function asnShort(asn: number, org: string) {
  if (!asn) return i18n.global.t('matrix.otherAsn')
  return asnName(asn, org)
}

// countryName is a country's name in the admin's language, its code when
// the browser has none.
export function countryName(code: string) {
  try {
    return (
      new Intl.DisplayNames([i18n.global.locale.value], { type: 'region' }).of(
        code.toUpperCase(),
      ) ?? code
    )
  } catch {
    return code
  }
}

// health is a success ratio's band, for the cell's colour.
export function health(authed: number, accepted: number, degraded: boolean) {
  if (degraded) return 'bad'
  if (accepted < 5) return 'none'
  const r = authed / accepted
  if (r >= 0.9) return 'good'
  if (r >= 0.6) return 'fair'
  return 'bad'
}
