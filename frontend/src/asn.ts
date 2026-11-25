// A network's short name, with nothing to load: format.ts's asnShort is it
// for every network but the "other" bucket, and asn.test.ts runs it
// under plain Node.

// asnName is a network's short name: the first word of its registered name
// without the "-AS" every registry tacks on ("MCCI-AS Mobile Communication
// Company of Iran PLC" is MCCI), or its number when it has no name. The
// suffix goes only behind a separator, so "ATLAS" and "MIDAS" keep their
// letters.
export function asnName(asn: number, org: string) {
  const first = (org || '').trim().split(/[\s,]+/)[0] ?? ''
  const short = first.replace(/[-_]ASN?[-_]?\d*$/i, '').replace(/[-_]+$/, '')
  return short || first || `AS${asn}`
}
