// Run by `npm run test` (node --test, no dependency). Node resolves only
// the file as named, hence the extension.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { asnName } from './asn.ts'

test('asnName keeps the operator and drops the AS suffix', () => {
  const cases: [number, string, string][] = [
    [197207, 'MCI-AS', 'MCI'],
    [44244, 'IRANCELL-AS', 'IRANCELL'],
    [14061, 'DIGITALOCEAN-ASN', 'DIGITALOCEAN'],
    [58224, 'TCI-AS12', 'TCI'],
    [20473, 'AS-CHOOPA', 'AS-CHOOPA'],
    [43754, 'IR-ASIATECH', 'IR-ASIATECH'],
    [16276, 'OVH_AS16276', 'OVH'],
    [12345, 'AS12345', 'AS12345'],
    [3356, 'Level3', 'Level3'],
    [1, 'ATLAS', 'ATLAS'],
    [2, 'MIDAS', 'MIDAS'],
    [64500, '', 'AS64500'],
  ]
  for (const [asn, org, want] of cases) assert.equal(asnName(asn, org), want, `${org}`)
})
