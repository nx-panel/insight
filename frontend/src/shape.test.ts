// Run by `npm run test` (node --test, no dependency).
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { handshakeOnly } from './shape.ts'

test('handshakeOnly is a WireGuard endpoint and nothing else', () => {
  assert.equal(handshakeOnly({ kind: 'endpoint', type: 'wireguard' }), true)
  assert.equal(handshakeOnly({ kind: 'endpoint', type: 'openvpn-server' }), false)
  assert.equal(handshakeOnly({ kind: 'endpoint', type: 'openconnect-server' }), false)
  assert.equal(handshakeOnly({ kind: 'inbound', type: 'vless' }), false)
})
