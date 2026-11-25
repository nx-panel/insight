// What a node's shape says of how its cells count, kept free of imports
// so `npm run test` runs it under Node.

// handshakeOnly: a WireGuard endpoint, whose cells count only the
// handshakes that worked (the matrix serves them with kind 'endpoint'); an
// OpenVPN or OpenConnect endpoint counts accepted and failed like an
// inbound.
export const handshakeOnly = (s: { kind: string; type: string }) =>
  s.kind === 'endpoint' && s.type === 'wireguard'
