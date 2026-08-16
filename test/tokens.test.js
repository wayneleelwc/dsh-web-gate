import test from 'node:test'
import assert from 'node:assert/strict'
import { mintSession, verifyToken, RevocationList } from '../src/tokens.js'
import { randomSecret } from '../src/crypto.js'

const secret = randomSecret()
const T0 = 1_000_000 // epoch ms

test('mint and verify access + refresh tokens', () => {
  const s = mintSession({ secret, sub: 'admin', pv: 1, accessTtlSeconds: 3600, refreshTtlSeconds: 86400, now: T0 })
  assert.ok(s.accessToken)
  assert.ok(s.refreshToken)
  const nowSec = Math.floor(T0 / 1000)
  const ap = verifyToken({ token: s.accessToken, secret, kind: 'access', pv: 1, nowSeconds: nowSec })
  assert.equal(ap.sub, 'admin')
  assert.equal(ap.kind, 'access')
  // wrong kind rejected
  assert.equal(verifyToken({ token: s.accessToken, secret, kind: 'refresh', pv: 1, nowSeconds: nowSec }), null)
  // wrong pv rejected
  assert.equal(verifyToken({ token: s.accessToken, secret, kind: 'access', pv: 2, nowSeconds: nowSec }), null)
})

test('expired token rejected', () => {
  const s = mintSession({ secret, sub: 'admin', pv: 1, accessTtlSeconds: 10, refreshTtlSeconds: 100, now: T0 })
  const nowSec = Math.floor(T0 / 1000) + 11
  assert.equal(verifyToken({ token: s.accessToken, secret, kind: 'access', pv: 1, nowSeconds: nowSec }), null)
  // refresh still valid
  assert.ok(verifyToken({ token: s.refreshToken, secret, kind: 'refresh', pv: 1, nowSeconds: nowSec }))
})

test('tampered token rejected', () => {
  const s = mintSession({ secret, sub: 'admin', pv: 1, accessTtlSeconds: 3600, refreshTtlSeconds: 86400, now: T0 })
  const nowSec = Math.floor(T0 / 1000)
  assert.equal(verifyToken({ token: s.accessToken.slice(0, -3) + 'abc', secret, kind: 'access', pv: 1, nowSeconds: nowSec }), null)
})

test('revocation list prunes by expiry', () => {
  const rl = new RevocationList()
  rl.add('abc', 100)
  assert.equal(rl.isRevoked('abc'), true)
  assert.equal(rl.isRevoked('xyz'), false)
  rl.prune(101)
  assert.equal(rl.isRevoked('abc'), false)
})
