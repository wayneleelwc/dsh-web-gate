import test from 'node:test'
import assert from 'node:assert/strict'
import { hashPassword, verifyPassword, randomSecret, signToken, unsignToken } from '../src/crypto.js'

test('hashPassword produces a scrypt hash that verifies', async () => {
  const hash = hashPassword('correct-horse-battery')
  assert.match(hash, /^scrypt\$16384\$8\$1\$/)
  assert.equal(await verifyPassword('correct-horse-battery', hash), true)
  assert.equal(await verifyPassword('wrong', hash), false)
  assert.equal(await verifyPassword('', hash), false)
})

test('verifyPassword rejects malformed hashes', async () => {
  assert.equal(await verifyPassword('x', ''), false)
  assert.equal(await verifyPassword('x', 'bcrypt$foo'), false)
  assert.equal(await verifyPassword('x', 'scrypt$notanum$8$1$YWJj$YWJj'), false)
  assert.equal(await verifyPassword('x', 'scrypt$16384$8$1$!!$!!'), false)
})

test('sign/unsign round trip and tamper detection', () => {
  const secret = randomSecret()
  const payload = { sub: 'admin', kind: 'access', exp: 123 }
  const token = signToken(payload, secret)
  assert.deepEqual(unsignToken(token, secret), payload)
  assert.equal(unsignToken(token, randomSecret()), null)
  assert.equal(unsignToken(token.slice(0, -2) + 'xx', secret), null)
  assert.equal(unsignToken('not-a-token', secret), null)
  assert.equal(unsignToken('', secret), null)
})

test('randomSecret returns distinct base64 secrets', () => {
  const a = randomSecret()
  const b = randomSecret()
  assert.notEqual(a, b)
  assert.ok(a.length >= 32)
})
