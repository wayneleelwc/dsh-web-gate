import test from 'node:test'
import assert from 'node:assert/strict'
import { parseCookies, serializeCookie, parseForm, createGate } from '../src/auth.js'
import { hashPassword } from '../src/crypto.js'
import { RevocationList, mintSession } from '../src/tokens.js'

const BASE_SESSION = {
  username: 'admin',
  accessTtlSeconds: 3600,
  refreshTtlSeconds: 86400,
  cookieName: 'gate',
  cookieSecure: false,
  cookieSameSite: 'Strict',
}

function makeGate({ session = {}, rateLimit = {}, ...rest } = {}) {
  const baseRate = {
    login: { windowMs: 60000, maxAttempts: 5, lockoutMs: 60000 },
    global: { enabled: false, capacity: 60, refillPerSecond: 30 },
  }
  const config = {
    session: { ...BASE_SESSION, ...session },
    rateLimit: {
      ...baseRate,
      ...rateLimit,
      login: { ...baseRate.login, ...(rateLimit.login ?? {}) },
    },
    insecure: false,
    ...rest,
  }
  const state = { secret: 'x'.repeat(32), pv: 1, passwordHash: hashPassword('secret-password'), version: 1 }
  let persisted = false
  const gate = createGate({ config, state, revocation: new RevocationList(), persist: async () => { persisted = true } })
  return { gate, state, persisted: () => persisted }
}

function accessTokenFromCookies(cookies) {
  return cookies[0].split(';')[0].split('=')[1]
}

test('parseCookies parses and tolerates absence', () => {
  assert.deepEqual(parseCookies('a=1; b=2'), { a: '1', b: '2' })
  assert.deepEqual(parseCookies(undefined), {})
  assert.deepEqual(parseCookies('a=1;b'), { a: '1' })
})

test('serializeCookie emits HttpOnly SameSite and Max-Age', () => {
  const cookie = serializeCookie('n', 'v', { maxAge: 10 })
  assert.match(cookie, /^n=v; /)
  assert.match(cookie, /HttpOnly/)
  assert.match(cookie, /SameSite=Strict/)
  assert.match(cookie, /Max-Age=10/)
  const secure = serializeCookie('n', 'v', { maxAge: 0, secure: true })
  assert.match(secure, /Secure/)
  assert.match(secure, /Max-Age=0/)
})

test('parseForm decodes urlencoded bodies', () => {
  assert.deepEqual(parseForm('password=hello+world&remember=1'), { password: 'hello world', remember: '1' })
  assert.deepEqual(parseForm('a=1&a=2&empty='), { a: '2', empty: '' })
})

test('parseForm tolerates malformed percent-encoding', () => {
  assert.deepEqual(parseForm('password=%zz&remember=1'), { password: '%zz', remember: '1' })
})

test('authenticate rejects without cookies', () => {
  const { gate } = makeGate()
  assert.equal(gate.authenticate({ headers: {} }).ok, false)
})

test('login rejects a wrong password and accepts the right one', async () => {
  const { gate } = makeGate()
  const bad = await gate.login({ password: 'wrong', remember: true, clientKey: 'ip' })
  assert.equal(bad.status, 401)
  assert.equal(bad.cookies, undefined)
  const good = await gate.login({ password: 'secret-password', remember: true, clientKey: 'ip' })
  assert.equal(good.status, 200)
  assert.equal(good.cookies.length, 2)
})

test('login without remember mints only the access cookie', async () => {
  const { gate } = makeGate()
  const res = await gate.login({ password: 'secret-password', remember: false, clientKey: 'ip' })
  assert.equal(res.cookies.length, 1)
})

test('login is rate-limited per client key', async () => {
  const { gate } = makeGate({ rateLimit: { login: { windowMs: 60000, maxAttempts: 2, lockoutMs: 60000 } } })
  await gate.login({ password: 'wrong', remember: false, clientKey: 'ip' })
  await gate.login({ password: 'wrong', remember: false, clientKey: 'ip' })
  const blocked = await gate.login({ password: 'secret-password', remember: false, clientKey: 'ip' })
  assert.equal(blocked.status, 429)
})

test('authenticate rotates an expired access token from a valid refresh token', () => {
  const secret = 's'.repeat(32)
  const state = { secret, pv: 1, passwordHash: hashPassword('pw') }
  const config = {
    session: BASE_SESSION,
    rateLimit: { login: { windowMs: 60000, maxAttempts: 5, lockoutMs: 60000 }, global: { enabled: false } },
    insecure: false,
  }
  const gate = createGate({ config, state, revocation: new RevocationList(), persist: async () => {} })
  const minted = mintSession({ secret, sub: 'admin', pv: 1, accessTtlSeconds: -10, refreshTtlSeconds: 3600 })
  const req = { headers: { cookie: `gate_access=${minted.accessToken}; gate_refresh=${minted.refreshToken}` } }
  const res = gate.authenticate(req)
  assert.equal(res.ok, true)
  assert.equal(res.rotated.length, 2)
})
test('change password bumps pv and invalidates prior tokens', async () => {
  const { gate, state, persisted } = makeGate()
  const login = await gate.login({ password: 'secret-password', remember: true, clientKey: 'ip' })
  const token = accessTokenFromCookies(login.cookies)
  const req = { headers: { cookie: `gate_access=${token}` } }
  assert.equal(gate.authenticate(req).ok, true)
  const before = state.pv
  const res = await gate.changePassword({ current: 'secret-password', password: 'new-password-1', confirm: 'new-password-1' })
  assert.equal(res.status, 200)
  assert.equal(state.pv, before + 1)
  assert.equal(persisted(), true)
  assert.equal(gate.authenticate(req).ok, false)
  const relogin = await gate.login({ password: 'new-password-1', remember: true, clientKey: 'ip' })
  assert.equal(relogin.status, 200)
})

test('change password rejects mismatched confirm and short passwords', async () => {
  const { gate } = makeGate()
  assert.equal((await gate.changePassword({ current: 'secret-password', password: 'a'.repeat(9), confirm: 'b'.repeat(9) })).status, 400)
  assert.equal((await gate.changePassword({ current: 'secret-password', password: 'short', confirm: 'short' })).status, 400)
  assert.equal((await gate.changePassword({ current: 'wrong-current', password: 'a'.repeat(9), confirm: 'a'.repeat(9) })).status, 401)
})

test('insecure mode authenticates every request', () => {
  const { gate } = makeGate({ insecure: true })
  const res = gate.authenticate({ headers: {} })
  assert.equal(res.ok, true)
  assert.equal(res.payload.insecure, true)
})
