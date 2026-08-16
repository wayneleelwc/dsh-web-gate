import test from 'node:test'
import assert from 'node:assert/strict'
import { resolveConfig } from '../src/config.js'

test('resolveConfig merges defaults and validates successfully', () => {
  const config = resolveConfig({ env: {}, overrides: { port: 0, upstreamPort: 4000 } })
  assert.equal(config.listen.port, 0)
  assert.equal(config.upstream.port, 4000)
  assert.equal(config.session.cookieName, 'dsh_web_gate')
  assert.equal(config.insecure, false)
})

test('environment variables take precedence over defaults', () => {
  const config = resolveConfig({
    env: { DSH_WEB_GATE_PORT: '4444', DSH_WEB_GATE_UPSTREAM_PORT: '4445', DSH_WEB_GATE_INSECURE: '1' },
  })
  assert.equal(config.listen.port, 4444)
  assert.equal(config.upstream.port, 4445)
  assert.equal(config.insecure, true)
})

test('CLI overrides take precedence over environment', () => {
  const config = resolveConfig({ env: { DSH_WEB_GATE_PORT: '4444' }, overrides: { port: 5000 } })
  assert.equal(config.listen.port, 5000)
})

test('invalid ports are rejected', () => {
  assert.throws(() => resolveConfig({ env: {}, overrides: { port: 70000 } }), /invalid listen\.port/)
  assert.throws(() => resolveConfig({ env: { DSH_WEB_GATE_UPSTREAM_PORT: '-1' } }), /invalid upstream\.port/)
})

test('invalid forwardHost is rejected', () => {
  assert.throws(() => resolveConfig({ env: { DSH_WEB_GATE_FORWARD_HOST: 'bogus' } }), /forwardHost/)
})

test('custom username is honored', () => {
  const config = resolveConfig({ env: { DSH_WEB_GATE_USERNAME: 'ops' } })
  assert.equal(config.session.username, 'ops')
})

test('invalid cookieName is rejected', () => {
  assert.throws(() => resolveConfig({ env: { DSH_WEB_GATE_COOKIE_NAME: 'bad name' } }), /cookieName/)
})

test('SameSite=None without Secure is rejected', () => {
  assert.throws(() => resolveConfig({ env: { DSH_WEB_GATE_COOKIE_SAMESITE: 'None' } }), /SameSite=None/)
})

test('refresh TTL shorter than access TTL is rejected', () => {
  assert.throws(() => resolveConfig({ env: { DSH_WEB_GATE_ACCESS_TTL: '3600', DSH_WEB_GATE_REFRESH_TTL: '60' } }), /refreshTtlSeconds/)
})

test('invalid rate-limit parameters are rejected', () => {
  assert.throws(() => resolveConfig({ env: { DSH_WEB_GATE_LOGIN_MAX_ATTEMPTS: '0' } }), /maxAttempts/)
  assert.throws(() => resolveConfig({ env: { DSH_WEB_GATE_LOGIN_LOCKOUT_MS: '-5' } }), /lockoutMs/)
})

test('logRequests and trustProxy are resolved from env', () => {
  const config = resolveConfig({ env: { DSH_WEB_GATE_TRUST_PROXY: '1', DSH_WEB_GATE_LOG_REQUESTS: 'true' } })
  assert.equal(config.trustProxy, true)
  assert.equal(config.logRequests, true)
})

test('non-numeric integer values fail loud', () => {
  assert.throws(() => resolveConfig({ env: { DSH_WEB_GATE_PORT: 'abc' } }), /expected an integer/)
  assert.throws(() => resolveConfig({ env: { DSH_WEB_GATE_ACCESS_TTL: 'soon' } }), /expected an integer/)
})

test('invalid boolean values fail loud', () => {
  assert.throws(() => resolveConfig({ env: { DSH_WEB_GATE_INSECURE: 'maybe' } }), /expected a boolean/)
})
