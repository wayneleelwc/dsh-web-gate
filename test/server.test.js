import test from 'node:test'
import assert from 'node:assert/strict'
import { startUpstream, startGateway, login, rawUpgrade } from './helpers.js'

test('unauthenticated navigation redirects to /login; /api returns 401', async () => {
  const up = await startUpstream()
  const gw = await startGateway({ upstreamPort: up.port })
  try {
    const nav = await fetch(`${gw.base}/`, { redirect: 'manual' })
    assert.equal(nav.status, 302)
    assert.match(nav.headers.get('location'), /\/login/)

    const deep = await fetch(`${gw.base}/some/deep/link`, { redirect: 'manual' })
    assert.equal(deep.status, 302)
    assert.match(deep.headers.get('location'), /next=%2Fsome%2Fdeep%2Flink/)

    const api = await fetch(`${gw.base}/api/anything`, { redirect: 'manual' })
    assert.equal(api.status, 401)
    assert.equal(api.headers.get('content-type').includes('application/json'), true)
  } finally {
    await gw.stop()
    await up.stop()
  }
})

test('login page renders and rejects wrong passwords', async () => {
  const up = await startUpstream()
  const gw = await startGateway({ upstreamPort: up.port })
  try {
    const page = await fetch(`${gw.base}/login`)
    assert.equal(page.status, 200)
    assert.match(await page.text(), /DeepSeek Harness Web Gate/)

    const bad = await fetch(`${gw.base}/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'password=wrong',
      redirect: 'manual',
    })
    assert.equal(bad.status, 401)
  } finally {
    await gw.stop()
    await up.stop()
  }
})

test('authenticated requests are proxied with the original Host preserved', async () => {
  const up = await startUpstream()
  const gw = await startGateway({ upstreamPort: up.port })
  try {
    const { status, cookieHeader } = await login(gw.base)
    assert.equal(status, 303)
    const res = await fetch(`${gw.base}/hello?x=1`, { headers: { cookie: cookieHeader } })
    assert.equal(res.status, 200)
    const body = await res.json()
    assert.equal(body.url, '/hello?x=1')
    assert.equal(body.host, new URL(gw.base).host)
    assert.equal(body.cookie, null) // gateway cookies are not forwarded
  } finally {
    await gw.stop()
    await up.stop()
  }
})

test('SSE streams through the gate', async () => {
  const up = await startUpstream()
  const gw = await startGateway({ upstreamPort: up.port })
  try {
    const { cookieHeader } = await login(gw.base)
    const res = await fetch(`${gw.base}/sse`, { headers: { cookie: cookieHeader } })
    assert.equal(res.status, 200)
    assert.match(res.headers.get('content-type'), /text\/event-stream/)
    const text = await res.text()
    assert.match(text, /data: one/)
    assert.match(text, /data: two/)
  } finally {
    await gw.stop()
    await up.stop()
  }
})

test('logout clears the session', async () => {
  const up = await startUpstream()
  const gw = await startGateway({ upstreamPort: up.port })
  try {
    const { cookieHeader } = await login(gw.base)
    const before = await fetch(`${gw.base}/hello`, { headers: { cookie: cookieHeader }, redirect: 'manual' })
    assert.equal(before.status, 200)
    const logout = await fetch(`${gw.base}/auth/logout`, {
      method: 'POST',
      headers: { cookie: cookieHeader, origin: gw.base },
      redirect: 'manual',
    })
    assert.equal(logout.status, 303)
    const after = await fetch(`${gw.base}/hello`, { redirect: 'manual' })
    assert.equal(after.status, 302)
  } finally {
    await gw.stop()
    await up.stop()
  }
})

test('change password invalidates the old password and old sessions', async () => {
  const up = await startUpstream()
  const gw = await startGateway({ upstreamPort: up.port })
  try {
    const { cookieHeader } = await login(gw.base)
    const res = await fetch(`${gw.base}/auth/change-password`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: cookieHeader, origin: gw.base },
      body: 'current=test-password&password=new-password-1&confirm=new-password-1',
      redirect: 'manual',
    })
    assert.equal(res.status, 200)
    assert.match(await res.text(), /口令已更新/)
    // old password no longer works
    assert.equal((await login(gw.base, 'test-password')).status, 401)
    // new password works
    assert.equal((await login(gw.base, 'new-password-1')).status, 303)
  } finally {
    await gw.stop()
    await up.stop()
  }
})

test('login brute force is rate-limited', async () => {
  const up = await startUpstream()
  const gw = await startGateway({ upstreamPort: up.port })
  try {
    // The default limit is 5 failures; exceed it.
    for (let i = 0; i < 6; i += 1) {
      await fetch(`${gw.base}/auth/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'password=wrong',
        redirect: 'manual',
      })
    }
    const blocked = await fetch(`${gw.base}/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'password=test-password',
      redirect: 'manual',
    })
    assert.equal(blocked.status, 429)
  } finally {
    await gw.stop()
    await up.stop()
  }
})

test('websocket upgrade is gated and proxied', async () => {
  const up = await startUpstream()
  const gw = await startGateway({ upstreamPort: up.port })
  try {
    const unauth = await rawUpgrade(gw.port, '/echo')
    assert.match(unauth, /HTTP\/1\.1 401/)

    const { cookieHeader } = await login(gw.base)
    const authed = await rawUpgrade(gw.port, '/echo', { Cookie: cookieHeader })
    assert.match(authed, /HTTP\/1\.1 101/)
    assert.match(authed, /upgrade: websocket/i)
  } finally {
    await gw.stop()
    await up.stop()
  }
})

test('security headers are present on gate pages', async () => {
  const up = await startUpstream()
  const gw = await startGateway({ upstreamPort: up.port })
  try {
    const res = await fetch(`${gw.base}/login`)
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff')
    assert.equal(res.headers.get('x-frame-options'), 'DENY')
    assert.match(res.headers.get('content-security-policy'), /default-src 'none'/)
  } finally {
    await gw.stop()
    await up.stop()
  }
})

test('X-Forwarded-For is overwritten (not spoofable) without trustProxy', async () => {
  const up = await startUpstream()
  const gw = await startGateway({ upstreamPort: up.port })
  try {
    const { cookieHeader } = await login(gw.base)
    const res = await fetch(`${gw.base}/xff`, {
      headers: { cookie: cookieHeader, 'x-forwarded-for': '6.6.6.6' },
    })
    const body = await res.json()
    assert.equal(body.xff, '127.0.0.1')
  } finally {
    await gw.stop()
    await up.stop()
  }
})

test('X-Forwarded-For appends the chain with trustProxy', async () => {
  const up = await startUpstream()
  const gw = await startGateway({ upstreamPort: up.port, trustProxy: true })
  try {
    const { cookieHeader } = await login(gw.base)
    const res = await fetch(`${gw.base}/xff`, {
      headers: { cookie: cookieHeader, 'x-forwarded-for': '6.6.6.6' },
    })
    const body = await res.json()
    assert.match(body.xff, /^6\.6\.6\.6, 127\.0\.0\.1$/)
  } finally {
    await gw.stop()
    await up.stop()
  }
})

test('HEAD requests are proxied without a body', async () => {
  const up = await startUpstream()
  const gw = await startGateway({ upstreamPort: up.port })
  try {
    const { cookieHeader } = await login(gw.base)
    const res = await fetch(`${gw.base}/anything`, { method: 'HEAD', headers: { cookie: cookieHeader } })
    assert.equal(res.status, 200)
    assert.equal(await res.text(), '')
  } finally {
    await gw.stop()
    await up.stop()
  }
})

test('oversized login body returns 413', async () => {
  const up = await startUpstream()
  const gw = await startGateway({ upstreamPort: up.port })
  try {
    const big = 'x'.repeat(70 * 1024)
    const res = await fetch(`${gw.base}/auth/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `password=${big}`,
      redirect: 'manual',
    })
    assert.equal(res.status, 413)
  } finally {
    await gw.stop()
    await up.stop()
  }
})
