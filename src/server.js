/**
 * HTTP server wiring: dispatches the gateway's own auth endpoints, gates every
 * other request, and proxies authenticated traffic (HTTP + WebSocket upgrade)
 * to the upstream DSH Web GUI.
 */

import { createServer } from 'node:http'
import { createGate, parseForm, readBody } from './auth.js'
import { proxyHttp, proxyUpgrade } from './proxy.js'
import { loginPage, settingsPage } from './pages.js'
import { securityHeaders } from './headers.js'

const PAGE_HEADERS = { 'content-type': 'text/html; charset=utf-8', ...securityHeaders() }
const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8', ...securityHeaders() }

function writeHtml(res, status, html, extra = {}) {
  res.writeHead(status, { ...PAGE_HEADERS, ...extra })
  res.end(html)
}

function writeJson(res, status, obj) {
  res.writeHead(status, { ...JSON_HEADERS, ...securityHeaders() })
  res.end(JSON.stringify(obj))
}

function clientKey(req, trustProxy) {
  if (trustProxy) {
    const xff = req.headers['x-forwarded-for']
    if (typeof xff === 'string' && xff) return xff.split(',')[0].trim()
  }
  return req.socket?.remoteAddress ?? 'unknown'
}

/** A `next` value is safe only when it is a same-origin absolute path. */
function isSafeNext(next) {
  return typeof next === 'string' && next.startsWith('/') && !next.startsWith('//')
}

/** Same-origin check for the gate's own state-changing endpoints. */
function isSameOrigin(req) {
  const origin = req.headers.origin
  if (!origin) return true
  const host = req.headers.host
  try {
    return new URL(origin).host === host
  } catch {
    return false
  }
}

/**
 * Create the gateway server.
 * @param {object} args
 * @param {object} args.config - resolved config.
 * @param {object} args.state - mutable state.
 * @param {import('./tokens.js').RevocationList} args.revocation
 * @param {() => Promise<void>} args.persist - persists state to disk.
 * @param {Pick<Console, 'log'|'error'|'warn'>} [args.logger]
 */
export function createGateway({ config, state, revocation, persist, logger = console }) {
  const gate = createGate({ config, state, revocation, persist })
  const { upstream, trustProxy, session } = config

  const server = createServer((req, res) => {
    if (config.logRequests) {
      const startedAt = Date.now()
      res.on('finish', () => {
        logger.log?.(`${req.method ?? 'GET'} ${req.url ?? '/'} ${res.statusCode} ${clientKey(req, trustProxy)} ${Date.now() - startedAt}ms`)
      })
    }
    handle(req, res).catch((err) => {
      logger.error?.(err instanceof Error ? err : new Error(String(err)))
      if (!res.headersSent) {
        const body = 'Internal Server Error\n'
        res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8', 'content-length': Buffer.byteLength(body) })
        res.end(body)
        return
      }
      res.end()
    })
  })

  async function handle(req, res) {
    const url = new URL(req.url ?? '/', 'http://gate.internal')
    const path = url.pathname
    const method = req.method ?? 'GET'

    if (!gate.allowGlobal(clientKey(req, trustProxy))) {
      writeJson(res, 429, { error: 'too many requests' })
      return
    }

    if (method === 'POST' && path === '/auth/login') {
      await handleLogin(req, res, url)
      return
    }

    if (method === 'POST' && path === '/auth/logout') {
      if (!isSameOrigin(req)) return writeJson(res, 403, { error: 'forbidden' })
      const cookies = gate.logout(req)
      res.writeHead(303, { location: '/login', 'set-cookie': cookies })
      res.end()
      return
    }

    if (method === 'POST' && path === '/auth/change-password') {
      if (!isSameOrigin(req)) return writeJson(res, 403, { error: 'forbidden' })
      await handleChangePassword(req, res)
      return
    }

    if (method === 'GET' && path === '/login') {
      const auth = gate.authenticate(req)
      if (auth.ok) {
        res.writeHead(302, { location: '/' })
        res.end()
        return
      }
      const next = url.searchParams.get('next') ?? ''
      writeHtml(res, 200, loginPage({ next: isSafeNext(next) ? next : '' }))
      return
    }

    if (method === 'GET' && path === '/settings') {
      const auth = gate.authenticate(req)
      if (!auth.ok) {
        res.writeHead(302, { location: '/login?next=/settings' })
        res.end()
        return
      }
      writeHtml(res, 200, settingsPage({ username: session.username }))
      return
    }

    if (method === 'GET' && path === '/healthz') {
      res.writeHead(200, { 'content-type': 'text/plain' })
      res.end('ok\n')
      return
    }

    // Everything else: authenticate, then proxy.
    const auth = gate.authenticate(req)
    if (!auth.ok) {
      if (path === '/api' || path.startsWith('/api/')) {
        writeJson(res, 401, { error: 'unauthorized' })
        return
      }
      const next = path === '/' ? '' : path + url.search
      const target = next ? `/login?next=${encodeURIComponent(next)}` : '/login'
      res.writeHead(302, { location: target })
      res.end()
      return
    }
    proxyHttp(req, res, upstream, {
      forwardHost: config.upstream.forwardHost,
      trustProxy,
      extraSetCookies: auth.rotated ?? [],
      stripCookies: [gate.cookieNames.access, gate.cookieNames.refresh],
    })
  }

  async function handleLogin(req, res, url) {
    if (!isSameOrigin(req)) return writeJson(res, 403, { error: 'forbidden' })
    let body
    try {
      body = await readBody(req)
    } catch {
      return writeJson(res, 413, { error: 'payload too large' })
    }
    const form = parseForm(body)
    const result = await gate.login({
      password: form.password ?? '',
      remember: form.remember === '1',
      clientKey: clientKey(req, trustProxy),
    })
    const next = isSafeNext(form.next) ? form.next : '/'
    if (result.status === 200) {
      res.writeHead(303, { location: next, 'set-cookie': result.cookies })
      res.end()
      return
    }
    writeHtml(res, result.status, loginPage({ error: result.error ?? '登录失败', next }))
  }

  async function handleChangePassword(req, res) {
    let body
    try {
      body = await readBody(req)
    } catch {
      return writeJson(res, 413, { error: 'payload too large' })
    }
    const form = parseForm(body)
    const result = await gate.changePassword({
      current: form.current ?? '',
      password: form.password ?? '',
      confirm: form.confirm ?? '',
    })
    if (result.status === 200) {
      writeHtml(res, 200, settingsPage({ success: result.success, username: session.username }), { 'set-cookie': result.cookies })
      return
    }
    writeHtml(res, result.status, settingsPage({ error: result.error, username: session.username }))
  }

  // Upgraded (WebSocket) sockets are detached from Node's connection
  // tracking, so server.close()/closeAllConnections() do not close them; the
  // gateway tracks them explicitly to guarantee shutdown terminates.
  const upgradedSockets = new Set()

  server.on('upgrade', (req, socket, head) => {
    upgradedSockets.add(socket)
    socket.on('close', () => upgradedSockets.delete(socket))
    const auth = gate.authenticate(req)
    if (!auth.ok) {
      socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n')
      socket.destroy()
      return
    }
    proxyUpgrade(req, socket, head, upstream, {
      forwardHost: config.upstream.forwardHost,
      trustProxy,
      extraSetCookies: auth.rotated ?? [],
      stripCookies: [gate.cookieNames.access, gate.cookieNames.refresh],
    })
  })

  /** Listen and resolve with the bound address. */
  function listen() {
    return new Promise((resolve, reject) => {
      server.once('error', reject)
      server.listen(config.listen.port, config.listen.host, () => {
        server.off('error', reject)
        const addr = server.address()
        resolve({ host: addr.address, port: addr.port })
      })
    })
  }

  /** Stop accepting connections and destroy upgraded + keep-alive sockets. */
  function close() {
    return new Promise((resolve) => {
      for (const socket of upgradedSockets) socket.destroy()
      server.close(() => resolve())
      server.closeAllConnections()
    })
  }

  return { server, gate, listen, close }
}
