/** Shared test helpers: a fake upstream (HTTP + WebSocket echo) and a gateway starter. */

import { createServer } from 'node:http'
import { connect } from 'node:net'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { resolveConfig } from '../src/config.js'
import { emptyState, saveState } from '../src/state.js'
import { hashPassword } from '../src/crypto.js'
import { RevocationList } from '../src/tokens.js'
import { createGateway } from '../src/server.js'

/** Force-close an http.Server, destroying upgraded sockets and keep-alive connections. */
export async function stop(server, upgraded = []) {
  if (!server) return
  for (const socket of upgraded) socket.destroy()
  if (typeof server.closeAllConnections === 'function') server.closeAllConnections()
  await new Promise((resolve) => server.close(resolve))
}

/** Start a fake upstream that echoes requests and supports an SSE-ish route. */
export async function startUpstream() {
  const server = createServer((req, res) => {
    if (req.url === '/sse') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache' })
      res.write('data: one\n\n')
      setTimeout(() => res.end('data: two\n\n'), 5)
      return
    }
    res.writeHead(200, { 'content-type': 'application/json', 'x-upstream': 'yes' })
    res.end(JSON.stringify({ method: req.method, url: req.url, host: req.headers.host, cookie: req.headers.cookie ?? null, xff: req.headers['x-forwarded-for'] ?? null }))
  })
  const upgraded = new Set()
  server.on('upgrade', (req, socket) => {
    upgraded.add(socket)
    socket.on('close', () => upgraded.delete(socket))
    socket.write('HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: test\r\n\r\n')
    socket.on('data', (d) => socket.write(d))
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  return { server, port: server.address().port, stop: () => stop(server, upgraded) }
}

/** Start a gateway bound to an ephemeral port, proxying to `upstreamPort`. */
export async function startGateway({ upstreamPort, password = 'test-password', trustProxy = false, logRequests = false, forwardHost = 'preserve' }) {
  const dir = await mkdtemp(join(tmpdir(), 'dsh-web-gate-'))
  const stateFile = join(dir, 'state.json')
  const state = emptyState()
  state.passwordHash = hashPassword(password)
  const config = resolveConfig({
    env: {},
    overrides: { upstreamPort, state: stateFile, port: 0, host: '127.0.0.1', trustProxy, logRequests, forwardHost },
  })
  const revocation = new RevocationList()
  const gateway = createGateway({
    config,
    state,
    revocation,
    persist: () => saveState(stateFile, state),
  })
  const addr = await gateway.listen()
  return { gateway, base: `http://127.0.0.1:${addr.port}`, port: addr.port, state, stateFile, stop: () => gateway.close() }
}

/** Log in against a gateway and return the Cookie header value. */
export async function login(base, password = 'test-password', remember = true) {
  const res = await fetch(`${base}/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: `password=${encodeURIComponent(password)}${remember ? '&remember=1' : ''}`,
    redirect: 'manual',
  })
  const cookies = res.headers.getSetCookie ? res.headers.getSetCookie() : []
  return { status: res.status, cookies, cookieHeader: cookies.map((c) => c.split(';')[0]).join('; ') }
}

/** Perform a raw HTTP Upgrade handshake and return the response head. */
export function rawUpgrade(port, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const socket = connect(port, '127.0.0.1')
    let buffer = ''
    const extra = Object.entries(headers)
      .map(([k, v]) => `${k}: ${v}\r\n`)
      .join('')
    const request =
      `GET ${path} HTTP/1.1\r\n` +
      `Host: 127.0.0.1:${port}\r\n` +
      'Connection: Upgrade\r\n' +
      'Upgrade: websocket\r\n' +
      'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n' +
      'Sec-WebSocket-Version: 13\r\n' +
      `${extra}\r\n`
    socket.on('data', (d) => {
      buffer += d.toString()
      if (buffer.includes('\r\n\r\n')) {
        socket.destroy()
        resolve(buffer)
      }
    })
    socket.on('error', reject)
    socket.on('close', () => resolve(buffer))
    socket.write(request)
  })
}
