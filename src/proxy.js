/**
 * Minimal reverse proxy over `node:http`: forwards HTTP (including streaming
 * SSE bodies) and WebSocket upgrades to the upstream DSH Web GUI, preserving
 * the original Host header so the DSH `/api` trust fence keeps seeing the
 * gateway's authority (loopback works out of the box; non-loopback deployments
 * register the gateway authority with `dsh web --trusted-host`).
 */

import { request as httpRequest } from 'node:http'

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

/** Drop specific cookie names from a Cookie header (the gate's own auth cookies). */
function stripCookieHeader(header, names) {
  if (!header || names.length === 0) return header
  const kept = []
  for (const part of String(header).split(';')) {
    const idx = part.indexOf('=')
    const name = idx === -1 ? part.trim() : part.slice(0, idx).trim()
    if (!name || names.includes(name)) continue
    kept.push(part.trim())
  }
  return kept.join('; ')
}

/**
 * Build upstream headers: drop hop-by-hop, rewrite Host per policy, and set
 * the X-Forwarded-* chain. When `trustProxy` is false, client-supplied
 * `x-forwarded-*` values are ignored (overwritten) so a client cannot spoof
 * them; when true, the trusted proxy's chain is appended to.
 */
function buildUpstreamHeaders(req, upstream, { forwardHost, trustProxy, stripCookies = [] }) {
  const headers = {}
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue
    if (HOP_BY_HOP.has(key.toLowerCase())) continue
    headers[key] = value
  }
  if (headers.cookie !== undefined) {
    const stripped = stripCookieHeader(headers.cookie, stripCookies)
    if (stripped) headers.cookie = stripped
    else delete headers.cookie
  }
  headers.host = forwardHost === 'target' ? `${upstream.host}:${upstream.port}` : (req.headers.host ?? `${upstream.host}:${upstream.port}`)

  const peer = req.socket?.remoteAddress ?? ''
  const socketProto = req.socket?.encrypted ? 'https' : 'http'
  if (trustProxy) {
    headers['x-forwarded-for'] = headers['x-forwarded-for'] ? `${headers['x-forwarded-for']}, ${peer}` : peer
    if (headers['x-forwarded-proto'] === undefined) headers['x-forwarded-proto'] = socketProto
  } else {
    headers['x-forwarded-for'] = peer
    headers['x-forwarded-proto'] = socketProto
  }
  headers['x-forwarded-host'] = req.headers.host ?? headers.host
  return headers
}

/**
 * Proxy one HTTP request to upstream, streaming the response (SSE-safe).
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {{host: string, port: number}} upstream
 * @param {object} [opts]
 * @param {'preserve'|'target'} [opts.forwardHost]
 * @param {boolean} [opts.trustProxy]
 * @param {string[]} [opts.extraSetCookies] - cookies to merge onto the response (refresh rotation).
 */
export function proxyHttp(req, res, upstream, { forwardHost = 'preserve', trustProxy = false, extraSetCookies = [], stripCookies = [] } = {}) {
  const headers = buildUpstreamHeaders(req, upstream, { forwardHost, trustProxy, stripCookies })

  const upstreamReq = httpRequest({
    hostname: upstream.host,
    port: upstream.port,
    method: req.method ?? 'GET',
    path: req.url ?? '/',
    headers,
    agent: false,
  }, (upstreamRes) => {
    const status = upstreamRes.statusCode ?? 502
    const resHeaders = {}
    for (const [key, value] of Object.entries(upstreamRes.headers)) {
      if (value === undefined) continue
      if (HOP_BY_HOP.has(key.toLowerCase())) continue
      resHeaders[key] = value
    }
    if (extraSetCookies.length > 0) {
      const existing = resHeaders['set-cookie'] ? [].concat(resHeaders['set-cookie']) : []
      resHeaders['set-cookie'] = existing.concat(extraSetCookies)
    }
    res.writeHead(status, resHeaders)
    upstreamRes.pipe(res)
  })

  upstreamReq.on('error', () => {
    if (!res.headersSent) {
      const body = 'Bad Gateway\n'
      res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8', 'content-length': Buffer.byteLength(body) })
      res.end(body)
      return
    }
    res.end()
  })

  // Client going away mid-stream must abort the upstream request.
  res.on('close', () => {
    if (!res.writableEnded) upstreamReq.destroy()
  })

  req.pipe(upstreamReq)
}

/**
 * Proxy one WebSocket upgrade to upstream, then pipe sockets both ways.
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:stream').Duplex} socket
 * @param {Buffer} head
 * @param {{host: string, port: number}} upstream
 * @param {object} [opts]
 */
export function proxyUpgrade(req, socket, head, upstream, { forwardHost = 'preserve', trustProxy = false, extraSetCookies = [], stripCookies = [] } = {}) {
  const headers = buildUpstreamHeaders(req, upstream, { forwardHost, trustProxy, stripCookies })
  headers.connection = 'Upgrade'
  headers.upgrade = req.headers.upgrade ?? 'websocket'

  const upstreamReq = httpRequest({
    hostname: upstream.host,
    port: upstream.port,
    method: req.method ?? 'GET',
    path: req.url ?? '/',
    headers,
    agent: false,
  })

  upstreamReq.on('upgrade', (upstreamRes, upstreamSocket, upstreamHead) => {
    let response = 'HTTP/1.1 101 Switching Protocols\r\n'
    // A 101 response must carry its own Connection/Upgrade headers (they are
    // hop-by-hop and therefore stripped from the forwarded set, so re-add them
    // from the negotiated upgrade).
    response += `connection: Upgrade\r\n`
    response += `upgrade: ${upstreamRes.headers.upgrade ?? req.headers.upgrade ?? 'websocket'}\r\n`
    for (const [key, value] of Object.entries(upstreamRes.headers)) {
      if (value === undefined) continue
      if (HOP_BY_HOP.has(key.toLowerCase())) continue
      response += `${key}: ${value}\r\n`
    }
    for (const cookie of extraSetCookies) {
      response += `set-cookie: ${cookie}\r\n`
    }
    response += '\r\n'
    socket.write(response)
    if (head && head.length > 0) upstreamSocket.write(head)
    if (upstreamHead && upstreamHead.length > 0) socket.write(upstreamHead)
    socket.pipe(upstreamSocket)
    upstreamSocket.pipe(socket)

    const teardown = () => {
      upstreamSocket.destroy()
      socket.destroy()
    }
    upstreamSocket.on('error', teardown)
    socket.on('error', () => upstreamSocket.destroy())
    upstreamSocket.on('close', () => socket.destroy())
    socket.on('close', () => upstreamSocket.destroy())
  })

  upstreamReq.on('error', () => {
    socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
    socket.destroy()
  })

  upstreamReq.end()
}
