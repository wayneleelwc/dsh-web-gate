/**
 * Gate authentication logic: cookie parsing, session mint/verify/rotate,
 * login, logout, and change-password. Pure functions over a state object and
 * a revocation list; HTTP wiring lives in server.js.
 */

import { hashPassword, verifyPassword } from './crypto.js'
import { mintSession, verifyToken } from './tokens.js'
import { LoginLimiter, TokenBucket } from './ratelimit.js'

/** Parse a Cookie header into a name→value map. */
export function parseCookies(header) {
  const out = {}
  if (!header) return out
  for (const part of header.split(';')) {
    const idx = part.indexOf('=')
    if (idx === -1) continue
    const name = part.slice(0, idx).trim()
    const value = part.slice(idx + 1).trim()
    if (name) out[name] = value
  }
  return out
}

/** Serialize a Set-Cookie header value. */
export function serializeCookie(name, value, { maxAge, httpOnly = true, sameSite = 'Strict', path = '/', secure = false }) {
  const parts = [`${name}=${value}`, `Path=${path}`, `SameSite=${sameSite}`]
  if (httpOnly) parts.push('HttpOnly')
  if (secure) parts.push('Secure')
  if (maxAge != null) parts.push(`Max-Age=${maxAge}`)
  return parts.join('; ')
}

/** Read a request body up to `maxBytes` and return it as a UTF-8 string. */
export function readBody(req, maxBytes = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    req.on('data', (chunk) => {
      size += chunk.length
      if (size > maxBytes) {
        reject(new Error('request body too large'))
        req.destroy()
        return
      }
      chunks.push(chunk)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

/** Parse an application/x-www-form-urlencoded body. */
export function parseForm(body) {
  const out = {}
  for (const pair of body.split('&')) {
    if (!pair) continue
    const idx = pair.indexOf('=')
    const key = decodeURIComponent(pair.slice(0, idx === -1 ? pair.length : idx).replace(/\+/g, ' '))
    const value = idx === -1 ? '' : decodeURIComponent(pair.slice(idx + 1).replace(/\+/g, ' '))
    if (key) out[key] = value
  }
  return out
}

/**
 * Create the gate controller bound to config, state, and a revocation list.
 * @param {object} args
 * @param {object} args.config - resolved config.
 * @param {object} args.state - mutable state (password hash, secret, pv).
 * @param {import('./tokens.js').RevocationList} args.revocation
 * @param {() => Promise<void>} args.persist - persists `state` to disk.
 */
export function createGate({ config, state, revocation, persist }) {
  const { session, rateLimit } = config
  const accessCookie = `${session.cookieName}_access`
  const refreshCookie = `${session.cookieName}_refresh`
  const loginLimiter = new LoginLimiter(rateLimit.login)
  const globalBucket = rateLimit.global.enabled ? new TokenBucket(rateLimit.global) : null

  const nowSeconds = () => Math.floor(Date.now() / 1000)
  const cookieOpts = (maxAge) => ({ maxAge, sameSite: session.cookieSameSite, secure: session.cookieSecure })

  const clearCookies = () => [
    serializeCookie(accessCookie, '', cookieOpts(0)),
    serializeCookie(refreshCookie, '', cookieOpts(0)),
  ]

  function mintCookies(remember) {
    const minted = mintSession({
      secret: state.secret,
      sub: session.username,
      pv: state.pv,
      accessTtlSeconds: session.accessTtlSeconds,
      refreshTtlSeconds: session.refreshTtlSeconds,
    })
    const cookies = [serializeCookie(accessCookie, minted.accessToken, cookieOpts(session.accessTtlSeconds))]
    if (remember) cookies.push(serializeCookie(refreshCookie, minted.refreshToken, cookieOpts(session.refreshTtlSeconds)))
    return cookies
  }

  function readTokens(req) {
    const cookies = parseCookies(req.headers.cookie)
    return { access: cookies[accessCookie], refresh: cookies[refreshCookie] }
  }

  /**
   * Authenticate a request. Returns `{ ok, payload }`, plus `rotated` cookies
   * when an expired access token was transparently renewed from a valid
   * refresh token. In insecure mode every request is treated as authenticated.
   */
  function authenticate(req) {
    if (config.insecure) return { ok: true, payload: { sub: session.username, insecure: true } }
    const { access, refresh } = readTokens(req)
    const now = nowSeconds()
    revocation.prune(now)
    const accessPayload = access
      ? verifyToken({ token: access, secret: state.secret, kind: 'access', pv: state.pv, nowSeconds: now })
      : null
    if (accessPayload && !revocation.isRevoked(accessPayload.jti)) {
      return { ok: true, payload: accessPayload }
    }
    if (refresh) {
      const refreshPayload = verifyToken({ token: refresh, secret: state.secret, kind: 'refresh', pv: state.pv, nowSeconds: now })
      if (refreshPayload && !revocation.isRevoked(refreshPayload.jti)) {
        revocation.add(refreshPayload.jti, refreshPayload.exp)
        return { ok: true, payload: refreshPayload, rotated: mintCookies(true) }
      }
    }
    return { ok: false }
  }

  /** Enforce the optional global per-IP request budget. */
  function allowGlobal(key) {
    if (globalBucket === null) return true
    return globalBucket.take(key)
  }

  /** Login: verify password (rate-limited) and mint session cookies. */
  async function login({ password, remember, clientKey }) {
    const limit = loginLimiter.check(clientKey)
    if (!limit.allowed) {
      return { status: 429, error: '尝试次数过多，请稍后再试', retryAfterMs: limit.retryAfterMs }
    }
    const ok = await verifyPassword(password, state.passwordHash ?? '')
    if (!ok) {
      loginLimiter.recordFailure(clientKey)
      return { status: 401, error: '口令错误' }
    }
    loginLimiter.recordSuccess(clientKey)
    return { status: 200, cookies: mintCookies(Boolean(remember)) }
  }

  /** Logout: revoke the presented tokens (best-effort) and clear cookies. */
  function logout(req) {
    const { access, refresh } = readTokens(req)
    const now = nowSeconds()
    const ap = access
      ? verifyToken({ token: access, secret: state.secret, kind: 'access', pv: state.pv, nowSeconds: now })
      : null
    if (ap) revocation.add(ap.jti, ap.exp)
    const rp = refresh
      ? verifyToken({ token: refresh, secret: state.secret, kind: 'refresh', pv: state.pv, nowSeconds: now })
      : null
    if (rp) revocation.add(rp.jti, rp.exp)
    return clearCookies()
  }

  /** Change password: verify current, hash new, bump pv (invalidates all sessions). */
  async function changePassword({ current, password, confirm }) {
    if (password !== confirm) return { status: 400, error: '两次输入的新口令不一致' }
    if (password.length < 8) return { status: 400, error: '新口令至少需要 8 个字符' }
    const ok = await verifyPassword(current, state.passwordHash ?? '')
    if (!ok) return { status: 401, error: '当前口令错误' }
    state.passwordHash = hashPassword(password)
    state.pv = state.pv + 1
    await persist()
    // Stay logged in with a session minted under the new generation; every
    // other outstanding token is now invalid by pv mismatch.
    return { status: 200, cookies: mintCookies(true), success: '口令已更新' }
  }

  return {
    authenticate,
    allowGlobal,
    login,
    logout,
    changePassword,
    readTokens,
    cookieNames: { access: accessCookie, refresh: refreshCookie },
  }
}
