/**
 * Stateless session tokens (access + refresh) with a password-generation
 * ("pv") claim and a per-token-id ("jti") revocation list.
 *
 * Design goals, matching the Hermes `basic` provider plus two hardening
 * additions:
 *
 * - Access and refresh tokens are HMAC-signed, base64url-encoded JSON blobs,
 *   so verification needs no server-side session store.
 * - A `pv` (password generation) claim makes every token invalid the moment
 *   the password changes, without scanning a store: bumping `pv` invalidates
 *   every outstanding token in one operation.
 * - A `jti` claim lets individual tokens be revoked (logout, refresh
 *   rotation). The revocation list is in-memory; it survives a refresh
 *   rotation within a process but is cleared on restart, at which point the
 *   signing secret already lost any tokens signed before it was rotated.
 */

import { randomBytes } from 'node:crypto'
import { signToken, unsignToken } from './crypto.js'

/** A bounded in-memory set of revoked token ids, pruned by expiry. */
export class RevocationList {
  /** @type {Map<string, number>} jti -> absolute expiry (epoch seconds) */
  #entries = new Map()

  /** Revoke a token id until its expiry. */
  add(jti, expSeconds) {
    if (jti) this.#entries.set(jti, expSeconds)
  }

  /** Whether a token id is currently revoked. */
  isRevoked(jti) {
    return jti != null && this.#entries.has(jti)
  }

  /** Drop entries whose expiry has passed. */
  prune(nowSeconds) {
    for (const [jti, exp] of this.#entries) {
      if (exp <= nowSeconds) this.#entries.delete(jti)
    }
  }
}

/**
 * Mint an access + refresh token pair for a subject.
 * @param {object} args
 * @param {string} args.secret - signing secret (base64 string).
 * @param {string} args.sub - subject identifier (the configured username).
 * @param {number} args.pv - current password generation.
 * @param {number} args.accessTtlSeconds - access token lifetime.
 * @param {number} args.refreshTtlSeconds - refresh token lifetime.
 * @param {number} [args.now] - epoch milliseconds (test injection).
 */
export function mintSession({ secret, sub, pv, accessTtlSeconds, refreshTtlSeconds, now = Date.now() }) {
  const iat = Math.floor(now / 1000)
  const accessJti = randomBytes(16).toString('hex')
  const refreshJti = randomBytes(16).toString('hex')
  const accessToken = signToken(
    { jti: accessJti, sub, kind: 'access', pv, iat, exp: iat + accessTtlSeconds },
    secret,
  )
  const refreshToken = signToken(
    { jti: refreshJti, sub, kind: 'refresh', pv, iat, exp: iat + refreshTtlSeconds },
    secret,
  )
  return { accessToken, refreshToken, accessJti, refreshJti }
}

/**
 * Verify a token against the signing secret, its kind, the current password
 * generation, and its expiry. Returns the payload, or null when invalid.
 * @param {object} args
 * @param {string} args.token
 * @param {string} args.secret
 * @param {'access'|'refresh'} args.kind
 * @param {number} args.pv
 * @param {number} args.nowSeconds
 */
export function verifyToken({ token, secret, kind, pv, nowSeconds }) {
  const payload = unsignToken(token, secret)
  if (payload === null) return null
  if (payload.kind !== kind) return null
  if (payload.pv !== pv) return null
  if (typeof payload.exp !== 'number' || payload.exp <= nowSeconds) return null
  return payload
}
