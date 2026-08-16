/**
 * Password hashing and stateless token signing primitives.
 *
 * Everything here uses only `node:crypto`, mirroring the design of the Hermes
 * Agent `dashboard_auth/basic` provider: memory-hard scrypt password hashing,
 * constant-time comparison, and HMAC-SHA256-signed stateless session tokens.
 * No third-party dependency is required.
 */

import {
  createHmac,
  randomBytes,
  scrypt as scryptCallback,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto'
import { promisify } from 'node:util'

const scrypt = promisify(scryptCallback)

/** RFC 7914 interactive-login parameters (~16 MiB memory, a few ms). */
export const SCRYPT_N = 2 ** 14
export const SCRYPT_R = 8
export const SCRYPT_P = 1
export const SCRYPT_DKLEN = 32
export const SCRYPT_SALT_BYTES = 16

/** HMAC-SHA256 digest length appended as a fixed suffix to signed tokens. */
export const HMAC_LEN = 32

/**
 * Hash a plaintext password into a `scrypt$N$r$p$<salt_b64>$<dk_b64>` string.
 * Uses the synchronous derivation because it only runs at configuration time
 * (hash-password / first-run setup), where blocking for a few milliseconds is
 * harmless.
 * @param password - plaintext password.
 */
export function hashPassword(password) {
  const salt = randomBytes(SCRYPT_SALT_BYTES)
  const dk = scryptSync(password, salt, SCRYPT_DKLEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P })
  return `scrypt$${SCRYPT_N}$${SCRYPT_R}$${SCRYPT_P}$${salt.toString('base64')}$${dk.toString('base64')}`
}

/**
 * Verify a plaintext password against a stored hash string, in constant time
 * with respect to the derived-key comparison. Returns false on any malformed
 * hash. The async derivation keeps the request loop responsive.
 * @param password - candidate plaintext password.
 * @param encoded - stored `scrypt$...` hash string.
 */
export async function verifyPassword(password, encoded) {
  try {
    const [scheme, nStr, rStr, pStr, saltB64, dkB64] = encoded.split('$')
    if (scheme !== 'scrypt') return false
    const n = Number(nStr)
    const r = Number(rStr)
    const p = Number(pStr)
    const salt = Buffer.from(saltB64, 'base64')
    const expected = Buffer.from(dkB64, 'base64')
    if (expected.length === 0) return false
    const actual = await scrypt(password, salt, expected.length, { N: n, r, p })
    return timingSafeEqual(actual, expected)
  } catch {
    return false
  }
}

/**
 * Generate a cryptographically random session-signing secret, base64-encoded.
 * @param bytes - number of random bytes (default 32).
 */
export function randomSecret(bytes = 32) {
  return randomBytes(bytes).toString('base64')
}

/**
 * Sign a JSON payload as a base64url token: `<json> || HMAC-SHA256(<json>)`.
 * The HMAC suffix has fixed length, so no separator is needed.
 * @param payload - JSON-serializable payload.
 * @param secret - signing secret (base64 or raw string bytes).
 */
export function signToken(payload, secret) {
  const raw = Buffer.from(JSON.stringify(payload), 'utf8')
  const sig = createHmac('sha256', secret).update(raw).digest()
  return Buffer.concat([raw, sig]).toString('base64url')
}

/**
 * Verify and decode a signed token. Returns the payload, or null when the
 * signature, encoding, or JSON is invalid.
 * @param token - base64url token.
 * @param secret - signing secret used to mint it.
 */
export function unsignToken(token, secret) {
  try {
    const blob = Buffer.from(token, 'base64url')
    if (blob.length <= HMAC_LEN) return null
    const raw = blob.subarray(0, blob.length - HMAC_LEN)
    const sig = blob.subarray(blob.length - HMAC_LEN)
    const expected = createHmac('sha256', secret).update(raw).digest()
    if (!timingSafeEqual(sig, expected)) return null
    return JSON.parse(raw.toString('utf8'))
  } catch {
    return null
  }
}
