/**
 * Durable gate state: the scrypt password hash, the session signing secret,
 * and the password generation (`pv`). Written atomically with mode 0600 so it
 * is owner-readable only. Plaintext passwords are never stored here.
 */

import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'
import { randomSecret } from './crypto.js'

export const STATE_VERSION = 1

/**
 * Build a fresh state object.
 * @param {object} [args]
 * @param {string} [args.secret] - base64 signing secret (generated if absent).
 * @param {string|null} [args.passwordHash] - scrypt hash, or null when unset.
 */
export function emptyState({ secret = randomSecret(), passwordHash = null } = {}) {
  return {
    version: STATE_VERSION,
    secret,
    pv: 1,
    passwordHash,
    createdAt: new Date().toISOString(),
  }
}

/**
 * Load and normalize state from disk. Returns null when the file does not
 * exist; throws on unreadable/corrupt content.
 * @param {string} path
 */
export async function loadState(path) {
  let raw
  try {
    raw = await readFile(path, 'utf8')
  } catch (err) {
    if (err.code === 'ENOENT') return null
    throw err
  }
  const data = JSON.parse(raw)
  if (typeof data !== 'object' || data === null) throw new Error(`dsh-web-gate: invalid state file ${path}`)
  // Normalize fields added after the first release, so older state files load.
  if (typeof data.secret !== 'string' || data.secret.length < 16) data.secret = randomSecret()
  if (!Number.isInteger(data.pv) || data.pv < 1) data.pv = 1
  if (typeof data.passwordHash !== 'string') data.passwordHash = null
  data.version = STATE_VERSION
  return data
}

/**
 * Atomically persist state with owner-only permissions.
 * @param {string} path
 * @param {object} state
 */
export async function saveState(path, state) {
  await mkdir(dirname(path), { recursive: true })
  const tmp = `${path}.tmp-${process.pid}-${Date.now()}`
  await writeFile(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 })
  await rename(tmp, path)
}

/**
 * Whether the gate has a password set (i.e. authentication is actually armed).
 * @param {object} state
 */
export function hasPassword(state) {
  return typeof state.passwordHash === 'string' && state.passwordHash.length > 0
}
