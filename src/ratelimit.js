/**
 * Rate limiting primitives. No third-party dependency: fixed-window counters
 * and a token bucket implemented over `Date.now()`.
 */

/**
 * A login brute-force limiter keyed by an arbitrary string (usually the client
 * IP). After `maxAttempts` failures within `windowMs`, the key is locked out
 * for `lockoutMs`.
 */
export class LoginLimiter {
  #windowMs
  #maxAttempts
  #lockoutMs
  /** @type {Map<string, number[]>} */
  #failures = new Map()
  /** @type {Map<string, { until: number }>} */
  #locks = new Map()

  constructor({ windowMs = 15 * 60 * 1000, maxAttempts = 5, lockoutMs = 15 * 60 * 1000 } = {}) {
    this.#windowMs = windowMs
    this.#maxAttempts = maxAttempts
    this.#lockoutMs = lockoutMs
  }

  /**
   * Whether an attempt is currently allowed for the key.
   * @param {string} key
   * @param {number} [now]
   * @returns {{ allowed: boolean, retryAfterMs: number }}
   */
  check(key, now = Date.now()) {
    const lock = this.#locks.get(key)
    if (lock && lock.until > now) return { allowed: false, retryAfterMs: lock.until - now }
    return { allowed: true, retryAfterMs: 0 }
  }

  /** Record a failed attempt; may trigger a lockout. */
  recordFailure(key, now = Date.now()) {
    const cutoff = now - this.#windowMs
    const recent = (this.#failures.get(key) ?? []).filter((t) => t > cutoff)
    recent.push(now)
    if (recent.length >= this.#maxAttempts) {
      this.#failures.delete(key)
      this.#locks.set(key, { until: now + this.#lockoutMs })
    } else {
      this.#failures.set(key, recent)
    }
  }

  /** Clear a key after a successful login. */
  recordSuccess(key) {
    this.#failures.delete(key)
    this.#locks.delete(key)
  }
}

/**
 * A per-key token bucket for coarse request shaping (optional global guard).
 */
export class TokenBucket {
  #capacity
  #refillPerSecond
  /** @type {Map<string, { tokens: number, last: number }>} */
  #buckets = new Map()

  constructor({ capacity = 60, refillPerSecond = 30 } = {}) {
    this.#capacity = capacity
    this.#refillPerSecond = refillPerSecond
  }

  /**
   * Consume one token for the key.
   * @returns {boolean} true when a token was available.
   */
  take(key, now = Date.now()) {
    const b = this.#buckets.get(key) ?? { tokens: this.#capacity, last: now }
    const elapsed = (now - b.last) / 1000
    b.tokens = Math.min(this.#capacity, b.tokens + elapsed * this.#refillPerSecond)
    b.last = now
    if (b.tokens < 1) {
      this.#buckets.set(key, b)
      return false
    }
    b.tokens -= 1
    this.#buckets.set(key, b)
    return true
  }
}
