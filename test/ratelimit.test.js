import test from 'node:test'
import assert from 'node:assert/strict'
import { LoginLimiter, TokenBucket } from '../src/ratelimit.js'

test('login limiter locks out after max attempts and resets on success', () => {
  const limiter = new LoginLimiter({ windowMs: 60000, maxAttempts: 3, lockoutMs: 60000 })
  const now = 1_000_000
  assert.deepEqual(limiter.check('ip1', now), { allowed: true, retryAfterMs: 0 })
  limiter.recordFailure('ip1', now)
  limiter.recordFailure('ip1', now + 1)
  assert.equal(limiter.check('ip1', now + 2).allowed, true)
  limiter.recordFailure('ip1', now + 2)
  const locked = limiter.check('ip1', now + 3)
  assert.equal(locked.allowed, false)
  assert.ok(locked.retryAfterMs > 0)
  limiter.recordSuccess('ip1')
  assert.equal(limiter.check('ip1', now + 4).allowed, true)
})

test('login limiter drops failures outside the window', () => {
  const limiter = new LoginLimiter({ windowMs: 1000, maxAttempts: 3, lockoutMs: 1000 })
  const now = 1_000_000
  limiter.recordFailure('ip1', now)
  limiter.recordFailure('ip1', now)
  limiter.recordFailure('ip1', now + 2000)
  limiter.recordFailure('ip1', now + 2000)
  assert.equal(limiter.check('ip1', now + 2000).allowed, true)
})

test('login limiter keys are independent', () => {
  const limiter = new LoginLimiter({ windowMs: 60000, maxAttempts: 1, lockoutMs: 60000 })
  limiter.recordFailure('ip1', 0)
  assert.equal(limiter.check('ip1', 1).allowed, false)
  assert.equal(limiter.check('ip2', 1).allowed, true)
})

test('token bucket consumes and refills', () => {
  const bucket = new TokenBucket({ capacity: 2, refillPerSecond: 1 })
  assert.equal(bucket.take('k', 0), true)
  assert.equal(bucket.take('k', 0), true)
  assert.equal(bucket.take('k', 0), false)
  assert.equal(bucket.take('k', 1000), true)
  assert.equal(bucket.take('k', 1000), false)
})

test('login limiter prune clears expired locks', () => {
  const limiter = new LoginLimiter({ windowMs: 1000, maxAttempts: 3, lockoutMs: 1000 })
  const now = 1_000_000
  limiter.recordFailure('ip1', now)
  limiter.recordFailure('ip1', now)
  limiter.recordFailure('ip1', now)
  assert.equal(limiter.check('ip1', now).allowed, false)
  limiter.prune(now + 2000)
  assert.equal(limiter.check('ip1', now + 2000).allowed, true)
})

test('login limiter prune drops stale failure timestamps', () => {
  const limiter = new LoginLimiter({ windowMs: 1000, maxAttempts: 5, lockoutMs: 1000 })
  const now = 1_000_000
  limiter.recordFailure('ip1', now)
  limiter.prune(now + 5000)
  // The stale failure is gone, so two new failures do not lock the key.
  limiter.recordFailure('ip1', now + 5000)
  limiter.recordFailure('ip1', now + 5000)
  assert.equal(limiter.check('ip1', now + 5000).allowed, true)
})

test('token bucket prune drops idle buckets', () => {
  const bucket = new TokenBucket({ capacity: 2, refillPerSecond: 1 })
  bucket.take('k', 0)
  bucket.prune(5000)
  // Bucket was idle long enough to refill fully, so a fresh one is used.
  assert.equal(bucket.take('k', 5000), true)
  assert.equal(bucket.take('k', 5000), true)
  assert.equal(bucket.take('k', 5000), false)
})
