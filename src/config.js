/**
 * Configuration resolution: a small, validated config object assembled from
 * (lowest to highest precedence) built-in defaults, an optional JSON config
 * file, `DSH_WEB_GATE_*` environment variables, and explicit CLI overrides.
 * Non-secret tunables live here; secrets (password hash, signing key) live in
 * the state file, not in config.
 */

export const DEFAULTS = Object.freeze({
  listen: { host: '127.0.0.1', port: 3090 },
  upstream: { host: '127.0.0.1', port: 3080, forwardHost: 'preserve' },
  session: {
    username: 'admin',
    accessTtlSeconds: 12 * 60 * 60, // 12h
    refreshTtlSeconds: 30 * 24 * 60 * 60, // 30d
    cookieName: 'dsh_web_gate',
    cookieSecure: false,
    cookieSameSite: 'Strict',
  },
  rateLimit: {
    login: { windowMs: 15 * 60 * 1000, maxAttempts: 5, lockoutMs: 15 * 60 * 1000 },
    global: { enabled: false, capacity: 60, refillPerSecond: 30 },
  },
  stateFile: './dsh-web-gate.state.json',
  insecure: false,
  trustProxy: false,
  logRequests: false,
})

function first(...values) {
  for (const v of values) {
    if (v !== undefined && v !== null && v !== '') return v
  }
  return undefined
}

function toInt(value) {
  if (value === undefined || value === null || value === '') return undefined
  const n = Number(value)
  if (!Number.isInteger(n)) {
    throw new Error(`dsh-web-gate: expected an integer, got ${JSON.stringify(value)}`)
  }
  return n
}

function toBool(value) {
  if (value === undefined || value === null || value === '') return undefined
  if (value === true || value === false) return value
  if (value === 1 || value === 0) return value === 1
  if (value === '1' || value === '0') return value === '1'
  if (value === 'true' || value === 'false') return value === 'true'
  throw new Error(`dsh-web-gate: expected a boolean, got ${JSON.stringify(value)}`)
}

function validatePort(value, label) {
  if (!Number.isInteger(value) || value < 0 || value > 65535) {
    throw new Error(`dsh-web-gate: invalid ${label}: ${value}`)
  }
  return value
}

/**
 * Merge defaults, a JSON config file, env vars, and CLI overrides into one
 * validated config object.
 * @param {object} args
 * @param {Record<string, string>} [args.env]
 * @param {object} [args.file] - parsed config file contents.
 * @param {object} [args.overrides] - explicit CLI flag values.
 */
export function resolveConfig({ env = {}, file = {}, overrides = {} } = {}) {
  const listenHost = first(overrides.host, env.DSH_WEB_GATE_HOST, file.listen?.host, DEFAULTS.listen.host)
  const upstreamHost = first(overrides.upstreamHost, env.DSH_WEB_GATE_UPSTREAM_HOST, file.upstream?.host, DEFAULTS.upstream.host)
  const sameSite = first(overrides.sameSite, env.DSH_WEB_GATE_COOKIE_SAMESITE, file.session?.cookieSameSite, DEFAULTS.session.cookieSameSite)

  const config = {
    listen: {
      host: listenHost,
      port: validatePort(
        toInt(first(overrides.port, env.DSH_WEB_GATE_PORT, file.listen?.port, DEFAULTS.listen.port)) ?? DEFAULTS.listen.port,
        'listen.port',
      ),
    },
    upstream: {
      host: upstreamHost,
      port: validatePort(
        toInt(first(overrides.upstreamPort, env.DSH_WEB_GATE_UPSTREAM_PORT, file.upstream?.port, DEFAULTS.upstream.port)) ?? DEFAULTS.upstream.port,
        'upstream.port',
      ),
      forwardHost: first(overrides.forwardHost, env.DSH_WEB_GATE_FORWARD_HOST, file.upstream?.forwardHost, DEFAULTS.upstream.forwardHost),
    },
    session: {
      username: first(overrides.username, env.DSH_WEB_GATE_USERNAME, file.session?.username, DEFAULTS.session.username),
      accessTtlSeconds: toInt(first(overrides.accessTtl, env.DSH_WEB_GATE_ACCESS_TTL, file.session?.accessTtlSeconds, DEFAULTS.session.accessTtlSeconds)) ?? DEFAULTS.session.accessTtlSeconds,
      refreshTtlSeconds: toInt(first(overrides.refreshTtl, env.DSH_WEB_GATE_REFRESH_TTL, file.session?.refreshTtlSeconds, DEFAULTS.session.refreshTtlSeconds)) ?? DEFAULTS.session.refreshTtlSeconds,
      cookieName: first(overrides.cookieName, env.DSH_WEB_GATE_COOKIE_NAME, file.session?.cookieName, DEFAULTS.session.cookieName),
      cookieSecure: toBool(first(overrides.cookieSecure, env.DSH_WEB_GATE_COOKIE_SECURE, file.session?.cookieSecure, DEFAULTS.session.cookieSecure)) ?? DEFAULTS.session.cookieSecure,
      cookieSameSite: sameSite,
    },
    rateLimit: {
      login: {
        windowMs: toInt(first(env.DSH_WEB_GATE_LOGIN_WINDOW_MS, file.rateLimit?.login?.windowMs, DEFAULTS.rateLimit.login.windowMs)) ?? DEFAULTS.rateLimit.login.windowMs,
        maxAttempts: toInt(first(env.DSH_WEB_GATE_LOGIN_MAX_ATTEMPTS, file.rateLimit?.login?.maxAttempts, DEFAULTS.rateLimit.login.maxAttempts)) ?? DEFAULTS.rateLimit.login.maxAttempts,
        lockoutMs: toInt(first(env.DSH_WEB_GATE_LOGIN_LOCKOUT_MS, file.rateLimit?.login?.lockoutMs, DEFAULTS.rateLimit.login.lockoutMs)) ?? DEFAULTS.rateLimit.login.lockoutMs,
      },
      global: {
        enabled: toBool(first(env.DSH_WEB_GATE_GLOBAL_LIMIT_ENABLED, file.rateLimit?.global?.enabled, DEFAULTS.rateLimit.global.enabled)) ?? DEFAULTS.rateLimit.global.enabled,
        capacity: toInt(first(env.DSH_WEB_GATE_GLOBAL_CAPACITY, file.rateLimit?.global?.capacity, DEFAULTS.rateLimit.global.capacity)) ?? DEFAULTS.rateLimit.global.capacity,
        refillPerSecond: toInt(first(env.DSH_WEB_GATE_GLOBAL_REFILL, file.rateLimit?.global?.refillPerSecond, DEFAULTS.rateLimit.global.refillPerSecond)) ?? DEFAULTS.rateLimit.global.refillPerSecond,
      },
    },
    stateFile: first(overrides.state, env.DSH_WEB_GATE_STATE, file.stateFile, DEFAULTS.stateFile),
    insecure: toBool(first(overrides.insecure, env.DSH_WEB_GATE_INSECURE, file.insecure, DEFAULTS.insecure)) ?? DEFAULTS.insecure,
    trustProxy: toBool(first(overrides.trustProxy, env.DSH_WEB_GATE_TRUST_PROXY, file.trustProxy, DEFAULTS.trustProxy)) ?? DEFAULTS.trustProxy,
    logRequests: toBool(first(overrides.logRequests, env.DSH_WEB_GATE_LOG_REQUESTS, file.logRequests, DEFAULTS.logRequests)) ?? DEFAULTS.logRequests,
    // Initial password, consumed only on first run, never persisted in config.
    password: first(env.DSH_WEB_GATE_PASSWORD, file.password, undefined),
  }

  validateConfig(config)
  return config
}

function validateConfig(config) {
  const { listen, upstream, session, rateLimit } = config
  if (typeof listen.host !== 'string' || listen.host.length === 0) {
    throw new Error('dsh-web-gate: listen.host must be a non-empty host')
  }
  if (typeof upstream.host !== 'string' || upstream.host.length === 0) {
    throw new Error('dsh-web-gate: upstream.host must be a non-empty host')
  }
  if (!['preserve', 'target'].includes(upstream.forwardHost)) {
    throw new Error(`dsh-web-gate: upstream.forwardHost must be "preserve" or "target", got ${JSON.stringify(upstream.forwardHost)}`)
  }
  if (typeof session.username !== 'string' || session.username.length === 0) {
    throw new Error('dsh-web-gate: session.username must be a non-empty string')
  }
  if (!/^[^\s()<>@,;:\\"/[\]?={}]+$/.test(session.cookieName)) {
    throw new Error(`dsh-web-gate: session.cookieName must be a valid cookie name token, got ${JSON.stringify(session.cookieName)}`)
  }
  if (!['Strict', 'Lax', 'None'].includes(session.cookieSameSite)) {
    throw new Error(`dsh-web-gate: session.cookieSameSite must be Strict, Lax, or None, got ${JSON.stringify(session.cookieSameSite)}`)
  }
  if (session.cookieSameSite === 'None' && !session.cookieSecure) {
    throw new Error('dsh-web-gate: SameSite=None requires session.cookieSecure=true (browsers reject non-Secure SameSite=None cookies)')
  }
  if (session.accessTtlSeconds < 60) {
    throw new Error('dsh-web-gate: session.accessTtlSeconds must be at least 60')
  }
  if (session.refreshTtlSeconds < session.accessTtlSeconds) {
    throw new Error('dsh-web-gate: session.refreshTtlSeconds must be >= session.accessTtlSeconds')
  }
  if (rateLimit.login.maxAttempts < 1) {
    throw new Error('dsh-web-gate: rateLimit.login.maxAttempts must be at least 1')
  }
  if (rateLimit.login.windowMs < 1) {
    throw new Error('dsh-web-gate: rateLimit.login.windowMs must be positive')
  }
  if (rateLimit.login.lockoutMs < 0) {
    throw new Error('dsh-web-gate: rateLimit.login.lockoutMs must be non-negative')
  }
  if (rateLimit.global.capacity < 1) {
    throw new Error('dsh-web-gate: rateLimit.global.capacity must be at least 1')
  }
  if (rateLimit.global.refillPerSecond <= 0) {
    throw new Error('dsh-web-gate: rateLimit.global.refillPerSecond must be positive')
  }
}
