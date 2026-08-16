/**
 * Public API surface. The gateway is consumed either as a library
 * (`createGateway`) or through the bundled CLI (`bin/dsh-web-gate.js`).
 */

export { resolveConfig, DEFAULTS } from './config.js'
export { hashPassword, verifyPassword, randomSecret, signToken, unsignToken } from './crypto.js'
export { mintSession, verifyToken, RevocationList } from './tokens.js'
export { LoginLimiter, TokenBucket } from './ratelimit.js'
export { emptyState, loadState, saveState, hasPassword } from './state.js'
export { parseCookies, serializeCookie, readBody, parseForm, createGate } from './auth.js'
export { proxyHttp, proxyUpgrade } from './proxy.js'
export { loginPage, settingsPage } from './pages.js'
export { securityHeaders } from './headers.js'
export { createGateway } from './server.js'
