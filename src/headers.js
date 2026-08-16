/**
 * Security response headers applied to the gateway's own pages (login and
 * settings). The proxied application's headers are forwarded untouched.
 */

export function securityHeaders() {
  return {
    'content-security-policy':
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; img-src 'self' data:",
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'no-referrer',
    'cross-origin-opener-policy': 'same-origin',
    'cache-control': 'no-store',
  }
}
