# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-08-16

### Added

- Zero-dependency authentication gateway (reverse proxy) for the DeepSeek
  Harness Web GUI, covering static assets, `/api` JSON-RPC + SSE, and WebSocket
  upgrades.
- scrypt password hashing (N=2^14, r=8, p=1) with constant-time comparison.
- Stateless HMAC-signed `access` + `refresh` session cookies with transparent
  renewal, `HttpOnly` / `SameSite=Strict`, and a `pv` password-generation claim
  for instant global invalidation on password change.
- Per-IP login rate limiting with lockout and an optional global token bucket.
- Login and change-password pages (pure HTML, no script, strict CSP).
- CLI: `start`, `hash-password`, `set-password`, `--version`, `--help`.
- Config via CLI flags, `DSH_WEB_GATE_*` environment variables, and a JSON
  config file; atomic state file (mode 0600) for password hash and signing key.
- Dockerfile, docker-compose example, systemd unit, and GitHub Actions CI.
- `node:test` unit and end-to-end test suite.

### Security

- Fail-closed startup: refuses to serve without a password unless `--insecure`.
- Gateway auth cookies are stripped before proxying so they never reach the
  upstream.
- Client-supplied `X-Forwarded-*` headers are ignored unless `trustProxy` is set.
- Bounded in-memory rate-limiters prune expired entries.
