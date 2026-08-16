# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| `main` (latest) | ✅ |

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities.

Report them privately to the maintainer via email or a GitHub Security Advisory
(**Security → Report a vulnerability**) on the repository. You will receive a
response within 72 hours, and a public disclosure after the fix is released.

Include as much of the following as you can:

- the affected version or commit,
- a minimal reproduction,
- the potential impact.

## Security model

See [`docs/security.md`](docs/security.md) for the full threat-model table,
the honest statement of what the gateway does and does not cover, and a
deployment checklist.

## Preferences

- Please **do** report timing side channels, cookie/session issues, proxy
  header-handling bugs, and brute-force bypasses.
- Please **do not** report the intentional single-password design, the lack of
  transport encryption (documented — TLS belongs in front), or the lack of
  multi-user/SSO (documented roadmap) as vulnerabilities.
