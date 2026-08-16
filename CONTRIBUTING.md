# Contributing

Thanks for your interest in contributing to `dsh-web-gate`.

## Ground rules

- **Zero runtime dependencies is a hard invariant.** Do not add npm packages to
  `dependencies`. Anything the gateway needs must use Node.js built-ins
  (`node:crypto`, `node:http`, `node:net`, etc.). Dev-only tooling is more
  flexible, but plain `node:test` is preferred.
- Keep the fail-closed posture: never make the gateway serve without a password
  unless `--insecure` is explicit.
- Every behavior change ships with a test.

## Getting started

```bash
git clone https://github.com/wayneleelwc/dsh-web-gate.git
cd dsh-web-gate
npm test
```

There is no build step and no install step.

## Making a change

1. Open an [issue](https://github.com/wayneleelwc/dsh-web-gate/issues) first for
   anything non-trivial, so the design can be discussed.
2. Add or update tests in `test/`.
3. Run `npm test` and make sure all tests pass.
4. Keep the README and `docs/` in sync with changed behavior.

## Style

- Plain modern JavaScript (ESM), `"type": "module"`.
- JSDoc on public function contracts (`@param` / `@returns`).
- Product copy (the login/settings pages) is Chinese; code comments are English.
- Files end with exactly one trailing newline.

## Pull requests

- One concern per PR.
- Link the issue it closes.
- CI must pass before merge.
