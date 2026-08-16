import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const BIN = join(dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'dsh-web-gate.js')

function run(args) {
  return spawnSync(process.execPath, [BIN, ...args], { encoding: 'utf8' })
}

test('--version prints the package version', () => {
  const res = run(['--version'])
  assert.equal(res.status, 0)
  assert.match(res.stdout.trim(), /^\d+\.\d+\.\d+$/)
})

test('--help prints usage', () => {
  const res = run(['--help'])
  assert.equal(res.status, 0)
  assert.match(res.stdout, /Usage:/)
})

test('unknown option fails', () => {
  const res = run(['--bogus'])
  assert.notEqual(res.status, 0)
  assert.match(res.stderr, /unknown option/)
})

test('hash-password prints an scrypt hash', () => {
  const res = run(['hash-password', 'test-password'])
  assert.equal(res.status, 0)
  assert.match(res.stdout.trim(), /^scrypt\$16384\$8\$1\$/)
})

test('unknown command fails', () => {
  const res = run(['frobnicate'])
  assert.notEqual(res.status, 0)
  assert.match(res.stderr, /unknown command/)
})
