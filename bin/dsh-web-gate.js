#!/usr/bin/env node
/**
 * `dsh-web-gate` CLI. Subcommands:
 *
 *   start [--config <path>] [--host h] [--port p] [--upstream-host h] [--upstream-port p] [--insecure]
 *   hash-password [password]
 *   set-password [password]
 *
 * `start` is the default command. The gate fails closed: it refuses to serve
 * without a password unless `--insecure` or `DSH_WEB_GATE_INSECURE=1` is set.
 */

import { createInterface } from 'node:readline'
import { createRequire } from 'node:module'
import { readFile } from 'node:fs/promises'
import { resolveConfig } from '../src/config.js'
import { hashPassword } from '../src/crypto.js'
import { emptyState, hasPassword, loadState, saveState } from '../src/state.js'
import { RevocationList } from '../src/tokens.js'
import { createGateway } from '../src/server.js'

const require = createRequire(import.meta.url)
const VERSION = require('../package.json').version

const USAGE = `dsh-web-gate — zero-dependency password gateway for the DeepSeek Harness Web GUI

Usage:
  dsh-web-gate [start] [options]
  dsh-web-gate hash-password [password]
  dsh-web-gate set-password [password]

Options:
  --config <path>          JSON config file (default: ./dsh-web-gate.config.json)
  --host <host>            listen host (default 127.0.0.1; 0.0.0.0 for LAN/public)
  --port <port>            listen port (default 3090)
  --upstream-host <host>   DSH Web GUI host (default 127.0.0.1)
  --upstream-port <port>   DSH Web GUI port (default 3080)
  --state <path>           state file (default ./dsh-web-gate.state.json)
  --log-requests           log one line per proxied request
  --insecure               disable the auth gate (DANGEROUS: do not expose to a network)
  --version, -v            print the version and exit
  --help, -h               print this help

Environment (overrides the config file):
  DSH_WEB_GATE_HOST, DSH_WEB_GATE_PORT, DSH_WEB_GATE_UPSTREAM_HOST,
  DSH_WEB_GATE_UPSTREAM_PORT, DSH_WEB_GATE_USERNAME, DSH_WEB_GATE_PASSWORD,
  DSH_WEB_GATE_INSECURE, DSH_WEB_GATE_LOG_REQUESTS, DSH_WEB_GATE_STATE
`

function parseArgs(argv) {
  const flags = {}
  const positional = []
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (arg === '--config' || arg === '--host' || arg === '--port' || arg === '--upstream-host' || arg === '--upstream-port' || arg === '--state') {
      const value = argv[++i]
      if (value === undefined || value.startsWith('--')) {
        throw new Error(`dsh-web-gate: ${arg} requires a value`)
      }
      flags[camel(arg)] = value
    } else if (arg === '--insecure') {
      flags.insecure = true
    } else if (arg === '--log-requests') {
      flags.logRequests = true
    } else if (arg === '--help' || arg === '-h') {
      flags.help = true
    } else if (arg === '--version' || arg === '-v' || arg === '-V') {
      flags.version = true
    } else if (arg.startsWith('--')) {
      throw new Error(`dsh-web-gate: unknown option ${JSON.stringify(arg)}`)
    } else {
      positional.push(arg)
    }
  }
  return { flags, positional }
}

function camel(flag) {
  const name = flag.replace(/^--/, '')
  return name.replace(/-([a-z])/g, (_, c) => c.toUpperCase())
}

async function loadConfigFile(path) {
  if (!path) return {}
  try {
    return JSON.parse(await readFile(path, 'utf8'))
  } catch (err) {
    if (err.code === 'ENOENT') return {}
    throw new Error(`dsh-web-gate: cannot read config file ${path}: ${err.message}`)
  }
}

/** Read a password line without echoing it (raw mode on a TTY). */
function readPassword(question) {
  const stdin = process.stdin
  const stdout = process.stdout
  return new Promise((resolve) => {
    if (!stdin.isTTY) {
      const rl = createInterface({ input: stdin, output: stdout })
      rl.question(question, (answer) => {
        rl.close()
        resolve(answer)
      })
      return
    }
    stdout.write(question)
    stdin.setRawMode(true)
    stdin.resume()
    stdin.setEncoding('utf8')
    let buffer = ''
    const onData = (char) => {
      switch (char) {
        case '\u0003': // ctrl-c
          stdin.setRawMode(false)
          stdout.write('\n')
          process.exit(130)
          break
        case '\r':
        case '\n':
          stdin.setRawMode(false)
          stdin.pause()
          stdin.off('data', onData)
          stdout.write('\n')
          resolve(buffer)
          break
        case '\u007f': // backspace
          if (buffer.length > 0) {
            buffer = buffer.slice(0, -1)
            stdout.write('\b \b')
          }
          break
        default:
          buffer += char
          stdout.write('*')
      }
    }
    stdin.on('data', onData)
  })
}

async function promptPassword(question) {
  return (await readPassword(question)).trim()
}

async function setupPassword(state, config) {
  if (hasPassword(state)) return
  if (config.password) {
    if (config.password.length < 8) {
      process.stderr.write('dsh-web-gate: WARNING: the configured password is shorter than 8 characters; consider a stronger one.\n')
    }
    state.passwordHash = hashPassword(config.password)
    return
  }
  if (process.stdin.isTTY) {
    const first = await promptPassword('设置初始访问口令（至少 8 位）: ')
    if (first.length < 8) throw new Error('dsh-web-gate: 口令至少需要 8 个字符')
    const second = await promptPassword('再次输入确认: ')
    if (first !== second) throw new Error('dsh-web-gate: 两次输入不一致')
    state.passwordHash = hashPassword(first)
    return
  }
  if (config.insecure) return
  throw new Error(
    'dsh-web-gate: no password configured and no TTY to prompt on. '
    + 'Set DSH_WEB_GATE_PASSWORD, run interactively, or pass --insecure to serve without auth (DANGEROUS).',
  )
}

async function startCommand(flags) {
  const file = await loadConfigFile(flags.config ?? './dsh-web-gate.config.json')
  const config = resolveConfig({
    env: process.env,
    file,
    overrides: {
      host: flags.host,
      port: flags.port !== undefined ? Number(flags.port) : undefined,
      upstreamHost: flags.upstreamHost,
      upstreamPort: flags.upstreamPort !== undefined ? Number(flags.upstreamPort) : undefined,
      state: flags.state,
      insecure: flags.insecure,
      logRequests: flags.logRequests,
    },
  })

  let state = await loadState(config.stateFile)
  if (state === null) {
    state = emptyState()
  }
  await setupPassword(state, config)
  await saveState(config.stateFile, state)

  const revocation = new RevocationList()
  const gateway = createGateway({
    config,
    state,
    revocation,
    persist: () => saveState(config.stateFile, state),
  })

  const addr = await gateway.listen()
  console.log(`dsh-web-gate listening on http://${addr.host}:${addr.port}`)
  console.log(`  upstream: ${config.upstream.host}:${config.upstream.port}`)
  console.log(`  auth: ${config.insecure ? 'DISABLED (--insecure)' : `password (user "${config.session.username}")`}`)
  if (config.insecure) {
    console.log('  WARNING: the auth gate is disabled. Do not expose this port to a network.')
  } else {
    console.log('  WARNING: ensure the upstream DSH Web GUI is bound to a non-public interface,')
    console.log('           or is otherwise unreachable except through this gateway.')
  }
  if (config.listen.host !== '127.0.0.1') {
    console.log(`  TIP: for non-loopback serving, register this authority with DSH: dsh web --trusted-host <public-host>:${config.listen.port}`)
  }

  const shutdown = () => {
    void gateway.close().then(() => process.exit(0))
  }
  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
}

async function main() {
  const { flags, positional } = parseArgs(process.argv.slice(2))
  const command = positional[0] ?? 'start'

  if (flags.version) {
    process.stdout.write(`${VERSION}\n`)
    return
  }

  if (flags.help) {
    process.stdout.write(USAGE)
    return
  }

  if (command === 'hash-password') {
    let password = positional[1]
    if (!password) password = await promptPassword('口令: ')
    process.stdout.write(hashPassword(password) + '\n')
    return
  }

  if (command === 'set-password') {
    const config = resolveConfig({
      env: process.env,
      file: await loadConfigFile(flags.config ?? './dsh-web-gate.config.json'),
      overrides: { state: flags.state },
    })
    let state = await loadState(config.stateFile)
    if (state === null) state = emptyState()
    let password = positional[1]
    if (!password) {
      password = await promptPassword('新口令（至少 8 位）: ')
    }
    if (password.length < 8) throw new Error('dsh-web-gate: 口令至少需要 8 个字符')
    state.passwordHash = hashPassword(password)
    state.pv = (state.pv ?? 1) + 1
    await saveState(config.stateFile, state)
    process.stdout.write(`口令已更新（${config.stateFile}）\n`)
    return
  }

  if (command === 'start' || command === 'serve') {
    await startCommand(flags)
    return
  }

  process.stderr.write(`dsh-web-gate: unknown command ${JSON.stringify(command)}\n\n${USAGE}`)
  process.exitCode = 1
}

main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`)
  process.exitCode = 1
})
