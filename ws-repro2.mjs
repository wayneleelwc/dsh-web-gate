import { startUpstream, startGateway, login, rawUpgrade, stop } from './test/helpers.js'

// Simulate 7 prior tests that each open a gateway, fetch, and stop it.
for (let i = 0; i < 7; i++) {
  const up = await startUpstream()
  const gw = await startGateway({ upstreamPort: up.port })
  await fetch(`${gw.base}/login`)
  await fetch(`${gw.base}/auth/login`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'password=wrong', redirect: 'manual' })
  await stop(gw.gateway.server)
  await stop(up.server)
}
console.log('prior tests done')

const up = await startUpstream()
const gw = await startGateway({ upstreamPort: up.port })
console.log('gateway on', gw.port)
const unauth = await rawUpgrade(gw.port, '/echo')
console.log('unauth:', JSON.stringify(unauth))
const { cookieHeader } = await login(gw.base)
console.log('login ok, cookie len', cookieHeader.length)
const authed = await rawUpgrade(gw.port, '/echo', { Cookie: cookieHeader })
console.log('authed:', JSON.stringify(authed))
await stop(gw.gateway.server)
await stop(up.server)
process.exit(0)
