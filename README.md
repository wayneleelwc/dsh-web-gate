# dsh-web-gate

**Zero-dependency password gateway for the [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) Web GUI.**

> 一个零第三方依赖的口令网关：放在 DeepSeek Harness Web 界面前面，进入网页前必须先输入访问口令；口令可在登录后的「设置」页面修改。参考了 Hermes Agent 的 `dashboard_auth/basic` 插件与 Open WebUI 的反向代理 + 鉴权策略。

`dsh-web-gate` is a small, auditable reverse proxy written in plain Node.js (ESM) using **only `node:crypto`** — no npm dependencies, no build step. It puts a real authentication gate in front of the DSH Web GUI and protects **all three** channels the GUI uses: static HTML, the `/api` JSON-RPC + SSE transport, and the WebSocket upgrade.

```
浏览器 ──HTTPS/HTTP──▶ dsh-web-gate ──127.0.0.1:3080──▶ dsh web (loopback only)
                        │  登录页 / 口令校验 / 会话 Cookie / 限流 / 反向代理
```

## 为什么是「网关」而不是「改 DSH」

DSH 的 `webServer` 服务是一个路由注册表（`register` / `registerFallback` / `registerUpgrade`），**没有中间件钩子**，也没有自带的认证层（其 `/api` 信任栅栏明确说明「不是认证层」）。任何想在进程内拦截 `/api`、WebSocket 和静态资源三者的「插件」都必须抢先占住 `fallback` 座位并重新实现全部路由，既脆弱又不可维护。

因此本项目采用行业成熟方案：**反向代理网关**（与 Open WebUI 官方推荐一致），把 DSH 收紧到仅回环监听，由网关承担认证。这样对 DSH 零侵入、可独立部署、可被 nginx/TLS 再包一层。

## 特性

- **真实口令认证**：scrypt 口令哈希（N=2^14, r=8, p=1，与 Hermes 相同参数）、恒定时间比较，内存中无明文、磁盘上无明文。
- **无状态会话**：HMAC-SHA256 签名的 access（12h）+ refresh（30d）Cookie，`HttpOnly` / `SameSite=Strict`，过期自动透明续期。
- **口令变更即全面下线**：`pv`（口令代际）声明使改密后所有旧会话立即失效，无需扫描会话表。
- **防暴力破解**：按 IP 的登录限流 + 锁定期；可选全局令牌桶限流。
- **CSRF 防护**：`SameSite=Strict` + 网关自身写操作的同源校验；DSH 自身的 `/api` 信任栅栏继续生效。
- **三条通道全代理**：静态资源、`/api`（含 SSE 流式）、WebSocket upgrade 全部经网关鉴权后透传。
- **口令修改**：登录后访问 `/settings` 页改密（需当前口令），或 `dsh-web-gate set-password` 命令行。
- **零依赖、零构建**：`node bin/dsh-web-gate.js` 直接运行；仅 `node:crypto` + 标准库。
- **Fail-closed**：未配置口令且非交互环境时**拒绝启动**（除非显式 `--insecure`，并打印醒目警告）。

## 快速开始（本地）

DSH Web GUI 默认在 `127.0.0.1:3080`，网关默认在 `127.0.0.1:3090` 反代它：

```bash
# 方式一：环境变量设置初始口令（首次运行写入状态文件，之后可改）
DSH_WEB_GATE_PASSWORD='你的强口令' node bin/dsh-web-gate.js start

# 方式二：交互式首次设置口令
node bin/dsh-web-gate.js start
# 设置初始访问口令（至少 8 位）: ********
```

然后访问 `http://127.0.0.1:3090`，输入口令进入 DSH；登录后访问 `http://127.0.0.1:3090/settings` 修改口令。

## 配置

三层配置，优先级从高到低：**CLI 参数 > 环境变量 `DSH_WEB_GATE_*` > 配置文件 `dsh-web-gate.config.json` > 内置默认值**。

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DSH_WEB_GATE_HOST` | `127.0.0.1` | 网关监听地址（公网用 `0.0.0.0`） |
| `DSH_WEB_GATE_PORT` | `3090` | 网关监听端口 |
| `DSH_WEB_GATE_UPSTREAM_HOST` | `127.0.0.1` | DSH Web GUI 地址 |
| `DSH_WEB_GATE_UPSTREAM_PORT` | `3080` | DSH Web GUI 端口 |
| `DSH_WEB_GATE_USERNAME` | `admin` | 会话主体标识（单用户，仅作显示/签发） |
| `DSH_WEB_GATE_PASSWORD` | — | 初始口令（仅首次运行消费，之后存 scrypt 哈希） |
| `DSH_WEB_GATE_ACCESS_TTL` | `43200` | access token 寿命（秒） |
| `DSH_WEB_GATE_REFRESH_TTL` | `2592000` | refresh token 寿命（秒） |
| `DSH_WEB_GATE_COOKIE_NAME` | `dsh_web_gate` | Cookie 前缀（生成 `<name>_access` / `<name>_refresh`） |
| `DSH_WEB_GATE_COOKIE_SECURE` | `false` | Cookie `Secure`（HTTPS 下应设为 `true`） |
| `DSH_WEB_GATE_COOKIE_SAMESITE` | `Strict` | `Strict` / `Lax` / `None` |
| `DSH_WEB_GATE_LOGIN_MAX_ATTEMPTS` | `5` | 锁定前的失败次数 |
| `DSH_WEB_GATE_LOGIN_WINDOW_MS` | `900000` | 失败计数窗口（毫秒） |
| `DSH_WEB_GATE_LOGIN_LOCKOUT_MS` | `900000` | 锁定时长（毫秒） |
| `DSH_WEB_GATE_GLOBAL_LIMIT_ENABLED` | `false` | 启用全局令牌桶限流 |
| `DSH_WEB_GATE_STATE` | `./dsh-web-gate.state.json` | 状态文件路径（含口令哈希与签名密钥，权限 0600） |
| `DSH_WEB_GATE_TRUST_PROXY` | `false` | 信任 `X-Forwarded-For`（网关前还有一层代理时才开） |
| `DSH_WEB_GATE_INSECURE` | `false` | 关闭认证（危险） |

完整配置见 [`config.example.json`](config.example.json)。

## CLI

```bash
node bin/dsh-web-gate.js start              # 启动网关（默认命令）
node bin/dsh-web-gate.js hash-password      # 生成 scrypt 哈希（可预置到状态文件）
node bin/dsh-web-gate.js set-password       # 直接修改状态文件中的口令（会 bump pv 使旧会话失效）
```

## 部署到服务器

1. **收紧 DSH**：只让 DSH 监听回环，并登记网关的公开主机名，使其 `/api` 信任栅栏放行：

   ```bash
   dsh web --host 127.0.0.1 --port 3080 --trusted-host <你的域名或IP>:3090
   ```

2. **启动网关**（监听公网接口）：

   ```bash
   DSH_WEB_GATE_HOST=0.0.0.0 DSH_WEB_GATE_PORT=3090 \
   DSH_WEB_GATE_PASSWORD='强口令' node bin/dsh-web-gate.js start --state /var/lib/dsh-web-gate/state.json
   ```

3. **（强烈建议）TLS**：网关本身是纯 HTTP，生产环境请在它前面接 nginx/Caddy 终止 TLS，并把 `DSH_WEB_GATE_COOKIE_SECURE=true`。

- **Docker**：见 [`Dockerfile`](Dockerfile) 与 [`docker-compose.example.yml`](docker-compose.example.yml)，状态文件挂载到 `/data` 卷以跨容器重启保留口令与会话密钥。
- **systemd**：见 [`deploy/dsh-web-gate.service`](deploy/dsh-web-gate.service)。

## 与业界方案的关系

| 方面 | Hermes `dashboard_auth/basic` | Open WebUI | 本项目 |
| --- | --- | --- | --- |
| 位置 | 进程内 dashboard 网关中间件 | 应用内 JWT / 反向代理 | 独立反向代理网关 |
| 口令哈希 | 标准库 scrypt（无第三方依赖） | bcrypt/argon2（应用内） | 标准库 scrypt（无第三方依赖） |
| 会话 | 无状态 HMAC 签名 token（access+refresh） | JWT + refresh | 无状态 HMAC 签名（access+refresh） |
| 常量时间比较 | 是（含未知用户的 dummy hash） | 视实现 | 是 |
| 口令变更下线 | 换 secret / 配置重载 | token 失效 | `pv` 代际 bump，立即全局失效 |
| 防暴力破解 | 由上游框架提供 | 应用内 | 内置按 IP 限流 + 锁定 |

设计细节与威胁模型见 [`docs/architecture.md`](docs/architecture.md) 与 [`docs/security.md`](docs/security.md)。

## 目录结构

```
bin/dsh-web-gate.js    CLI 入口（start / hash-password / set-password）
src/crypto.js          scrypt 哈希、HMAC 签名、恒定时间比较
src/tokens.js          access/refresh token、pv 代际、jti 吊销表
src/ratelimit.js       登录限流 + 令牌桶
src/auth.js            会话签发/校验/续期、登录/登出/改密逻辑
src/proxy.js           HTTP（SSE）与 WebSocket upgrade 反向代理
src/server.js          HTTP 服务装配与路由分发
src/config.js          配置解析与校验
src/state.js           状态文件（0600）原子读写
src/pages.js           登录页 / 设置改密页（纯 HTML，无脚本，严格 CSP）
test/                  node:test 单元 + 端到端测试
```

## 测试

```bash
npm test      # 等价于 node --test "test/*.test.js"
```

32 个测试覆盖：哈希往返与篡改、token 签发/过期/pv 失效/吊销、限流锁定、登录/登出/改密、SSE 流式透传、WebSocket 鉴权与透传、安全响应头。

## 许可

[MIT](LICENSE)
