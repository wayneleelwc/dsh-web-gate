# 架构设计

本文说明 `dsh-web-gate` 为何做成反向代理网关，以及各模块的设计取舍。

## 为什么必须放在 DSH 之前

DeepSeek Harness 的 Web 面由 `@deepseek-ai/dsh-host-webserver` 提供 `webServer` 服务。它暴露的接口是：

- `register(route)` —— 精确/前缀路由，每个路由处理器「拥有」整个响应生命周期；
- `registerUpgrade(route)` —— WebSocket 升级路由；
- `registerFallback(handler)` —— 唯一的一个兜底座位（SPA 静态资源服务）；
- `tapIndex(transform)` —— 对 `index.html` 的字符串变换。

它**没有请求中间件**：请求一进来就按「精确表 → 最长前缀 → 兜底」直接命中某个处理器。而 Web 面实际有**三条通道**：

1. 静态资源 + SPA（由 `frontend-static` 占住兜底座位）；
2. `/api/*` 的 JSON-RPC + SSE（由 `client-connection` 注册前缀路由，经 `http-bridge` 桥接到网关）；
3. WebSocket upgrade（由 `client-connection` 注册升级路由）。

一个「插件」想在这三条通道**之前**统一鉴权，唯一办法是抢先占住兜底座位、并重注册 `/api` 前缀与升级路由，等于把 `frontend-static`、`connection` 的实现都替换一遍。这既脆弱（与 DSH 内部实现耦合）又不可维护，而且 `/api` 前缀是单一注册、占位即冲突。

结论：**进程内网关在 DSH 当前架构下不可行也不应做**。正确做法与 Open WebUI 官方推荐一致——**反向代理**。DSH 收紧到回环监听，由独立网关承担认证，再反代到 DSH。

## 会话模型

会话采用 Hermes `dashboard_auth/basic` 的无状态 HMAC 签名 token，并额外加了两个硬化点：

- **`pv`（password generation，口令代际）**：token 负载里带 `pv`，状态文件里存当前 `pv`。改密时 `pv += 1`，所有旧 token 因代际不匹配立即失效——一次操作让全部旧会话下线，无需扫描会话表。
- **`jti`（token id）+ 内存吊销表**：登出与 refresh 轮换时把单个 token 的 `jti` 加入吊销表（按 `exp` 惰性淘汰），用于「吊销某一个会话」而非「全部」。

token 格式：`base64url(JSON(payload) || HMAC-SHA256(JSON(payload)))`。HMAC 后缀定长 32 字节，无需分隔符。

| 字段 | 说明 |
| --- | --- |
| `sub` | 主体（配置的用户名） |
| `kind` | `access` / `refresh` |
| `jti` | 随机 token id |
| `pv` | 口令代际 |
| `iat` / `exp` | 签发/过期时间（epoch 秒） |

- access token 默认 12h，放在 `HttpOnly; SameSite=Strict` Cookie 里，随每次请求携带。
- refresh token 默认 30d，仅在 access 过期时被网关消费；网关验到「access 过期但 refresh 有效」时**透明轮换**：吊销旧 refresh、签发新 access+refresh，并把新 Cookie 合并进响应（HTTP 与 WebSocket 101 都支持）。

## 密码学

- **口令哈希**：`scrypt`，N=2^14, r=8, p=1, dklen=32, salt=16B，与 Hermes 相同参数（RFC 7914 交互式登录档位，约 16 MiB 内存）。格式 `scrypt$N$r$p$<salt_b64>$<dk_b64>`。
- **比较**：`crypto.timingSafeEqual` 恒定时间比较派生密钥，避免时序侧信道。
- **签名密钥**：首次运行用 `crypto.randomBytes(32)` 生成，base64 存于状态文件。未显式配置 `secret` 时每次首跑生成随机密钥（等价 Hermes 的行为）。

## 状态与配置的分离

- **配置**（`dsh-web-gate.config.json` + 环境变量）：非敏感的可调项——监听/上游地址、TTL、Cookie 属性、限流参数等。可提交、可分享。
- **状态**（`dsh-web-gate.state.json`，权限 0600）：敏感项——scrypt 口令哈希、签名密钥、`pv`。原子写入（临时文件 + `rename`），**绝不提交**。

口令的明文只存在于「首次运行设置」与「改密请求」的瞬间，磁盘与内存常态均只有哈希。

## 反向代理语义

- **Host 透传（默认 `forwardHost: preserve`）**：DSH 的 `/api` 信任栅栏用 `Host` + `Origin` 判断同源，且要求 `Host` 是回环或已登记的 `--trusted-host`。网关默认保留浏览器的原始 `Host`，因此：
  - 本地回环场景开箱即用；
  - 非回环部署需在 DSH 侧登记网关的公开 authority：`dsh web --trusted-host <public-host>:<gateway-port>`。
  - 也可用 `forwardHost: target` 强制改写为上游地址（此时需自行处理 Origin 一致性）。
- **网关自身 Cookie 不外泄**：反代前剥离网关自己的 `*_access` / `*_refresh` Cookie，上游（DSH）不接触会话 token。
- **流式透传**：响应体用 `pipe` 透传，SSE 长连接按块转发；客户端中断会中止上游请求。
- **WebSocket**：`upgrade` 事件鉴权后，与上游建立升级连接并双向 `pipe`；101 响应补回 `Connection/Upgrade` 头（跳-by-hop 头在转发时会剥掉）。
- **连接复用**：上游请求使用 `agent: false`（每次新连接、用完即关），对单用户网关足够，且避免遗留连接；也避免了测试/关闭时连接池挂起。
- **关闭语义**：升级后的 socket 不会被 Node 的连接跟踪覆盖（`close()`/`closeAllConnections()` 都不关它们），网关显式跟踪升级 socket 并在关闭时销毁，保证停机不悬挂。

## 限流

- **登录限流**（默认 5 次 / 15 分钟窗口，锁定 15 分钟）：按客户端 IP 计数，失败达到阈值即锁定；成功登录清零。锁定期间即便口令正确也返回 429。
- **全局限流**（可选，默认关闭）：每 IP 令牌桶，`capacity` / `refillPerSecond` 可调，用于粗粒度抗滥用。

## Fail-closed

网关默认**拒绝在没有口令的情况下启动**：

- 有 `DSH_WEB_GATE_PASSWORD` / 配置文件 `password` / TTY 交互 → 设置口令哈希；
- 都没有且非交互 → 抛错退出，而不是「无认证放行」；
- 显式 `--insecure` 才关闭认证，并打印醒目警告。

这与 Hermes「无凭据则 dashboard 拒绝启动（除非 `--insecure`）」的策略一致，避免「配置漏了反而裸奔」。
