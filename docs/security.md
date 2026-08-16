# 安全模型

## 威胁模型与防护

| 威胁 | 防护 |
| --- | --- |
| 未授权访问 Web GUI | 三条通道（静态 / `/api` SSE / WebSocket）统一鉴权，未认证一律拒绝 |
| 口令暴力破解 | 登录限流 + 锁定；scrypt 内存硬函数提高单次成本 |
| 口令泄露（磁盘） | 只存 scrypt 哈希，状态文件 0600；明文仅存在于首次设置/改密瞬间 |
| 口令泄露（内存） | 验证后即丢弃明文；token 用 HMAC 签名而非加密，无需口令参与 |
| 会话 token 被窃取 | Cookie `HttpOnly`（脚本不可读）+ `SameSite=Strict` + 可选 `Secure`；access 短寿命 + 透明轮换 |
| 改密后旧会话残留 | `pv` 代际 bump，旧 token 立即失效 |
| 单个会话被窃取后的登出 | `jti` 吊销表（登出时写入；refresh 续期不吊销，见 architecture.md） |
| CSRF | `SameSite=Strict` Cookie + 网关自身写操作同源校验；DSH 自身的 `/api` Origin/Host 栅栏继续生效 |
| DNS rebinding / 跨站读取 | 网关自身页面带严格 CSP + `X-Frame-Options: DENY`；DSH 的 Host 栅栏继续生效 |
| 会话 token 泄露给上游 | 反代前剥离网关自己的 Cookie，DSH 不接触 token |
| 响应劫持/注入 | 网关自身页面 `default-src 'none'`（无脚本）、`nosniff`、`no-store`、`frame-ancestors 'none'` |
| 上游失联 | 502；不把内部错误细节回显给客户端 |
| 请求体过大 | 登录/改密请求体上限 64 KiB，超限返回 413 |
| 停机悬挂 | 升级 socket 显式跟踪并在关闭时销毁 |

## 安全边界（诚实声明）

本网关解决的是「**谁**能进入 Web 界面」这一层。它**不**覆盖：

- **传输加密**：网关本身是纯 HTTP。公网部署必须在前面接 TLS 终止（nginx/Caddy/Cloudflare），并设 `DSH_WEB_GATE_COOKIE_SECURE=true`。
- **DSH 自身的授权/沙箱**：网关放行后，进入的是 DSH 的完整能力面（含执行代码、读写文件的 agent）。口令应当足够强，且建议仅对可信用户开放。网关不改变 DSH 内部的沙箱与审批策略。
- **多用户 / 角色 / SSO**：当前是单口令单用户。如需多用户或 OIDC/SSO，请参考 Open WebUI 的 auth 层或在网关前加 OAuth2 代理（如 oauth2-proxy / Authelia）。
- **审计日志**：网关默认不在磁盘记录访问日志；如需审计，接在网关前的反向代理/ingress 层采集，或在网关上自行扩展。
- **秘密轮换**：`set-password` 会轮换口令哈希并 bump `pv`；签名密钥的显式轮换需替换状态文件中的 `secret`（会使所有会话失效）。

## 部署检查清单

- [ ] DSH Web GUI 仅监听 `127.0.0.1`（或防火墙封住 3080），不直接暴露。
- [ ] 网关监听公网接口，前置 TLS 终止。
- [ ] `DSH_WEB_GATE_COOKIE_SECURE=true`（HTTPS 下）。
- [ ] 非回环部署在 DSH 侧登记网关 authority：`dsh web --trusted-host <public-host>:<gateway-port>`。
- [ ] 首次启动设置强口令（≥12 字符，避免字典/泄露口令）。
- [ ] 状态文件权限 0600，目录权限收紧。
- [ ] 状态文件纳入备份但不进版本控制 / 容器镜像。
- [ ] 不设置 `DSH_WEB_GATE_INSECURE=1`（除非明确知道后果）。
- [ ] 如网关前还有代理，按需开启 `DSH_WEB_GATE_TRUST_PROXY`（信任 `X-Forwarded-For`）。

## 已知限制与后续方向

- 单口令单用户，无多账户、无角色。
- 登录限流为进程内存态，多副本部署时需外部分布式限流。
- 吊销表为内存态（重启清空）；重启后旧 token 仅依赖 `pv` 与签名密钥，若密钥未轮换则长寿命 refresh token 理论上仍有效直到过期。需要「重启也吊销」时，可在状态文件持久化 `jti` 吊销表（当前未做，属有意权衡）。
