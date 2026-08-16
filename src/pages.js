/**
 * The gateway's own HTML pages (login and change-password). Pure HTML + inline
 * CSS, no JavaScript, so they render under a strict Content-Security-Policy
 * with no script surface. Product copy is Chinese; the gate is a small,
 * self-contained screen in front of the DeepSeek Harness Web GUI.
 */

function escapeHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

const CSS = `
:root {
  color-scheme: dark;
  --bg: #0e1116;
  --bg-card: #161b22;
  --border: #2a313c;
  --text: #e6edf3;
  --muted: #8b949e;
  --accent: #4c8dff;
  --accent-strong: #2f6fe0;
  --error-bg: #3a1d1d;
  --error-fg: #ff8f8f;
  --ok-bg: #123a24;
  --ok-fg: #7ee2a8;
}
* { box-sizing: border-box; }
html, body { height: 100%; margin: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC",
    "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
}
.card {
  width: 100%;
  max-width: 360px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 28px;
}
.logo {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 6px;
}
.logo-mark {
  width: 30px; height: 30px; border-radius: 8px;
  background: linear-gradient(135deg, var(--accent), #7c5cff);
  display: inline-flex; align-items: center; justify-content: center;
  font-weight: 700; color: #fff; flex: 0 0 auto;
}
h1 { font-size: 18px; margin: 0; font-weight: 600; }
.sub { color: var(--muted); font-size: 13px; margin: 8px 0 22px; line-height: 1.5; }
label { display: block; font-size: 13px; color: var(--muted); margin-bottom: 6px; }
input[type="password"] {
  width: 100%; padding: 10px 12px; font-size: 15px;
  background: #0d1117; color: var(--text);
  border: 1px solid var(--border); border-radius: 8px;
  outline: none;
}
input[type="password"]:focus { border-color: var(--accent); box-shadow: 0 0 0 2px rgba(76,141,255,0.25); }
.check { display: flex; align-items: center; gap: 8px; margin: 14px 0; font-size: 13px; color: var(--muted); }
.check input { accent-color: var(--accent); }
button {
  width: 100%; padding: 10px 12px; font-size: 15px; font-weight: 600;
  background: var(--accent); color: #fff; border: 0; border-radius: 8px;
  cursor: pointer;
}
button:hover { background: var(--accent-strong); }
.msg { padding: 10px 12px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; }
.msg.error { background: var(--error-bg); color: var(--error-fg); }
.msg.ok { background: var(--ok-bg); color: var(--ok-fg); }
.hint { font-size: 12px; color: var(--muted); margin-top: 14px; line-height: 1.5; }
.meta { margin-top: 22px; padding-top: 16px; border-top: 1px solid var(--border); font-size: 12px; color: var(--muted); }
.meta a { color: var(--accent); text-decoration: none; }
button.linklike {
  display: inline; width: auto; padding: 0; margin: 0;
  background: none; border: 0; color: var(--accent);
  font: inherit; font-size: 12px; font-weight: 400; text-decoration: none; cursor: pointer;
}
button.linklike:hover { background: none; text-decoration: underline; }
.row { margin-bottom: 14px; }
`

function shell(title, bodyHtml) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${escapeHtml(title)}</title>
<style>${CSS}</style>
</head>
<body>
${bodyHtml}
</body>
</html>`
}

/**
 * Render the login page.
 * @param {object} args
 * @param {string} [args.error] - error message to show.
 * @param {string} [args.next] - path to return to after login.
 */
export function loginPage({ error = '', next = '' } = {}) {
  const errorHtml = error
    ? `<div class="msg error">${escapeHtml(error)}</div>`
    : ''
  return shell('登录 · DeepSeek Harness Web Gate', `
<div class="card">
  <div class="logo"><span class="logo-mark">D</span><h1>DeepSeek Harness Web Gate</h1></div>
  <p class="sub">该 Web 界面受访问口令保护。请输入口令以继续。</p>
  ${errorHtml}
  <form method="post" action="/auth/login">
    <input type="hidden" name="next" value="${escapeHtml(next)}">
    <div class="row">
      <label for="password">访问口令</label>
      <input type="password" id="password" name="password" autocomplete="current-password" autofocus required>
    </div>
    <div class="check">
      <input type="checkbox" id="remember" name="remember" value="1" checked>
      <label for="remember" style="margin:0; cursor:pointer;">在此设备保持登录（30 天）</label>
    </div>
    <button type="submit">进入</button>
  </form>
  <p class="hint">连续多次输入错误将触发临时锁定。口令可在登录后的「设置」页面修改。</p>
</div>`)
}

/**
 * Render the change-password page (authenticated).
 * @param {object} args
 * @param {string} [args.error]
 * @param {string} [args.success]
 * @param {string} [args.username]
 */
export function settingsPage({ error = '', success = '', username = '' } = {}) {
  const errorHtml = error
    ? `<div class="msg error">${escapeHtml(error)}</div>`
    : ''
  const successHtml = success
    ? `<div class="msg ok">${escapeHtml(success)}</div>`
    : ''
  return shell('设置 · DeepSeek Harness Web Gate', `
<div class="card">
  <div class="logo"><span class="logo-mark">D</span><h1>网关设置</h1></div>
  <p class="sub">修改访问口令。修改后，所有其他已登录设备都将立即失效。</p>
  ${errorHtml}${successHtml}
  <form method="post" action="/auth/change-password">
    <div class="row">
      <label for="current">当前口令</label>
      <input type="password" id="current" name="current" autocomplete="current-password" autofocus required>
    </div>
    <div class="row">
      <label for="password">新口令</label>
      <input type="password" id="password" name="password" autocomplete="new-password" minlength="8" required>
    </div>
    <div class="row">
      <label for="confirm">确认新口令</label>
      <input type="password" id="confirm" name="confirm" autocomplete="new-password" minlength="8" required>
    </div>
    <button type="submit">保存新口令</button>
  </form>
  <div class="meta">
    当前用户：<strong>${escapeHtml(username)}</strong><br>
    <a href="/">返回 Web 界面</a> ·
    <form method="post" action="/auth/logout" style="display:inline; margin:0;">
      <button type="submit" class="linklike">退出登录</button>
    </form>
  </div>
</div>`)
}
