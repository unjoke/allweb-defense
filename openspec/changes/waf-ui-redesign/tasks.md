## 1. WAF Dashboard 后端

- [x] 1.1 在 `waf/` 下新建 `dashboard.py`，实现 aiohttp Dashboard app，包含 `/`（主页）和 `/events`（SSE）两个路由
- [x] 1.2 实现 SSE 端点：异步 tail `security.log`，从文件末尾开始，每 0.5s 检查新行，推送新增行，30s 无新行发送 keepalive
- [x] 1.3 实现内存攻击统计计数器（按攻击类型），在 SSE 推送时同步更新，通过 `/stats` JSON 端点暴露
- [x] 1.4 修改 `waf/proxy.py` 的 `main()` 函数，使用 `aiohttp.web.AppRunner` 同时启动代理（:8080）和 Dashboard（:8081）
- [x] 1.5 Dashboard 主页路由读取当前 `config["rules"]` 状态，传入模板渲染

## 2. WAF Dashboard 前端模板

- [x] 2.1 新建 `waf/templates/` 目录，创建 `dashboard.html`：黑白线条风格，顶部显示规则状态列表，中部显示攻击统计卡片，底部显示实时日志流
- [x] 2.2 在 `dashboard.html` 中实现 SSE 客户端 JS：连接 `/events`，新日志行插入日志列表顶部，同步更新统计计数器

## 3. 前端主题基础层

- [x] 3.1 重写 `shared/templates/base.html`：移除 Bootstrap CDN，定义全局 CSS（黑底、白字、monospace、直角、红色顶边线导航栏），保留所有 Jinja2 变量和 block 结构
- [x] 3.2 在 `base.html` 中实现原生 JS 的 flash 消息关闭功能（替代 Bootstrap JS）

## 4. 应用页面模板重写

- [x] 4.1 重写 `shared/templates/login.html`：直角输入框，白底黑字登录按钮，无卡片阴影
- [x] 4.2 重写 `shared/templates/register.html`：与 login 风格一致
- [x] 4.3 重写 `shared/templates/messages.html`：留言列表用线条分隔替代卡片，发布按钮白底黑字，删除按钮红色线条
- [x] 4.4 重写 `shared/templates/search.html`：搜索框直角，结果列表线条风格
- [x] 4.5 重写 `shared/templates/profile.html`：两个功能区用线条分隔，按钮风格统一
- [x] 4.6 重写 `shared/templates/admin_users.html`：表格线条风格，角色标签改为 [ADMIN]/[USER] 文本
- [x] 4.7 重写 `shared/templates/admin_messages.html`：文件列表线条风格，删除按钮红色
- [x] 4.8 重写 `shared/templates/403.html`：黑底红字错误页，显示 "403 FORBIDDEN"
- [x] 4.9 重写 `shared/templates/429.html`：黑底红字错误页，显示 "429 TOO MANY REQUESTS"

## 5. 拦截响应主题化（验证阶段补加）

- [x] 5.1 修改 `waf/proxy.py` 的 `_blocked()`：当 status 为 403/429 时，渲染 `shared/templates/403.html`/`429.html` 返回 HTML 而不是 plain text；为独立 Jinja2 提供 `get_flashed_messages` stub 兼容 base.html

## 6. 验证

- [x] 6.1 启动 vulnerable app（:5000）和 WAF（:8080/:8081），验证代理正常转发
- [x] 6.2 访问 Dashboard（:8081），验证规则状态和统计显示正确
- [x] 6.3 发送一个 SQL 注入请求，验证 Dashboard 实时收到拦截日志并更新计数（SSE 客户端连接时计数 +1）
- [x] 6.4 触发 403/429，确认返回 HTML（6.4 KB / 6.5 KB）而非 plain text，包含 WAF-DEMO 品牌、CSS 变量、无 Bootstrap 引用
- [x] 6.5 模板渲染验证：所有 10 个 shared/templates 页面 Jinja2 解析通过，无 Bootstrap 残留
