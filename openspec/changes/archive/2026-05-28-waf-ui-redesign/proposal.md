## Why

当前项目以"漏洞版 vs 防护版"双 App 对比的方式展示安全防护，但这种方式需要维护两套应用代码，且无法直观展示 WAF 的实时拦截过程。改为"WAF 代理直接保护漏洞版应用"的单一演示路径，并为 WAF 增加实时日志 Dashboard，能更清晰地展示通防 WAF 的核心价值。同时，现有前端使用 Bootstrap 5 圆润风格，与安全工具的专业气质不符，需要重设计为黑白配色、线条感强的成熟风格。

## What Changes

- **移除 `app/protected` 的展示入口**：保留代码文件但不再在任何 UI 或文档中引导用户访问 :5001，演示路径统一为 WAF(:8080) → vulnerable app(:5000)
- **新增 WAF Dashboard**：WAF 在独立端口（:8081）提供实时日志查看界面，展示拦截记录、攻击类型统计、规则开关状态
- **全站前端重设计**：`shared/templates/` 下所有 10 个模板从 Bootstrap 圆润风格重写为黑白配色、直角、线条感强的终端/工业风格
- **WAF Dashboard 模板**：新增 WAF 专属模板目录 `waf/templates/`，包含 dashboard 主页

## Capabilities

### New Capabilities

- `waf-dashboard`: WAF 实时日志 Dashboard，独立 Web 界面，展示拦截日志流、攻击类型分布、规则启用状态
- `frontend-theme`: 全站黑白锐利主题，替换 Bootstrap 圆润风格，统一应用于 shared/templates 所有页面

### Modified Capabilities

- `waf-proxy`: WAF 代理新增 Dashboard 子服务，在 :8081 端口提供管理界面（现有代理逻辑不变）

## Impact

- `waf/proxy.py`：新增 Dashboard HTTP 服务器（独立 aiohttp app 或子路由）
- `waf/templates/`：新建目录，存放 Dashboard HTML 模板
- `shared/templates/*.html`：全部重写，移除 Bootstrap 依赖，改用自定义 CSS
- `app/protected/`：代码保留，不删除，但不再被任何入口引用
- `security.log`：Dashboard 读取此文件实时展示
