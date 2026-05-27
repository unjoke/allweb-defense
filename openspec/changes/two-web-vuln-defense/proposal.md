## Why

现有通防中间件（`app/protected/middleware.py`）通过 Flask `before_request` 钩子绑定在留言系统上，与业务代码耦合，无法保护其他语言或框架编写的后端。本 change 将通防能力提取为独立的反向代理进程，实现语言无关的通用 WAF，同时保留原有 Flask 内嵌通防作为对比演示。

## What Changes

- 新增 `waf/` 目录，实现基于 `aiohttp` 的异步反向代理 WAF 进程
- 新增 `waf/detector.py`，从 `middleware.py` 提取所有纯检测函数，去除 Flask 依赖
- 新增 `waf/config.py`，支持命令行参数与 YAML 配置文件两种方式，命令行优先
- 新增 `waf/config.yaml`，提供默认配置（监听端口、后端地址、规则开关、频率限制参数）
- 新增 `tests/test_detector.py`，对 `detector.py` 中的纯函数进行单元测试
- 更新 `requirements.txt`，新增 `aiohttp==3.9.5` 和 `pyyaml==6.0.2`

## Capabilities

### New Capabilities

- `waf-proxy`: 独立反向代理 WAF 进程，监听可配置端口，对所有入站请求执行安全检测后转发给后端；支持 SQL 注入、XSS、路径穿越、命令注入、文件上传、频率限制检测，以及安全响应头注入
- `waf-config`: WAF 配置加载模块，支持 YAML 文件与命令行参数混合配置，命令行参数优先覆盖文件配置
- `waf-detector`: 框架无关的安全检测函数库，所有函数无副作用，可独立单元测试

### Modified Capabilities

## Impact

- 新增依赖：`aiohttp==3.9.5`、`pyyaml==6.0.2`
- `app/protected/middleware.py` 保留不动，作为"Flask 内嵌通防"演示
- `app/vulnerable/app.py`（端口 5000）无需改动，直接作为 WAF 代理的后端目标
- 攻击演示脚本可改为打 WAF 代理端口（8080），验证代理层拦截效果
- 课设报告新增"绑定式通防 vs 代理式通防"对比章节
