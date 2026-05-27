## 1. 依赖与目录结构

- [ ] 1.1 在 `requirements.txt` 中新增 `aiohttp==3.9.5` 和 `pyyaml==6.0.2`
- [ ] 1.2 创建 `waf/` 目录，添加 `waf/__init__.py`（空文件）

## 2. waf/detector.py — 框架无关检测函数库

- [ ] 2.1 从 `app/protected/middleware.py` 提取 `detect_sql_injection`、`sanitize_xss`、`detect_path_traversal`、`detect_cmd_injection`、`is_allowed_extension` 五个纯函数，去除所有 Flask 导入，写入 `waf/detector.py`
- [ ] 2.2 将频率限制函数 `check_rate_limit` 和 `record_login_failure` 改写为接受外部 `state: dict` 和 `config: dict` 参数（不使用全局变量），写入 `waf/detector.py`
- [ ] 2.3 验证 `import waf.detector` 在无 Flask 环境下成功

## 3. waf/config.py — 配置加载模块

- [ ] 3.1 实现 `load_config(args) -> dict`：先读取 YAML 文件（`--config` 指定路径或默认 `waf/config.yaml`），再用命令行非 None 参数覆盖对应字段，返回合并后的配置字典
- [ ] 3.2 实现 `build_arg_parser() -> ArgumentParser`：定义 `--listen`、`--backend`、`--config`、`--disable` 参数
- [ ] 3.3 编写 `waf/config.yaml` 默认配置文件，包含 `listen_port`、`backend_url`、`rules`（各规则开关）、`rate_limit`（`max_failures`、`window`、`lockout`）、`log_path`

## 4. waf/proxy.py — 异步反向代理主入口

- [ ] 4.1 实现请求处理函数 `handle_request(request, config, state, logger)`：提取 GET 参数、POST 表单、上传文件名，依次调用 detector 函数，命中则返回对应错误响应并记录日志
- [ ] 4.2 实现 XSS 净化逻辑：对 GET/POST 参数值调用 `sanitize_xss`，将净化后的值写入转发请求
- [ ] 4.3 实现请求转发：使用 `aiohttp.ClientSession` 将通过检测的请求（保留原始 method、headers、body）转发给后端，替换 Host header
- [ ] 4.4 实现响应处理：将后端响应注入安全响应头（CSP、X-Frame-Options、X-Content-Type-Options、X-XSS-Protection、Referrer-Policy）后返回给客户端
- [ ] 4.5 实现 `main()` 入口：解析参数，加载配置，初始化 aiohttp web.Application，启动服务器
- [ ] 4.6 添加 `waf/__main__.py`，使 `python -m waf.proxy` 可直接启动

## 5. tests/test_detector.py — 单元测试

- [ ] 5.1 为 `detect_sql_injection` 编写正例（UNION 注入、OR 注入）和反例（正常字符串）测试用例
- [ ] 5.2 为 `sanitize_xss` 编写正例（script 标签、javascript: 协议、on* 事件）和反例测试用例
- [ ] 5.3 为 `detect_path_traversal` 编写正例（`../`、URL 编码变体）和反例测试用例
- [ ] 5.4 为 `detect_cmd_injection` 编写正例（`;`、`&&`、`|`）和反例测试用例
- [ ] 5.5 为 `is_allowed_extension` 编写白名单内和白名单外的测试用例
- [ ] 5.6 为频率限制函数编写超阈值锁定和未超阈值不锁定的测试用例
- [ ] 5.7 运行 `pytest tests/test_detector.py`，确认全部通过

## 6. 集成验证

- [ ] 6.1 安装新依赖：`pip install aiohttp==3.9.5 pyyaml==6.0.2`
- [ ] 6.2 启动漏洞版后端（端口 5000），启动 WAF 代理（端口 8080，后端指向 5000）
- [ ] 6.3 对 8080 端口重放 SQL 注入、路径穿越、命令注入攻击，验证均返回 403 并写入 security.log
- [ ] 6.4 对 8080 端口重放 XSS payload，验证参数被净化后转发
- [ ] 6.5 验证正常业务请求（登录、留言、搜索）通过代理后功能正常
- [ ] 6.6 验证所有响应包含安全响应头
