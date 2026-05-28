## ADDED Requirements

### Requirement: Dashboard 子服务共存
WAF 代理 SHALL 在启动时同时运行 Dashboard 子服务（:8081），两个服务共享同一 asyncio event loop 和配置对象。

#### Scenario: 双服务同时运行
- **WHEN** 执行 `python -m waf` 启动 WAF
- **THEN** :8080 代理服务和 :8081 Dashboard 服务均正常响应请求，互不干扰

#### Scenario: 启动日志输出
- **WHEN** WAF 启动成功
- **THEN** stderr 输出两行：代理监听信息和 Dashboard 监听信息
