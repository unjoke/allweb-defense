# 漏洞修复方案总结

本文档用于替代原来的 `app/protected/` 防护版代码。项目现在只保留漏洞应用和独立 WAF，修复思路在这里集中说明，便于课程报告、答辩和后续迁移到真实项目。

## 总体修复策略

建议采用两层防护：

1. 应用层修复：在业务代码中消除漏洞根因，例如参数化查询、权限校验、CSRF Token、路径归一化。
2. WAF 层缓解：在反向代理入口拦截高风险 payload，降低已知攻击和误配置带来的风险。

WAF 不能替代应用层修复。WAF 更适合作为统一入口、防护兜底、日志审计和临时缓解手段。

## 需要修复的点

| 漏洞类型 | 当前风险位置 | 修复建议 |
|---|---|---|
| SQL 注入 | 登录、搜索接口拼接 SQL | 使用参数化查询，不把用户输入直接拼入 SQL；生产环境关闭原始 SQL 错误回显。 |
| 存储型 XSS | 留言内容原样保存并渲染 | 渲染时默认 HTML 转义；如允许富文本，使用白名单 HTML sanitizer。 |
| 反射型 XSS | 搜索词回显到页面 | 对输出内容进行 HTML 编码；配合 CSP 降低脚本执行风险。 |
| CSRF | 修改密码、删除等 POST 操作 | 为状态变更请求加入 CSRF Token；Cookie 设置 `SameSite=Lax` 或 `Strict`。 |
| 路径穿越 | 下载接口直接拼接文件名 | 使用 `realpath`/`resolve` 归一化路径，并校验最终路径必须位于允许目录内。 |
| 命令注入 | 管理员文件删除使用 `shell=True` | 避免 shell；使用语言内置文件 API 或 `subprocess.run([...], shell=False)`。 |
| 水平越权 | 用户可删除非本人资源 | 每次操作资源前校验 `resource.owner_id == session.user_id`。 |
| 垂直越权 | 普通用户可访问管理接口 | 为管理路由统一加入角色校验，例如 `role == "admin"`。 |
| 不安全文件上传 | 上传文件缺少类型校验 | 使用扩展名白名单、magic bytes 校验、大小限制和随机文件名；上传目录禁止执行脚本。 |
| 暴力破解 | 登录接口缺少失败限制 | 按 IP/账号记录失败次数，超过阈值后短时锁定；避免信任可伪造的 `X-Forwarded-For`。 |

## WAF 配置建议

默认 WAF 配置位于 `waf/config.yaml`。挂载其他项目时重点修改：

```yaml
listen_port: 8080
backend_url: "http://127.0.0.1:5000"
login_path: "/login"
```

- `listen_port` 是 WAF 对外入口。
- `backend_url` 是真实后端地址。
- `login_path` 用于暴力破解限速规则。

如果要按路径裁剪检测规则，可以在主配置中加入：

```yaml
url_rules_file: "waf/url_rules.example.yaml"
```

URL 规则示例：

```yaml
rules:
  - url: /search
    detect: [SQL, XSS]
  - url: /upload/*
    detect: [UPLOAD, PATH]
  - url: /*
    detect: [SQL, XSS, PATH, CMD, UPLOAD]
```

规则从上到下匹配，第一个命中的规则生效。更具体的路径应放在前面，`/*` 应放在最后。

## 源站绕过修复

WAF 有效的前提是攻击者不能直接访问后端源站。当前本地实验建议：

- 后端应用只监听 `127.0.0.1`。
- 对外只暴露 WAF 端口。
- 不要把漏洞应用绑定到 `0.0.0.0`。

分布式部署时还应使用防火墙、内网安全组、反代专用请求头、mTLS 或 HMAC 请求签名，防止攻击者绕过 WAF 直连源站。

## 清理后的项目边界

项目现在保留三类核心内容：

- `app/vulnerable/`：故意存在漏洞的演示应用。
- `waf/`：独立反向代理 WAF。
- `evaluation/` 和 `attacks/`：攻击复现与检测效果评估。

原 `app/protected/` 已删除，避免同时维护两套业务代码造成结构混乱。修复方案以本文档为准。
