## ADDED Requirements

### Requirement: SQL 注入攻击脚本
攻击演示 SHALL 提供 Python 脚本，自动向目标 URL 发送 SQL 注入 payload（登录绕过 + UNION 注入），并输出响应状态码和关键响应内容。

#### Scenario: 脚本对漏洞版成功注入
- **WHEN** 脚本以漏洞版地址为目标运行
- **THEN** 脚本输出登录成功标志或数据库内容，状态码 200

#### Scenario: 脚本对防护版被拦截
- **WHEN** 脚本以防护版地址为目标运行
- **THEN** 脚本输出状态码 403 和拦截提示

### Requirement: XSS 攻击脚本
攻击演示 SHALL 提供 Python 脚本，向留言板提交存储型 XSS payload，并验证 payload 是否出现在响应页面中。同时提供 `xss_payload.txt` 包含至少 8 种 XSS payload 变体（含编码绕过变体）。

#### Scenario: 存储型 XSS payload 被写入并返回
- **WHEN** 脚本向漏洞版留言板提交 XSS payload
- **THEN** 脚本验证留言列表页面包含未转义的 payload

### Requirement: CSRF 演示页面
攻击演示 SHALL 提供一个静态 HTML 页面，包含自动提交的伪造修改密码表单，模拟跨站请求伪造攻击。

#### Scenario: CSRF 页面对漏洞版成功伪造
- **WHEN** 已登录用户在浏览器中打开该 HTML 页面
- **THEN** 表单自动提交到漏洞版应用，密码被修改

### Requirement: 越权访问攻击脚本
攻击演示 SHALL 提供 Python 脚本，演示水平越权（访问他人留言）和垂直越权（普通用户访问 admin 接口）。

#### Scenario: 垂直越权访问 admin 接口
- **WHEN** 脚本以普通用户 session 请求 `/admin/users`
- **THEN** 漏洞版返回 200 和用户列表，防护版返回 403

### Requirement: 路径穿越攻击脚本
攻击演示 SHALL 提供 Python 脚本，通过构造 `../` 序列尝试读取应用源码或系统文件。

#### Scenario: 路径穿越读取文件
- **WHEN** 脚本请求 `/download?filename=../../app.py`
- **THEN** 漏洞版返回文件内容，防护版返回 403

### Requirement: 命令注入攻击脚本
攻击演示 SHALL 提供 Python 脚本，以 admin session 向留言文件删除接口提交包含 shell 特殊字符的 `filename` 参数，验证命令是否被执行。

#### Scenario: 命令注入执行系统命令
- **WHEN** 脚本以 admin session 提交 `filename=msg_001.txt; id`
- **THEN** 漏洞版返回包含系统用户信息的输出，防护版返回 403

### Requirement: 暴力破解攻击脚本
攻击演示 SHALL 提供 Python 脚本，对登录接口连续发送错误密码请求，验证是否触发频率限制。

#### Scenario: 暴力破解触发限制
- **WHEN** 脚本连续发送 15 次错误密码请求
- **THEN** 漏洞版全部返回 200（登录失败页），防护版在第 11 次后返回 429
