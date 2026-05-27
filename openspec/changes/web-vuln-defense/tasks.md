## 1. 环境搭建

- [x] 1.1 初始化项目目录结构（app/vulnerable、app/protected、attacks、tests、shared/templates、shared/static）
- [x] 1.2 创建 requirements.txt，添加 Flask、requests 依赖
- [x] 1.3 编写数据库初始化脚本 init_db.py，创建 users（含 role 字段）、messages、files 表，插入 admin 和普通用户测试数据；创建 `messages/` 目录用于存储留言 txt 文件

## 2. 漏洞版应用 — 基础功能

- [x] 2.1 实现登录/注册路由，登录使用字符串拼接 SQL（SQL 注入漏洞）
- [x] 2.2 实现留言发布路由，内容同时写入数据库和 `messages/msg_<id>_<username>.txt` 文件，原样渲染到页面（存储型 XSS）
- [x] 2.3 实现留言搜索路由，将 `q` 参数直接反射到页面（反射型 XSS + SQL 注入）
- [x] 2.4 实现修改密码路由，不含 CSRF Token 校验（CSRF 漏洞）
- [x] 2.5 实现文件下载路由，直接拼接 `filename` 参数（路径穿越漏洞）
- [x] 2.6 实现留言删除路由，不校验留言归属（水平越权漏洞）
- [x] 2.7 实现 admin 用户管理路由，后端不校验角色（垂直越权漏洞）
- [x] 2.8 实现头像上传路由，不校验文件扩展名（不安全文件上传漏洞）
- [x] 2.9 实现 admin 留言文件删除路由，使用 `subprocess.run("rm messages/" + filename, shell=True)` 拼接执行（命令注入漏洞）
- [x] 2.10 开启 Flask debug=True，使异常返回完整堆栈（敏感信息泄露）
- [x] 2.11 创建全部 HTML 模板（登录页、注册页、留言板、搜索结果页、个人设置页、admin 用户管理页、admin 留言文件管理页）
- [x] 2.12 手动验证 10 类漏洞均可复现

## 3. 通防安全中间件

- [x] 3.1 实现 `before_request` 钩子框架，提取所有 GET/POST 参数和上传文件信息
- [x] 3.2 实现 SQL 注入检测函数（关键字正则匹配）
- [x] 3.3 实现 XSS 检测与净化函数（HTML 实体编码）
- [x] 3.4 实现路径穿越检测函数（`../` 序列检查）
- [x] 3.5 实现命令注入检测函数（shell 特殊字符检查）
- [x] 3.6 实现 CSRF Token 生成与验证逻辑（基于 Flask session）
- [x] 3.7 实现路由权限表和越权访问控制逻辑（角色校验 + 资源归属校验）
- [x] 3.8 实现文件上传扩展名白名单校验
- [x] 3.9 实现登录频率限制（基于内存字典，IP + 时间窗口）
- [x] 3.10 实现 `after_request` 钩子，注入 CSP、X-Frame-Options 等安全响应头
- [x] 3.11 实现拦截日志记录，写入 security.log

## 4. 防护版应用

- [ ] 4.1 复制漏洞版业务逻辑，修改登录和搜索 SQL 为参数化查询
- [ ] 4.2 在 app 初始化时注册通防中间件
- [ ] 4.3 在所有状态变更表单模板中添加 CSRF Token 隐藏字段
- [ ] 4.4 关闭 Flask debug 模式，配置自定义错误页面
- [x] 4.5 验证防护版对 10 类攻击均返回 403/429 或净化处理

## 5. 攻击演示脚本

- [x] 5.1 编写 `attacks/sql_injection.py`（登录绕过 + UNION 注入）
- [x] 5.2 编写 `attacks/xss_demo.py`（存储型 XSS 提交与验证）
- [x] 5.3 编写 `attacks/xss_payload.txt`（至少 8 种 XSS payload 变体）
- [x] 5.4 编写 `attacks/csrf_demo.html`（自动提交的伪造修改密码表单）
- [x] 5.5 编写 `attacks/privilege_escalation.py`（水平越权 + 垂直越权）
- [x] 5.6 编写 `attacks/path_traversal.py`（路径穿越读取文件）
- [x] 5.7 编写 `attacks/cmd_injection.py`（以 admin session 向留言文件删除接口提交注入 payload，验证命令执行结果）
- [x] 5.8 编写 `attacks/brute_force.py`（暴力破解登录接口）

## 6. 对比测试

- [x] 6.1 编写 `tests/test_all.py`，覆盖 10 类攻击的漏洞版测试用例
- [x] 6.2 添加防护版测试用例，验证全部攻击被拦截
- [x] 6.3 实现格式化对比表格输出（攻击类型 / 漏洞版结果 / 防护版结果）
- [x] 6.4 实现末尾防护率统计输出
- [x] 6.5 运行完整测试，确认漏洞版 10/10 成功，防护版 0/10 成功

## 7. 收尾

- [ ] 7.1 更新 recommend.md，同步最终漏洞列表和架构变更
- [ ] 7.2 编写 README，说明启动方式、测试步骤和演示流程
- [ ] 7.3 录制演示视频（含姓名学号、代码展示、10 类攻击演示、防护对比）
- [ ] 7.4 撰写课程设计报告
