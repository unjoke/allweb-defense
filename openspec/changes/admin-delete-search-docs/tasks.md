# Tasks: admin-delete-search-docs

## 1. 删除权限重构（垂直越权）

- [x] 1.1 `app/vulnerable/app.py` messages 路由：传 `current_role=session.get("role","")` 给模板
- [x] 1.2 `app/vulnerable/app.py` delete_message 路由：更新注释为垂直越权说明
- [x] 1.3 `shared/templates/messages.html`：DELETE 按钮用 `{% if current_role == 'admin' %}` 包裹

## 2. /search 搜索框

- [x] 2.1 `shared/templates/search.html`：顶部加搜索表单，预填 q 值

## 3. README 手动攻击方法

- [x] 3.1 README.md 新增"手动攻击方法"章节，覆盖全部 10 类漏洞
