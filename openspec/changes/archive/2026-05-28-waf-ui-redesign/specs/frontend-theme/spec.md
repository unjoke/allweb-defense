## ADDED Requirements

### Requirement: 黑白直角主题基础样式
`shared/templates/base.html` SHALL 定义全局 CSS 变量和基础样式，实现黑底白字、直角边框、monospace 字体的主题，不依赖任何外部 CSS 框架或 CDN。

#### Scenario: 页面基础外观
- **WHEN** 用户访问任意页面
- **THEN** 页面背景为 #0a0a0a，主文字颜色为 #e8e8e8，字体为 monospace，所有边框 border-radius 为 0

#### Scenario: 无外部依赖
- **WHEN** 在无网络环境下访问页面
- **THEN** 页面样式完整显示，无 CDN 加载失败导致的样式缺失

### Requirement: 导航栏样式
导航栏 SHALL 使用顶部红色细线（`border-top: 2px solid #ff3333`）作为视觉标识，背景为深黑色，链接为白色。

#### Scenario: 导航栏外观
- **WHEN** 用户访问任意页面
- **THEN** 顶部导航栏显示红色顶边线，背景 #111，链接颜色 #e8e8e8，hover 时变为 #ffffff

#### Scenario: 漏洞版标识
- **WHEN** mode 为 'vulnerable'
- **THEN** 导航栏品牌名旁显示红色 [VULN] 标签

#### Scenario: 防护版标识
- **WHEN** mode 不为 'vulnerable'（或为 'protected'）
- **THEN** 导航栏品牌名旁显示绿色 [PROTECTED] 标签

### Requirement: 表单控件样式
所有表单输入框、按钮 SHALL 使用直角、黑底、白色边框线条风格。

#### Scenario: 输入框外观
- **WHEN** 用户查看任意包含表单的页面
- **THEN** input/textarea 背景为 #111，边框为 1px solid #444，文字为 #e8e8e8，focus 时边框变为 #ffffff，border-radius 为 0

#### Scenario: 主操作按钮
- **WHEN** 用户查看主操作按钮（登录、发布、提交等）
- **THEN** 按钮为白底黑字，border 1px solid #fff，hover 时反转为黑底白字

#### Scenario: 危险操作按钮
- **WHEN** 用户查看删除等危险操作按钮
- **THEN** 按钮边框和文字为 #ff3333，hover 时背景变为 #ff3333，文字变为 #000

### Requirement: Flash 消息样式
Flash 消息 SHALL 使用线条边框风格替代 Bootstrap alert 的圆角填充风格。

#### Scenario: 成功消息
- **WHEN** 页面显示 success 类型 flash 消息
- **THEN** 消息框左边框为 3px solid #00ff41，背景为 #0a0a0a，文字为 #00ff41

#### Scenario: 危险/错误消息
- **WHEN** 页面显示 danger 类型 flash 消息
- **THEN** 消息框左边框为 3px solid #ff3333，背景为 #0a0a0a，文字为 #ff3333

#### Scenario: 消息可关闭
- **WHEN** 用户点击消息框的关闭按钮
- **THEN** 消息框从页面移除（原生 JS 实现，不依赖 Bootstrap JS）

### Requirement: 数据表格样式
管理页面的数据表格 SHALL 使用线条分隔风格，无圆角，无背景色交替。

#### Scenario: 表格外观
- **WHEN** 用户访问用户管理或留言管理页面
- **THEN** 表格使用 1px solid #333 边框，表头背景 #111，行 hover 背景 #1a1a1a，无圆角

### Requirement: 角色/状态标签样式
角色标签（admin/user）和状态标签 SHALL 使用方括号文本风格替代 Bootstrap badge 圆角胶囊。

#### Scenario: Admin 标签
- **WHEN** 用户角色为 admin
- **THEN** 显示为 [ADMIN] 文本，颜色 #ff3333

#### Scenario: User 标签
- **WHEN** 用户角色为 user
- **THEN** 显示为 [USER] 文本，颜色 #888
