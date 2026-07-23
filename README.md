# 用户信息管理平台

一个基于 Flask 的简易用户信息管理平台，支持用户注册、登录、信息展示、个人中心、账户充值、头像上传、用户搜索、登出等功能，内置多层爆破防护机制和 SQL 注入防护。

> ⚠️ **安全练习项目** — 本系统设计上包含从脆弱到加固的完整过程，用于学习 Web 安全防护。

---

## 功能特性

- 📝 **用户注册** — 新用户自助注册，密码自动哈希存储
- 🔐 **用户登录/登出** — 基于 Session 的认证，支持爆破防护
- 👤 **个人中心** — 查看个人资料（邮箱、手机、余额、角色）
- 💰 **账户充值** — 安全受限的充值功能（正数金额、仅限自己、有上限）
- 🖼️ **头像上传** — 支持图片上传与在线预览
- 🔍 **用户搜索** — 支持按用户名或邮箱搜索用户
- 📄 **动态页面** — 动态加载帮助中心等静态页面（白名单防护）
- 📋 **审计日志** — 记录登录、注册、搜索、上传、充值等全部操作
- 🛡️ **三层爆破防护**
  - **渐进式延迟** — 每次登录失败等待时间递增（0.3s × 失败次数）
  - **账户锁定** — 连续 5 次失败后锁定账户 5 分钟
  - **IP 封禁** — 同一 IP 累计 20 次失败后封禁 10 分钟
- 🔑 **密码安全** — 密码使用 scrypt 算法哈希存储，永不回显
- 🛡️ **SQL 注入防护** — 所有 SQL 查询使用参数化查询
- 🛡️ **上传安全** — 扩展名白名单 + MIME 校验 + 魔数校验 + UUID 重命名 + 路径穿越防护
- 🛡️ **越权防护** — 个人中心和充值功能验证身份与权限
- 📋 **外部配置** — 用户数据独立存放于 `users.json` 和 `users.db`，不硬编码在源码中

---

## 快速开始

### 环境要求

- Python 3.8+
- Flask 3.x

### 安装与运行

```bash
# 克隆仓库
git clone https://github.com/94cjyg/Class01.git
cd Class01

# 安装依赖
pip install flask werkzeug

# 启动服务
python3 app.py
```

访问 http://localhost:5000

### 内置账户

| 用户名 | 密码 | 角色 | 邮箱 | 余额 |
|:------:|:----:|:----:|:----:|:----:|
| admin | admin123 | admin | admin@example.com | 99999 |
| alice | alice2025 | user | alice@example.com | 100 |

---

## 项目结构

```
/opt/Class01/
├── app.py            # Flask 主应用（路由 + 爆破防护 + 注入防护 + 审计日志 + 权限校验）
├── users.json        # 预置用户数据（密码已哈希）
├── audit.log         # 审计日志文件（自动生成，不提交 Git）
├── data/
│   └── users.db      # SQLite 数据库（注册用户存储，自动生成，不提交 Git）
├── pages/
│   └── help.html      # 帮助中心页面（白名单可控）
├── templates/
│   ├── base.html     # 基础模板（导航栏）
│   ├── login.html    # 登录页
│   ├── register.html # 注册页
│   ├── profile.html  # 个人中心页（用户信息 + 充值表单）
│   ├── upload.html   # 头像上传页
│   └── index.html    # 首页（用户信息展示 + 搜索功能）
├── static/
│   ├── uploads/      # 上传文件存储（自动生成，不提交 Git）
│   └── css/
│       └── style.css # 蓝色渐变主题样式
├── .gitignore
└── README.md
```

---

## API 接口

| 路由 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 首页，已登录显示用户信息，未登录提示登录 |
| `/login` | GET | 登录页面 |
| `/login` | POST | 提交登录表单（参数：username, password） |
| `/register` | GET | 注册页面 |
| `/register` | POST | 提交注册（参数：username, password, email, phone） |
| `/profile` | GET | 个人中心（参数：user_id，需登录，仅限查看自己） |
| `/recharge` | POST | 账户充值（参数：user_id, amount，仅限自己，正数，有上限） |
| `/search` | GET | 搜索用户（参数：keyword），重定向至首页显示结果 |
| `/upload` | GET | 上传头像页面 |
| `/upload` | POST | 上传图片文件（参数：file，仅限图片格式） |
| `/page` | GET | 动态页面加载（参数：name=help，白名单限制） |
| `/logout` | GET | 登出并清除 Session |

---

## 安全机制

### 已修复的漏洞

| # | 漏洞类型 | 原问题 | 修复方式 | 严重程度 |
|:-:|---------|--------|---------|:--------:|
| 1 | 硬编码凭据 | 用户名密码写在 app.py 中 | 迁移至外部 `users.json` + `users.db` | 🔴 |
| 2 | 明文密码（JSON） | 密码明文存储，`==` 直接比对 | scrypt 哈希 + `check_password_hash` | 🔴 |
| 3 | 明文密码（SQLite） | 注册/初始化密码明文写入数据库 | `generate_password_hash` 哈希后存储 | 🔴 |
| 4 | 响应越权 | 密码字段传到模板并显示在页面 | 白名单过滤，密码永不进入模板 | 🟠 |
| 5 | Secret Key 硬编码 | 固定 `"dev-key-2025"` | 环境变量或随机生成 | 🟠 |
| 6 | 调试模式泄露 | `debug=True` 暴露 Werkzeug 控制台 | 已关闭 | 🟡 |
| 7 | HTML 注释泄露 | 注释写入 admin/admin123 | 已删除 | 🟡 |
| 8 | **SQL 注入（搜索）** | f-string 拼接 SQL | **参数化查询** | 🔴 |
| 9 | **SQL 注入（注册）** | f-string 拼接 SQL | **参数化查询** | 🔴 |
| 10 | 无爆破防护 | 登录接口无频率限制 | 三层爆破防护（延迟+锁定+封禁） | 🔴 |
| 11 | 无扩展名校验 | 可上传 `.php` 一句话木马 | 白名单仅允许图片扩展名 | 🔴 |
| 12 | 无文件内容校验 | 改后缀即可绕过 | 8 字节魔数校验 | 🔴 |
| 13 | 原始文件名保留 | 攻击者可控制文件名 | 32 位随机十六进制重命名 | 🔴 |
| 14 | 路径穿越 | `../../../` 可写入任意目录 | normpath + 前缀检查 | 🔴 |
| 15 | 无审计日志 | 无法追踪攻击行为 | 全操作审计日志记录 | 🟡 |
| 16 | **未授权访问 profile** | 无需登录即可查看任意用户 | 添加 session 登录检查 | 🔴 |
| 17 | **水平越权（IDOR）** | 可遍历 user_id 查看他人资料 | 校验仅限查看自己的资料 | 🔴 |
| 18 | **越权充值** | 可修改 user_id 为他人充值 | 校验仅限自己 | 🔴 |
| 19 | **负金额扣款** | 充负数可扣减任意用户余额 | amount <= 0 拒绝 | 🔴 |
| 20 | **充值无上限** | 可充任意大金额 | MAX_RECHARGE 上限校验 | 🟠 |
| 21 | **内存数据不同步** | USERS 修改不写入 SQLite | 双数据源同步更新 | 🟠 |
| 22 | **文件包含（LFI）** | 用户输入直接拼接入文件路径 | 白名单机制（仅允许预定义页面） | 🔴 |

### SQL 注入防护

所有 SQL 查询均使用参数化查询，用户输入与 SQL 语句完全分离：

```python
# ❌ 修复前：f-string 拼接（可注入）
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%'"

# ✅ 修复后：参数化查询
like_pattern = f"%{keyword}%"
sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
c.execute(sql, (like_pattern, like_pattern))
```

### 上传安全防护

头像上传功能实施五层安全校验：

```python
# ① 扩展名白名单
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"}

# ② MIME 类型检查
if file.content_type not in ["image/jpeg", "image/png", ...]: ...

# ③ 文件魔数校验（读文件头验证真实类型）
MAGIC_NUMBERS = {b"\xff\xd8": "jpeg", b"\x89PNG\r\n": "png", ...}
header = file.read(8)
is_valid_image = any(header.startswith(magic) for magic in MAGIC_NUMBERS)

# ④ UUID 重命名（防路径穿越 + 防覆盖）
safe_filename = f"{secrets.token_hex(16)}{ext}"

# ⑤ 路径前缀检查
if not filepath.startswith(os.path.normpath(upload_dir)):
    return render_template("upload.html", error="非法文件名")
```

### 越权与业务逻辑防护

个人中心和充值功能修复的漏洞链：

```
修复前攻击路径：
  未登录 → /profile?user_id=1 → 获取任意用户资料
  登录 → 改 hidden user_id → 给他人充值
  登录 → 改 amount=-99999 → 扣减任意用户余额

修复后防护：
  ✅ 登录检查 → 未登录跳转
  ✅ 身份校验 → 只能查看/操作自己的账户
  ✅ 金额校验 → amount <= 0 拒绝
  ✅ 上限校验 → 单次不超过 MAX_RECHARGE
  ✅ 数据同步 → USERS + SQLite 同时更新
```

### 文件包含（LFI）防护

动态页面加载功能曾存在严重的路径遍历漏洞，修复后实施白名单机制防止任意文件读取：

```python
# ❌ 修复前：用户输入直接拼接入路径，可路径穿越读取任意文件
page_path = os.path.join("pages", name)      # name=../app.py → 读取源码

# ✅ 修复后：白名单机制，只允许预定义页面
ALLOWED_PAGES = {"help"}                      # 只允许 help
if name not in ALLOWED_PAGES:                 # 不在白名单直接拒绝
    page_content = "页面不存在"
page_path = os.path.join("pages", f"{name}.html")  # 路径完全由服务端控制
```

修复前攻击者可通过 `../` 穿越、绝对路径绕过、URL编码绕过等方式读取服务器任意文件（源码、配置、系统文件），修复后白名单一刀切死所有绕过方式。


### 审计日志

所有敏感操作均记录日志，格式如下：

```
2026-07-21 16:49:53,022 |   127.0.0.1 | admin        | 登录成功     | USERS 验证
2026-07-21 16:49:53,714 |   127.0.0.1 | admin        | 上传拒绝     | 扩展名非法: shell.php
2026-07-22 15:57:39,796 |   127.0.0.1 | admin        | 充值         | user_id=1 amount=500
```

| 操作 | 记录内容 |
|:----|:---------|
| 登录成功/失败 | 用户名、IP、验证来源、失败原因 |
| 登录拦截 | 用户名、IP、拦截原因（锁定/封禁） |
| 登出 | 用户名、IP |
| 注册 | 用户名、IP、邮箱、手机 |
| 搜索 | 用户名、IP、关键词 |
| 上传成功/拒绝 | 用户名、IP、文件名、拒绝原因 |
| 充值 | 用户名、IP、目标 user_id、金额 |

### 爆破防护配置

防护参数可在 `app.py` 顶部调整：

```python
MAX_ACCOUNT_FAILS = 5       # 连续失败 N 次锁定账户
ACCOUNT_LOCK_MINUTES = 5    # 账户锁定时间（分钟）
MAX_IP_FAILS = 20           # 同一 IP 累计失败上限
IP_BLOCK_MINUTES = 10       # IP 封禁时间（分钟）
DELAY_BASE = 0.3            # 基础延迟（秒，每次失败递增）
MAX_RECHARGE = 10000000     # 单次充值上限
```

---

## 数据源说明

系统使用**双数据源**架构：

| 数据源 | 存储位置 | 用途 | 密码存储 | 余额存储 |
|--------|----------|------|----------|----------|
| JSON 文件 | `users.json` | 预置用户（admin、alice），含角色和余额 | scrypt 哈希 | 内存 + SQLite |
| SQLite 数据库 | `data/users.db` | 注册新用户存储，搜索查询，余额操作 | scrypt 哈希 | SQLite |

---

## 许可证

MIT License
