# 用户信息管理平台

一个基于 Flask 的简易用户信息管理平台，支持用户登录、信息展示、登出等功能，内置多层爆破防护机制。

> ⚠️ **安全练习项目** — 本系统设计上包含从脆弱到加固的完整过程，用于学习 Web 安全防护。

---

## 功能特性

- 🔐 **用户登录/登出** — 基于 Session 的认证
- 👤 **用户信息展示** — 登录后查看个人资料
- 🛡️ **三层爆破防护**
  - **渐进式延迟** — 每次登录失败等待时间递增（0.3s × 失败次数）
  - **账户锁定** — 连续 5 次失败后锁定账户 5 分钟
  - **IP 封禁** — 同一 IP 累计 20 次失败后封禁 10 分钟
- 🔑 **密码安全** — 密码使用 scrypt 算法哈希存储
- 📋 **外部配置** — 用户数据独立存放于 `users.json`，不硬编码在源码中

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
├── app.py            # Flask 主应用（路由 + 爆破防护逻辑）
├── users.json        # 用户数据（密码已哈希）
├── templates/
│   ├── base.html     # 基础模板（导航栏）
│   ├── login.html    # 登录页
│   └── index.html    # 首页（用户信息展示）
├── static/
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
| `/logout` | GET | 登出并清除 Session |

---

## 安全机制

### 已修复的漏洞

| 漏洞类型 | 原问题 | 修复方式 |
|---------|--------|---------|
| 硬编码凭据 | 用户名密码写在 app.py 中 | 迁移至外部 `users.json` 文件 |
| 明文密码 | 密码明文存储，`==` 直接比对 | scrypt 哈希 + `check_password_hash` |
| 响应越权 | 密码字段传到模板并显示在页面 | 白名单过滤，密码永不进入模板 |
| Secret Key 硬编码 | 固定 `"dev-key-2025"` | 环境变量或随机生成 |
| 调试模式泄露 | `debug=True` 暴露 Werkzeug 控制台 | 已关闭 |
| HTML 注释泄露 | 注释写入 admin/admin123 | 已删除 |

### 爆破防护配置

防护参数可在 `app.py` 顶部调整：

```python
MAX_ACCOUNT_FAILS = 5       # 连续失败 N 次锁定账户
ACCOUNT_LOCK_MINUTES = 5    # 账户锁定时间（分钟）
MAX_IP_FAILS = 20           # 同一 IP 累计失败上限
IP_BLOCK_MINUTES = 10       # IP 封禁时间（分钟）
DELAY_BASE = 0.3            # 基础延迟（秒，每次失败递增）
```

---

## 许可证

MIT License
