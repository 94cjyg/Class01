import os
import json
import sqlite3
import secrets
import time
import logging
import functools
from datetime import datetime
from collections import defaultdict
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


# === CSRF Token 生成 ===
@app.before_request
def ensure_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)


def csrf_required(f):
    """CSRF Token 验证装饰器"""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = request.form.get("csrf_token", "")
        if not token or token != session.get("csrf_token", ""):
            return "CSRF 验证失败，请刷新页面后重试", 403
        return f(*args, **kwargs)
    return decorated

# === 审计日志 ===
audit_logger = logging.getLogger("audit")
audit_handler = logging.FileHandler(os.path.join(os.path.dirname(__file__), "audit.log"), encoding="utf-8")
audit_handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)


def audit(action, username, ip, detail=""):
    """写入审计日志"""
    audit_logger.info(f"{ip:>15s} | {username or '匿名':<12s} | {action:<12s} | {detail}")


@app.errorhandler(413)
def too_large(e):
    return render_template("upload.html", error="文件过大，最大允许 16MB"), 413

# === 爆破防护状态（内存） ===
FAILED_ACCOUNTS = defaultdict(list)   # username -> [timestamp, ...]
FAILED_IPS = defaultdict(list)        # ip -> [timestamp, ...]
LOCKED_ACCOUNTS = {}                  # username -> unlock_time
BLOCKED_IPS = {}                      # ip -> block_until

MAX_ACCOUNT_FAILS = 5                 # 连续失败 N 次锁定账户
ACCOUNT_LOCK_MINUTES = 5              # 账户锁定时间
MAX_IP_FAILS = 20                     # 同一 IP 累计失败上限
IP_BLOCK_MINUTES = 10                 # IP 封禁时间
WINDOW = 900                          # 统计窗口 15 分钟
DELAY_BASE = 0.3                      # 基础延迟秒数（每次失败递增）


def _cleanup():
    """清理过期记录"""
    now = time.time()
    for k in list(FAILED_ACCOUNTS):
        FAILED_ACCOUNTS[k] = [t for t in FAILED_ACCOUNTS[k] if now - t < WINDOW]
        if not FAILED_ACCOUNTS[k]:
            del FAILED_ACCOUNTS[k]
    for k in list(FAILED_IPS):
        FAILED_IPS[k] = [t for t in FAILED_IPS[k] if now - t < WINDOW]
        if not FAILED_IPS[k]:
            del FAILED_IPS[k]
    for k in list(LOCKED_ACCOUNTS):
        if now >= LOCKED_ACCOUNTS[k]:
            del LOCKED_ACCOUNTS[k]
    for k in list(BLOCKED_IPS):
        if now >= BLOCKED_IPS[k]:
            del BLOCKED_IPS[k]


def _check_blocked(ip, username):
    """检查 IP/账户是否被封禁，返回 (是否阻止, 提示消息)"""
    now = time.time()
    if username in LOCKED_ACCOUNTS:
        remaining = int(LOCKED_ACCOUNTS[username] - now)
        if remaining > 0:
            return True, f"账户暂时锁定，请 {remaining} 秒后再试"
        del LOCKED_ACCOUNTS[username]
    if ip in BLOCKED_IPS:
        remaining = int(BLOCKED_IPS[ip] - now)
        if remaining > 0:
            return True, f"IP 已被临时封禁，请 {remaining} 秒后再试"
        del BLOCKED_IPS[ip]
    return False, ""


def _record_failure(ip, username):
    """记录失败并触发锁定逻辑"""
    now = time.time()
    FAILED_ACCOUNTS[username].append(now)
    FAILED_IPS[ip].append(now)
    _cleanup()

    # 检查账户锁
    if len(FAILED_ACCOUNTS[username]) >= MAX_ACCOUNT_FAILS:
        LOCKED_ACCOUNTS[username] = now + ACCOUNT_LOCK_MINUTES * 60
        # 锁定后清空失败计数
        FAILED_ACCOUNTS[username] = []

    # 检查 IP 封禁
    if len(FAILED_IPS[ip]) >= MAX_IP_FAILS:
        BLOCKED_IPS[ip] = now + IP_BLOCK_MINUTES * 60

    # 渐进式延迟：失败次数越多等越久
    fail_count = min(len(FAILED_ACCOUNTS[username]) + len(FAILED_IPS[ip]), 30)
    delay = DELAY_BASE * fail_count
    time.sleep(delay)


def _record_success(username):
    """登录成功后清除该账户的失败记录"""
    FAILED_ACCOUNTS.pop(username, None)


def load_users():
    users_path = os.environ.get("USERS_PATH", os.path.join(os.path.dirname(__file__), "users.json"))
    try:
        with open(users_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"FATAL: Could not load users from {users_path}: {e}")
        return {}


USERS = load_users()


def get_user_id(username):
    """根据用户名查询 user_id"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row["id"] if row else 1


@app.context_processor
def inject_user_id():
    """向所有模板注入当前登录用户的 user_id"""
    uid = None
    if "username" in session:
        uid = get_user_id(session["username"])
    return dict(current_user_id=uid)


def get_user_info(username):
    """从 USERS 或 SQLite 获取用户信息，优先 USERS"""
    if username in USERS:
        user = USERS[username]
        return {
            "username": user["username"],
            "role": user["role"],
            "email": user["email"],
            "phone": user["phone"],
            "balance": user["balance"]
        }
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        if row:
            return {
                "username": row["username"],
                "role": "user",
                "email": row["email"] or "",
                "phone": row["phone"] or "",
                "balance": row["balance"] if row["balance"] is not None else 0
            }
    except Exception:
        pass
    return None


def get_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            balance INTEGER DEFAULT 0
        )
    """)
    # 兼容旧表：如果没有 balance 列则添加
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # 列已存在
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("admin", generate_password_hash("admin123"), "admin@example.com", "13800138000", 99999))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ("alice", generate_password_hash("alice2025"), "alice@example.com", "13900139001", 100))
    conn.commit()
    conn.close()


init_db()


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    search_results = None
    keyword = request.args.get("keyword", "")

    if username:
        user_info = get_user_info(username)

    if keyword:
        username = session.get("username", "匿名")
        ip = request.remote_addr or "unknown"
        audit("搜索", username, ip, f"keyword={keyword}")
        conn = get_db()
        c = conn.cursor()
        like_pattern = f"%{keyword}%"
        sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
        print(f"[SQL] {sql}  params: ['%{keyword}%']")
        c.execute(sql, (like_pattern, like_pattern))
        rows = c.fetchall()
        search_results = [dict(row) for row in rows]
        conn.close()

    return render_template("index.html", username=username, user=user_info,
                           search_results=search_results, keyword=keyword)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    registered = request.args.get("registered")
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ip = request.remote_addr or "unknown"

        _cleanup()

        # 爆破防护检测
        blocked, msg = _check_blocked(ip, username)
        if blocked:
            audit("登录拦截", username, ip, msg)
            error = msg
        elif username in USERS and check_password_hash(USERS[username]["password_hash"], password):
            _record_success(username)
            session["username"] = username
            audit("登录成功", username, ip, "USERS 验证")
            return redirect(url_for("index"))
        else:
            # 回退到 SQLite 校验（新注册用户）
            try:
                conn = get_db()
                c = conn.cursor()
                c.execute("SELECT password FROM users WHERE username = ?", (username,))
                row = c.fetchone()
                conn.close()
                if row and check_password_hash(row["password"], password):
                    _record_success(username)
                    session["username"] = username
                    audit("登录成功", username, ip, "SQLite 验证")
                    return redirect(url_for("index"))
            except Exception:
                pass
            _record_failure(ip, username)
            audit("登录失败", username, ip, "密码错误")
            error = "用户名或密码错误"

    return render_template("login.html", error=error, registered=registered)


@app.route("/logout")
def logout():
    username = session.get("username", "未知")
    ip = request.remote_addr or "unknown"
    session.clear()
    audit("登出", username, ip, "")
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")
        ip = request.remote_addr or "unknown"

        conn = get_db()
        c = conn.cursor()
        password_hash = generate_password_hash(password)
        sql = "INSERT INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, 0)"
        print(f"[SQL] {sql}  params: ['{username}', '{password_hash}', '{email}', '{phone}']")
        c.execute(sql, (username, password_hash, email, phone))
        conn.commit()
        conn.close()
        audit("注册", username, ip, f"email={email} phone={phone}")
        return redirect(url_for("login", registered=1))

    return render_template("register.html")


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    username = session.get("username", "匿名")
    ip = request.remote_addr or "unknown"
    audit("搜索", username, ip, f"keyword={keyword}")
    return redirect(url_for("index", keyword=keyword))


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect(url_for("login"))

    username = session.get("username", "未知")
    ip = request.remote_addr or "unknown"

    if request.method == "POST":
        # CSRF 校验
        token = request.form.get("csrf_token", "")
        if not token or token != session.get("csrf_token", ""):
            return render_template("upload.html", error="CSRF 验证失败"), 403

        if "file" not in request.files:
            return render_template("upload.html", error="未选择文件")

        file = request.files["file"]
        if file.filename == "":
            return render_template("upload.html", error="未选择文件")

        original_filename = file.filename

        # 检查文件扩展名
        ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"}
        ext = os.path.splitext(original_filename)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            audit("上传拒绝", username, ip, f"扩展名非法: {original_filename}")
            return render_template("upload.html", error="不支持的文件类型，仅允许图片文件（jpg/jpeg/png/gif/bmp/webp）")

        # 检查 MIME 类型
        if file.content_type not in ["image/jpeg", "image/png", "image/gif", "image/bmp", "image/webp"]:
            audit("上传拒绝", username, ip, f"MIME非法: {file.content_type} ({original_filename})")
            return render_template("upload.html", error="文件内容类型不合法，仅允许图片文件")

        # 读取文件头进一步验证
        file.seek(0)
        header = file.read(8)
        file.seek(0)
        MAGIC_NUMBERS = {
            b"\xff\xd8": "image/jpeg",
            b"\x89PNG\r\n": "image/png",
            b"GIF87a": "image/gif",
            b"GIF89a": "image/gif",
            b"BM": "image/bmp",
            b"RIFF": "image/webp",
        }
        is_valid_image = any(header.startswith(magic) for magic in MAGIC_NUMBERS)
        if not is_valid_image:
            audit("上传拒绝", username, ip, f"魔数校验失败: {original_filename}")
            return render_template("upload.html", error="文件内容不是有效的图片格式")

        # 使用 UUID 重命名，防止路径穿越和覆盖
        safe_filename = f"{secrets.token_hex(16)}{ext}"
        upload_dir = os.path.join(app.root_path, "static/uploads")
        os.makedirs(upload_dir, exist_ok=True)
        filepath = os.path.normpath(os.path.join(upload_dir, safe_filename))

        # 确保文件写入 uploads 目录内（防止路径穿越）
        if not filepath.startswith(os.path.normpath(upload_dir)):
            audit("上传拒绝", username, ip, f"路径穿越尝试: {original_filename}")
            return render_template("upload.html", error="非法文件名")

        file.save(filepath)
        file_url = url_for("static", filename=f"uploads/{safe_filename}")
        audit("上传成功", username, ip, f"{original_filename} → {safe_filename} ({os.path.getsize(filepath)} bytes)")
        return render_template("upload.html", success=True, file_url=file_url, filename=safe_filename)

    return render_template("upload.html")


def get_user_by_id(user_id):
    """根据 user_id 从数据源查询用户完整信息"""
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    username = row["username"]
    # USERS 字典中的用户优先取 balance
    if username in USERS:
        user = USERS[username]
        return {
            "id": row["id"],
            "username": username,
            "email": row["email"] or user.get("email", ""),
            "phone": row["phone"] or user.get("phone", ""),
            "balance": user.get("balance", 0),
            "role": user.get("role", "user")
        }
    return {
        "id": row["id"],
        "username": username,
        "email": row["email"] or "",
        "phone": row["phone"] or "",
        "balance": row["balance"] if row["balance"] is not None else 0,
        "role": "user"
    }


@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect(url_for("login"))

    user_id = request.args.get("user_id")
    if not user_id:
        return redirect(url_for("index"))
    try:
        user_id = int(user_id)
    except ValueError:
        return redirect(url_for("index"))

    username = session["username"]

    # 验证是否查看自己的资料
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row or row["username"] != username:
        return render_template("profile.html", error="无权查看其他用户的资料", user=None)

    user_info = get_user_by_id(user_id)
    if not user_info:
        return render_template("profile.html", error="用户不存在", user=None)

    return render_template("profile.html", user=user_info)


MAX_RECHARGE = 10000000  # 单次充值上限


@app.route("/recharge", methods=["POST"])
@csrf_required
def recharge():
    if "username" not in session:
        return redirect(url_for("login"))

    user_id = request.form.get("user_id")
    amount = request.form.get("amount")
    login_user = session["username"]
    ip = request.remote_addr or "unknown"

    try:
        user_id = int(user_id)
        amount = int(amount)
    except (ValueError, TypeError):
        return redirect(url_for("index"))

    # 负数或零校验
    if amount <= 0:
        return redirect(url_for("profile", user_id=user_id))

    # 金额上限校验
    if amount > MAX_RECHARGE:
        return redirect(url_for("profile", user_id=user_id))

    # 从 SQLite 查询目标用户
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return redirect(url_for("index"))

    target_username = row["username"]

    # 只能给自己充值
    if login_user != target_username:
        conn.close()
        return redirect(url_for("profile", user_id=user_id))

    # USERS 字典和 SQLite 同步更新
    if target_username in USERS:
        USERS[target_username]["balance"] = USERS[target_username].get("balance", 0) + amount
        # 同步到 SQLite
        c.execute("UPDATE users SET balance = COALESCE(balance, 0) + ? WHERE id = ?", (amount, user_id))
    else:
        c.execute("UPDATE users SET balance = COALESCE(balance, 0) + ? WHERE id = ?", (amount, user_id))

    conn.commit()
    conn.close()

    audit("充值", login_user, ip, f"user_id={user_id} amount={amount}")
    return redirect(url_for("profile", user_id=user_id))


@app.route("/page")
def page():
    name = request.args.get("name", "")
    if not name:
        return redirect(url_for("index"))

    # 白名单机制 — 只允许预定义的页面名称
    ALLOWED_PAGES = {"help"}

    if name not in ALLOWED_PAGES:
        page_content = "<p style='color:#999;text-align:center;padding:40px;'>页面不存在</p>"
    else:
        page_path = os.path.join("pages", f"{name}.html")
        try:
            with open(page_path, "r", encoding="utf-8") as f:
                page_content = f.read()
        except Exception:
            page_content = "<p style='color:#999;text-align:center;padding:40px;'>页面不存在</p>"

    username = session.get("username")
    return render_template("index.html", username=username, page_content=page_content)


@app.route("/change-password", methods=["POST"])
@csrf_required
def change_password():
    if "username" not in session:
        return redirect(url_for("login"))

    login_user = session["username"]
    username = request.form.get("username", "")
    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    ip = request.remote_addr or "unknown"

    if not username or not new_password:
        return redirect(url_for("profile", user_id=1))

    # 两次新密码必须一致
    if new_password != confirm_password:
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        return render_template("profile.html", user=get_user_by_id(row["id"] if row else None), error="两次输入的新密码不一致")

    # 只能修改自己的密码
    if login_user != username:
        audit("修改密码被拒", login_user, ip, f"企图修改{username}的密码")
        return redirect(url_for("index"))

    # 验证原密码
    password_valid = False
    if username in USERS:
        password_valid = check_password_hash(USERS[username]["password_hash"], old_password)
    else:
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE username = ?", (username,))
            row = c.fetchone()
            conn.close()
            if row:
                password_valid = check_password_hash(row["password"], old_password)
        except Exception:
            pass

    if not password_valid:
        audit("修改密码失败", login_user, ip, "原密码错误")
        # 需要传递错误信息到 profile 页面
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = c.fetchone()
        conn.close()
        return render_template("profile.html", user=get_user_by_id(row["id"] if row else None), error="原密码错误")

    password_hash = generate_password_hash(new_password)

    # 更新 USERS 字典（内存）
    if username in USERS:
        USERS[username]["password_hash"] = password_hash

    # 更新 SQLite 数据库
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = c.fetchone()

    if row:
        c.execute("UPDATE users SET password = ? WHERE username = ?", (password_hash, username))
        target_id = row["id"]
    else:
        c.execute("INSERT INTO users (username, password, email, phone, balance) VALUES (?, ?, '', '', 0)",
                  (username, password_hash))
        target_id = c.lastrowid

    conn.commit()
    conn.close()

    audit("修改密码成功", login_user, ip, "")
    return redirect(url_for("profile", user_id=target_id))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
