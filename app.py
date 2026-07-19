import os
import json
import secrets
import time
from collections import defaultdict
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

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


@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user = USERS[username]
        user_info = {
            "username": user["username"],
            "role": user["role"],
            "email": user["email"],
            "phone": user["phone"],
            "balance": user["balance"]
        }
    return render_template("index.html", username=username, user=user_info)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ip = request.remote_addr or "unknown"

        _cleanup()

        # 爆破防护检测
        blocked, msg = _check_blocked(ip, username)
        if blocked:
            error = msg
        elif username in USERS and check_password_hash(USERS[username]["password_hash"], password):
            _record_success(username)
            session["username"] = username
            return redirect(url_for("index"))
        else:
            _record_failure(ip, username)
            error = "用户名或密码错误"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
