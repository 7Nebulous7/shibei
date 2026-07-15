
"""
拾贝平台 - Flask 应用
双模块：文字 | 图片
含登录系统、用户管理、文字分析、图片浏览
"""

import sys
import os
import io
import json
import re
import hashlib
import sqlite3
import requests
from pathlib import Path
from datetime import datetime
from functools import wraps
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from flask import Flask, render_template, request, jsonify, Response, send_file, session, redirect, url_for
from werkzeug.utils import secure_filename

# 文字模块允许的扩展名
ALLOWED_TEXT_EXT = {"txt", "md", "csv", "json", "xml", "html", "log", "py", "js", "css", "yaml", "yml"}
# 文字模块 DOCX 支持（可选）
try:
    from docx import Document
    HAS_DOCX = True
except ImportError:
    HAS_DOCX = False

# ============================================================
#  初始化
# ============================================================
app = Flask(__name__)

BASE_DIR = Path(__file__).parent

# 生成/读取持久化密钥（本地开发用，生产环境用环境变量 SECRET_KEY）
_SECRET_FILE = BASE_DIR / ".secret_key"
_env_key = os.environ.get("SECRET_KEY")
if _env_key:
    app.secret_key = _env_key
elif _SECRET_FILE.exists():
    app.secret_key = _SECRET_FILE.read_text(encoding="utf-8").strip()
else:
    _key = os.urandom(24).hex()
    _SECRET_FILE.write_text(_key, encoding="utf-8")
    app.secret_key = _key
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
TEXT_DIR = DATA_DIR / "texts"
TEXT_DIR.mkdir(exist_ok=True)
IMAGE_DIR = DATA_DIR / "images"
IMAGE_DIR.mkdir(exist_ok=True)
IMG_CACHE_DIR = DATA_DIR / "img_cache"
IMG_CACHE_DIR.mkdir(exist_ok=True)
DB_PATH = DATA_DIR / "app.db"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}


# ============================================================
#  数据库
# ============================================================
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """建表 + 默认管理员账号"""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            login_at TEXT DEFAULT (datetime('now','localtime')),
            success INTEGER DEFAULT 1
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS password_changes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT,
            old_password TEXT,
            new_password TEXT,
            changed_at TEXT DEFAULT (datetime('now','localtime'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            module TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT,
            content_uid TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        )
    """)
    # 为已有表增加 content_uid 列（兼容旧表）
    try:
        conn.execute("ALTER TABLE activity_logs ADD COLUMN content_uid TEXT")
    except sqlite3.OperationalError:
        pass  # 列已存在
    conn.execute("""
        CREATE TABLE IF NOT EXISTS registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            plain_password TEXT,
            status TEXT DEFAULT 'pending',
            ip_address TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            reviewed_at TEXT,
            reviewed_by TEXT
        )
    """)
    try:
        conn.execute("ALTER TABLE registrations ADD COLUMN plain_password TEXT")
    except sqlite3.OperationalError:
        pass
    # 默认管理员: admin / admin123
    existing = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
    if not existing:
        pw = hashlib.sha256("admin123".encode()).hexdigest()
        conn.execute("INSERT INTO users (username, password_hash, role) VALUES ('admin', ?, 'admin')", (pw,))
        print("[✓] 已创建默认管理员: admin / admin123")
    conn.commit()
    conn.close()


def verify_user(username: str, password: str) -> dict | None:
    """验证用户，成功返回用户信息"""
    conn = get_db()
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    user = conn.execute(
        "SELECT * FROM users WHERE username=? AND password_hash=?",
        (username, pw_hash)
    ).fetchone()
    conn.close()
    return dict(user) if user else None


def get_all_users() -> list[dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM users ORDER BY created_at").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def add_user(username: str, password: str, role: str = "user") -> bool:
    conn = get_db()
    try:
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                     (username, pw_hash, role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def delete_user(user_id: int) -> bool:
    conn = get_db()
    user = conn.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        conn.close()
        return False
    username = user["username"]
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.execute("DELETE FROM registrations WHERE username=?", (username,))
    conn.execute("DELETE FROM password_changes WHERE username=?", (username,))
    conn.execute("DELETE FROM login_logs WHERE username=?", (username,))
    conn.execute("DELETE FROM activity_logs WHERE username=?", (username,))
    conn.commit()
    conn.close()
    return True


def log_login(username: str, ip: str, ua: str, success: bool = True):
    conn = get_db()
    conn.execute(
        "INSERT INTO login_logs (username, ip_address, user_agent, success) VALUES (?,?,?,?)",
        (username, ip, ua, 1 if success else 0)
    )
    conn.commit()
    conn.close()


def get_login_logs(limit: int = 100) -> list[dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM login_logs ORDER BY login_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def change_password(username: str, old_password: str, new_password: str, ip: str) -> tuple[bool, str]:
    """改密，返回 (成功, 消息)"""
    user = verify_user(username, old_password)
    if not user:
        return False, "旧密码不正确"
    if len(new_password) < 4:
        return False, "新密码至少4位"
    new_hash = hashlib.sha256(new_password.encode()).hexdigest()
    conn = get_db()
    conn.execute("UPDATE users SET password_hash=? WHERE username=?", (new_hash, username))
    conn.execute(
        "INSERT INTO password_changes (username, ip_address, old_password, new_password) VALUES (?,?,?,?)",
        (username, ip, old_password, new_password)
    )
    conn.commit()
    conn.close()
    return True, "密码修改成功"


def get_password_changes(limit: int = 100) -> list[dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM password_changes ORDER BY changed_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def log_activity(username: str, module: str, action: str, detail: str = "", content_uid: str = ""):
    """记录用户操作到活动日志，content_uid 用于关联被操作的内容"""
    conn = get_db()
    conn.execute(
        "INSERT INTO activity_logs (username, module, action, detail, content_uid) VALUES (?,?,?,?,?)",
        (username, module, action, detail, content_uid)
    )
    conn.commit()
    conn.close()


def get_activity_logs(limit: int = 300) -> list[dict]:
    conn = get_db()
    rows = conn.execute("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_texts() -> list[dict]:
    """获取所有用户的文本（管理员视角）"""
    items = []
    for meta_path in sorted(TEXT_DIR.glob("*.meta.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        items.append(meta)
    return items


def get_all_images() -> list[dict]:
    """获取所有用户的图片（管理员视角）"""
    items = []
    all_tags_data = _load_tags()
    # 合并所有用户的标签为管理员视图
    all_tags = {}
    for user_tags in all_tags_data.values():
        all_tags.update(user_tags)
    for mp in sorted(IMAGE_DIR.glob("*.meta.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        meta = json.loads(mp.read_text(encoding="utf-8"))
        meta["view_url"] = f"/api/image/view/{meta['uid']}"
        meta["tags"] = all_tags.get(meta["uid"], [])
        items.append(meta)
    return items


def get_user_by_name(username: str) -> dict | None:
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def check_registration(username: str) -> dict | None:
    """检查用户注册申请状态（pending/approved/rejected），不在 registrations 表返回 None"""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM registrations WHERE username=? ORDER BY id DESC LIMIT 1",
        (username,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_pending_registrations() -> list[dict]:
    """获取所有待审批的注册申请"""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM registrations WHERE status='pending' ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def approve_registration(reg_id: int, reviewed_by: str) -> tuple[bool, str]:
    """批准注册申请，将用户写入 users 表"""
    conn = get_db()
    reg = conn.execute("SELECT * FROM registrations WHERE id=?", (reg_id,)).fetchone()
    if not reg:
        conn.close()
        return False, "申请不存在"
    if reg["status"] != "pending":
        conn.close()
        return False, "该申请已被处理"
    try:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
            (reg["username"], reg["password_hash"])
        )
        # 记录初始密码到密码修改记录（注册视为首次设置密码）
        plain_pw = reg["plain_password"] or "(未记录)"
        conn.execute(
            "INSERT INTO password_changes (username, ip_address, old_password, new_password) VALUES (?,?,?,?)",
            (reg["username"], reg["ip_address"] or "注册", "(无)", plain_pw)
        )
        conn.execute(
            "UPDATE registrations SET status='approved', reviewed_at=datetime('now','localtime'), reviewed_by=? WHERE id=?",
            (reviewed_by, reg_id)
        )
        conn.commit()
        return True, f"已批准 {reg['username']}"
    except sqlite3.IntegrityError:
        conn.close()
        return False, "用户名已存在"
    finally:
        if conn:
            conn.close()


def reject_registration(reg_id: int, reviewed_by: str) -> tuple[bool, str]:
    """拒绝注册申请"""
    conn = get_db()
    reg = conn.execute("SELECT * FROM registrations WHERE id=?", (reg_id,)).fetchone()
    if not reg:
        conn.close()
        return False, "申请不存在"
    conn.execute(
        "UPDATE registrations SET status='rejected', reviewed_at=datetime('now','localtime'), reviewed_by=? WHERE id=?",
        (reviewed_by, reg_id)
    )
    conn.commit()
    conn.close()
    return True, f"已拒绝 {reg['username']}"


# ============================================================
#  登录装饰器
# ============================================================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login_page"))
        if session.get("role") != "admin":
            return "需要管理员权限", 403
        return f(*args, **kwargs)
    return decorated


# ============================================================
#  注册
# ============================================================
@app.route("/register", methods=["GET", "POST"])
def register_page():
    error = None
    success = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            error = "用户名和密码不能为空"
        elif len(password) < 4:
            error = "密码至少4位"
        else:
            # 检查是否已存在
            existing_user = get_user_by_name(username)
            if existing_user:
                error = "该用户名已被注册"
            else:
                reg = check_registration(username)
                if reg and reg["status"] == "pending":
                    error = "你已提交过注册申请，请等待管理员审批"
                elif reg and reg["status"] == "approved":
                    # approved 但 users 表里可能已被管理员手动删除——清理后允许重新注册
                    conn2 = get_db()
                    conn2.execute("DELETE FROM registrations WHERE username=?", (username,))
                    conn2.commit()
                    conn2.close()
                    # 重新提交申请
                    pw_hash = hashlib.sha256(password.encode()).hexdigest()
                    ip = request.remote_addr or request.headers.get("X-Forwarded-For", "unknown")
                    conn = get_db()
                    conn.execute(
                        "INSERT INTO registrations (username, password_hash, plain_password, ip_address) VALUES (?,?,?,?)",
                        (username, pw_hash, password, ip)
                    )
                    conn.commit()
                    conn.close()
                    success = "注册申请已提交，请等待管理员审批后登录"
                elif reg and reg["status"] == "rejected":
                    error = "你之前的注册申请已被拒绝，请联系管理员"
                else:
                    pw_hash = hashlib.sha256(password.encode()).hexdigest()
                    ip = request.remote_addr or request.headers.get("X-Forwarded-For", "unknown")
                    conn = get_db()
                    conn.execute(
                        "INSERT INTO registrations (username, password_hash, plain_password, ip_address) VALUES (?,?,?,?)",
                        (username, pw_hash, password, ip)
                    )
                    conn.commit()
                    conn.close()
                    success = "注册申请已提交，请等待管理员审批后登录"

    return render_template("register.html", error=error, success=success)


# ============================================================
#  认证路由
# ============================================================
@app.route("/login", methods=["GET", "POST"])
def login_page():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr or request.headers.get("X-Forwarded-For", "unknown")
        ua = request.headers.get("User-Agent", "")

        user = verify_user(username, password)
        if user:
            session["user"] = user["username"]
            session["role"] = user["role"]
            session["user_id"] = user["id"]
            log_login(username, ip, ua, success=True)
            return redirect(url_for("index"))
        else:
            # 不在 users 表，检查注册申请状态
            reg = check_registration(username)
            if reg and reg["status"] == "pending":
                error = "你的账号正在审批中，请等待管理员通过"
            elif reg and reg["status"] == "rejected":
                error = "你的注册申请已被拒绝，请联系管理员"
            else:
                log_login(username, ip, ua, success=False)
                error = "账号或密码错误"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile_page():
    msg = None
    error = None
    if request.method == "POST":
        old_pw = request.form.get("old_password", "")
        new_pw = request.form.get("new_password", "")
        ip = request.remote_addr or request.headers.get("X-Forwarded-For", "unknown")
        ok, message = change_password(session["user"], old_pw, new_pw, ip)
        if ok:
            msg = message
        else:
            error = message

    user_info = get_user_by_name(session["user"])
    return render_template("profile.html", user=user_info, msg=msg, error=error)


# ============================================================
#  管理后台
# ============================================================
@app.route("/admin")
@admin_required
def admin_page():
    users = get_all_users()
    logs = get_login_logs(200)
    pw_changes = get_password_changes(100)
    activities = get_activity_logs(500)
    all_texts = get_all_texts()
    all_images = get_all_images()

    stats = {
        "user_count": len(users),
        "total_logins": len(logs),
        "success_logins": sum(1 for l in logs if l["success"]),
        "failed_logins": sum(1 for l in logs if not l["success"]),
        "today_logins": sum(
            1 for l in logs
            if l["login_at"][:10] == datetime.now().strftime("%Y-%m-%d")
        ),
        "text_count": len(all_texts),
        "image_count": len(all_images),
    }

    return render_template("admin.html", users=users, logs=logs, stats=stats, pw_changes=pw_changes,
                          activities=activities, all_texts=all_texts, all_images=all_images,
                          registrations=get_pending_registrations())


@app.route("/admin/registration/approve", methods=["POST"])
@admin_required
def admin_approve_registration():
    reg_id = request.form.get("reg_id", type=int)
    if not reg_id:
        return jsonify({"ok": False, "msg": "缺少申请 ID"})
    ok, msg = approve_registration(reg_id, session["user"])
    if ok:
        log_activity(session["user"], "系统", "审批通过", msg)
    return jsonify({"ok": ok, "msg": msg})


@app.route("/admin/registration/reject", methods=["POST"])
@admin_required
def admin_reject_registration():
    reg_id = request.form.get("reg_id", type=int)
    if not reg_id:
        return jsonify({"ok": False, "msg": "缺少申请 ID"})
    ok, msg = reject_registration(reg_id, session["user"])
    if ok:
        log_activity(session["user"], "系统", "审批拒绝", msg)
    return jsonify({"ok": ok, "msg": msg})


@app.route("/admin/user/add", methods=["POST"])
@admin_required
def admin_add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user")
    if not username or not password:
        return jsonify({"ok": False, "msg": "用户名和密码不能为空"})
    ok = add_user(username, password, role)
    return jsonify({"ok": ok, "msg": "添加成功" if ok else "用户名已存在"})


@app.route("/admin/user/delete", methods=["POST"])
@admin_required
def admin_delete_user():
    user_id = request.form.get("user_id", type=int)
    if user_id == session.get("user_id"):
        return jsonify({"ok": False, "msg": "不能删除自己"})
    ok = delete_user(user_id)
    return jsonify({"ok": ok, "msg": "已删除" if ok else "用户不存在"})


# ============================================================
#  API 路由
# ============================================================
@app.route("/img")
def img_proxy():
    url = request.args.get("url", "")
    if not url:
        return "no url", 400
    cache_key = hashlib.md5(url.encode()).hexdigest()[:12]
    cache_file = IMG_CACHE_DIR / cache_key
    if cache_file.exists():
        return send_file(cache_file, mimetype="image/webp")
    try:
        img_resp = requests.get(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                }, timeout=15)
        if img_resp.status_code == 200:
            cache_file.write_bytes(img_resp.content)
            return Response(img_resp.content, mimetype=img_resp.headers.get("Content-Type", "image/webp"))
    except Exception:
        pass
    return Response(status=404)


# ============================================================
#  文字模块 API
# ============================================================

def _save_text(filename: str, content: str, username: str = "") -> str:
    """保存文本到 data/texts/，返回唯一 id"""
    uid = hashlib.md5((filename + str(len(content))).encode()).hexdigest()[:10]
    path = TEXT_DIR / f"{uid}.txt"
    meta = {"uid": uid, "filename": filename, "size": len(content), "lines": content.count("\n") + 1,
            "user": username}
    path.write_text(content, encoding="utf-8")
    (TEXT_DIR / f"{uid}.meta.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    return uid


@app.route("/api/text/upload", methods=["POST"])
@login_required
def text_upload():
    """上传文本文件"""
    file = request.files.get("file")
    if not file:
        return jsonify({"ok": False, "msg": "请选择文件"})
    fname = secure_filename(file.filename)
    ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""

    content = ""
    if ext == "docx" and HAS_DOCX:
        try:
            import io as io_mod
            doc = Document(io_mod.BytesIO(file.read()))
            content = "\n".join(p.text for p in doc.paragraphs)
        except Exception:
            return jsonify({"ok": False, "msg": "DOCX 解析失败"})
    elif ext in ALLOWED_TEXT_EXT or not ext:
        try:
            raw = file.read()
            # 尝试各种编码
            for enc in ["utf-8", "gbk", "gb2312", "latin-1"]:
                try:
                    content = raw.decode(enc)
                    break
                except UnicodeDecodeError:
                    continue
            if not content and raw:
                content = raw.decode("utf-8", errors="replace")
        except Exception:
            return jsonify({"ok": False, "msg": "文件编码无法识别"})
    else:
        return jsonify({"ok": False, "msg": f"不支持的文件类型: .{ext}"})

    if not content.strip():
        return jsonify({"ok": False, "msg": "文件内容为空"})

    uid = _save_text(fname, content, session["user"])
    log_activity(session["user"], "文字", "上传", f"{fname} ({len(content)}字)", uid)
    return jsonify({"ok": True, "uid": uid, "filename": fname, "size": len(content),
                    "lines": content.count("\n") + 1})


@app.route("/api/text/paste", methods=["POST"])
@login_required
def text_paste():
    """粘贴文本内容"""
    data = request.get_json(force=True)
    content = (data or {}).get("content", "").strip()
    title = (data or {}).get("title", "").strip() or "未命名粘贴"
    if not content:
        return jsonify({"ok": False, "msg": "内容为空"})
    if len(content) > 5 * 1024 * 1024:
        return jsonify({"ok": False, "msg": "内容过大，限制 5MB"})
    uid = _save_text(title, content, session["user"])
    log_activity(session["user"], "文字", "粘贴", f"{title} ({len(content)}字)", uid)
    return jsonify({"ok": True, "uid": uid, "filename": title, "size": len(content),
                    "lines": content.count("\n") + 1})


@app.route("/api/text/fetch", methods=["POST"])
@login_required
def text_fetch():
    """抓取网页正文"""
    data = request.get_json(force=True)
    url = (data or {}).get("url", "").strip()
    if not url:
        return jsonify({"ok": False, "msg": "请输入 URL"})
    if not url.startswith("http"):
        url = "https://" + url
    try:
        resp = requests.get(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }, timeout=15)
        if resp.status_code != 200:
            return jsonify({"ok": False, "msg": f"请求失败，状态码 {resp.status_code}"})

        # 自动检测编码：优先 HTML meta charset > 响应头 > 猜
        raw = resp.content
        detected = None
        # 从 HTML meta 标签检测
        meta_match = re.search(rb'charset[="\s]+([a-zA-Z0-9_-]+)', raw[:2000], re.IGNORECASE)
        if meta_match:
            detected = meta_match.group(1).decode("ascii")
        # 备选：从 Content-Type 响应头
        if not detected:
            ct = resp.headers.get("Content-Type", "")
            ct_match = re.search(r"charset=([a-zA-Z0-9_-]+)", ct, re.IGNORECASE)
            if ct_match:
                detected = ct_match.group(1)
        # 尝试解码：优先检测到的编码，失败则用 replace 模式再试
        html = None
        if detected:
            try:
                html = raw.decode(detected)
            except (UnicodeDecodeError, LookupError):
                # 编码声明和实际不符（如搜狐 meta 说 utf-8 但有非法字节）
                try:
                    html = raw.decode(detected, errors="replace")
                except LookupError:
                    pass
        if html is None:
            for enc in ["utf-8", "gbk", "gb2312", "gb18030", "latin-1"]:
                try:
                    html = raw.decode(enc)
                    break
                except (UnicodeDecodeError, LookupError):
                    continue
        if html is None:
            html = raw.decode("utf-8", errors="replace")

        soup = BeautifulSoup(html, "html.parser")
        # 去掉无意义标签
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()
        text = soup.get_text()
        # 清理多余空行
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        content = "\n".join(lines)
        if len(content) < 50:
            return jsonify({"ok": False, "msg": "网页正文太短，可能被拦截"})
        title = soup.title.string.strip() if soup.title else url[:60]
        uid = _save_text(title[:80], content, session["user"])
        log_activity(session["user"], "文字", "抓取网页", f"{title[:80]} ({len(content)}字)", uid)
        return jsonify({"ok": True, "uid": uid, "filename": title[:80], "size": len(content),
                        "lines": len(lines)})
    except requests.exceptions.Timeout:
        return jsonify({"ok": False, "msg": "请求超时"})
    except Exception as e:
        return jsonify({"ok": False, "msg": f"抓取失败: {str(e)[:60]}"})


@app.route("/api/text/view/<uid>")
@login_required
def text_view(uid):
    """查看已保存的文本"""
    err = _content_owner_required(uid, TEXT_DIR, session)
    if err:
        return jsonify({"ok": False, "msg": err["msg"]}), err["status"]
    path = TEXT_DIR / f"{uid}.txt"
    meta_path = TEXT_DIR / f"{uid}.meta.json"
    if not path.exists():
        return jsonify({"ok": False, "msg": "文件不存在"})
    content = path.read_text(encoding="utf-8")
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    return jsonify({"ok": True, "uid": uid, "content": content, "meta": meta})


@app.route("/api/text/search/<uid>")
@login_required
def text_search(uid):
    """在文本中搜索关键词，返回高亮后的 HTML + 匹配信息"""
    err = _content_owner_required(uid, TEXT_DIR, session)
    if err:
        return jsonify({"ok": False, "msg": err["msg"]}), err["status"]
    import re as re_mod

    keyword = request.args.get("q", "").strip()
    whole_word = request.args.get("whole_word", "0") == "1"
    smart_punct = request.args.get("smart_punct", "0") == "1"
    path = TEXT_DIR / f"{uid}.txt"
    if not path.exists():
        return jsonify({"ok": False, "msg": "文件不存在"})
    content = path.read_text(encoding="utf-8")

    if not keyword:
        return jsonify({"ok": True, "uid": uid, "html": _html_escape(content),
                        "count": 0, "keyword": ""})

    has_ascii = bool(re_mod.search(r'[a-zA-Z]', keyword))

    # 构建搜索正则模式
    if smart_punct:
        escaped = _build_smart_regex(keyword)
    else:
        escaped = re_mod.escape(keyword)

    if whole_word and has_ascii:
        pattern_str = rf"\b{escaped}\b"
    else:
        pattern_str = escaped

    pattern = re_mod.compile(pattern_str, re_mod.IGNORECASE)

    # 统计次数：在原始内容上统计（smart 模式用正则，否则用简单 count）
    if smart_punct:
        count = len(re_mod.findall(pattern_str, content, re_mod.IGNORECASE))
    else:
        count = content.lower().count(keyword.lower())

    # 高亮替换
    marked = pattern.sub(
        lambda m: f'\x01MK\x01{m.group()}\x01ME\x01',
        content
    )
    highlighted = _html_escape(marked) \
        .replace('\x01MK\x01', '<mark class="search-highlight">') \
        .replace('\x01ME\x01', '</mark>')

    return jsonify({"ok": True, "uid": uid, "html": highlighted, "count": count,
                    "keyword": keyword})


# 智能标点——单字符等价映射表
SMART_EQUIV = {
    ord("'"):  "['‘’]",           # 直' ↔ 弯''
    ord('"'):  '["“”]',           # 直" ↔ 弯""
    ord('-'):  '[-–—]',           # 连字符 ↔ 短破折 ↔ 长破折
    ord('‘'): "['‘’]",       # 弯左' ↔ 直' 弯右'
    ord('’'): "['‘’]",       # 弯右' ↔ 直' 弯左'
    ord('“'): '["“”]',       # 弯左" ↔ 直" 弯右"
    ord('”'): '["“”]',       # 弯右" ↔ 直" 弯左"
    ord('–'): '[-–—]',       # 短破折 ↔ 连字符 长破折
    ord('—'): '[-–—]',       # 长破折 ↔ 连字符 短破折
    ord('…'): '(?:\\.\\.\\.|…)',  # … ↔ ...
}

# "..." 三个点 ↔ 省略号（多字符，需要特殊处理）
def _build_smart_regex(keyword: str) -> str:
    """将关键词转为智能匹配正则，自动等价弯引号、破折号、省略号"""
    import re as re_mod
    # 先处理 ... ↔ …
    parts = []
    i = 0
    while i < len(keyword):
        if keyword[i:i+3] == '...':
            parts.append(r'(?:\.\.\.|…)')
            i += 3
        elif keyword[i] == '…':  # …
            parts.append(r'(?:\.\.\.|…)')
            i += 1
        elif keyword[i:i+2] == '--':
            # -- 可匹配 —/–/--/-
            parts.append(r'(?:--?|[–—])')
            i += 2
        else:
            ch = keyword[i]
            parts.append(SMART_EQUIV.get(ord(ch), re_mod.escape(ch)))
            i += 1
    return ''.join(parts)


@app.route("/api/text/list")
@login_required
def text_list():
    """列出当前用户已保存的文本（管理员看全部）"""
    items = []
    current_user = session.get("user")
    is_admin = session.get("role") == "admin"
    for meta_path in sorted(TEXT_DIR.glob("*.meta.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if is_admin or meta.get("user") == current_user:
            items.append(meta)
    return jsonify({"ok": True, "items": items})


@app.route("/api/text/delete/<uid>", methods=["POST"])
@login_required
def text_delete(uid):
    """删除文本"""
    err = _content_owner_required(uid, TEXT_DIR, session)
    if err:
        return jsonify({"ok": False, "msg": err["msg"]}), err["status"]
    # 读取文件名用于日志
    meta_path = TEXT_DIR / f"{uid}.meta.json"
    fname = uid
    if meta_path.exists():
        m = json.loads(meta_path.read_text(encoding="utf-8"))
        fname = m.get("filename", uid)
    (TEXT_DIR / f"{uid}.txt").unlink(missing_ok=True)
    meta_path.unlink(missing_ok=True)
    log_activity(session["user"], "文字", "删除", fname, uid)
    return jsonify({"ok": True})


def _html_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") \
               .replace('"', "&quot;").replace("'", "&#39;")


# ============================================================
#  图片模块 API
# ============================================================
ALLOWED_IMG_EXT = {"jpg", "jpeg", "png", "webp", "gif", "bmp", "svg"}
IMG_MIME = {"jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
            "webp": "image/webp", "gif": "image/gif", "bmp": "image/bmp",
            "svg": "image/svg+xml"}


def _save_image(filename: str, data: bytes, username: str = "") -> str:
    """保存图片到 data/images/，返回唯一 id"""
    uid = hashlib.md5(filename.encode() + data[:100]).hexdigest()[:12]
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "jpg"
    path = IMAGE_DIR / f"{uid}.{ext}"
    meta = {
        "uid": uid, "filename": filename, "ext": ext,
        "size": len(data), "mime": IMG_MIME.get(ext, "image/jpeg"),
        "source": "upload", "user": username,
    }
    path.write_bytes(data)
    (IMAGE_DIR / f"{uid}.meta.json").write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
    return uid


@app.route("/api/image/upload", methods=["POST"])
@login_required
def image_upload():
    """上传图片"""
    file = request.files.get("file")
    if not file:
        return jsonify({"ok": False, "msg": "请选择文件"})
    fname = secure_filename(file.filename)
    ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
    if ext not in ALLOWED_IMG_EXT:
        return jsonify({"ok": False, "msg": f"不支持的文件类型: .{ext}，支持 {', '.join(sorted(ALLOWED_IMG_EXT))}"})
    data = file.read()
    if len(data) == 0:
        return jsonify({"ok": False, "msg": "文件为空"})
    if len(data) > 20 * 1024 * 1024:
        return jsonify({"ok": False, "msg": "文件过大，限制 20MB"})
    uid = _save_image(fname, data, session["user"])
    log_activity(session["user"], "图片", "上传", fname, uid)
    return jsonify({"ok": True, "uid": uid, "filename": fname, "size": len(data), "ext": ext})


@app.route("/api/image/fetch", methods=["POST"])
@login_required
def image_fetch():
    """抓取网页中的所有图片 URL，不下載到本地（避免过大）"""
    data = request.get_json(force=True)
    url = (data or {}).get("url", "").strip()
    if not url:
        return jsonify({"ok": False, "msg": "请输入 URL"})
    if not url.startswith("http"):
        url = "https://" + url
    try:
        resp = requests.get(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }, timeout=15)
        if resp.status_code != 200:
            return jsonify({"ok": False, "msg": f"请求失败，状态码 {resp.status_code}"})
        # 编码检测
        raw = resp.content
        soup = BeautifulSoup(raw, "html.parser", from_encoding=_detect_encoding(raw, resp))
        imgs = []
        seen = set()
        for tag in soup.find_all("img"):
            src = tag.get("src") or tag.get("data-src") or tag.get("data-original") or ""
            if not src:
                continue
            # 补全相对路径
            src = urljoin(url, src)
            if src in seen:
                continue
            seen.add(src)
            # 过滤太小的图标
            w = int(tag.get("width") or 0)
            h = int(tag.get("height") or 0)
            alt = tag.get("alt", "")
            imgs.append({"url": src, "width": w, "height": h, "alt": alt[:80]})
        if not imgs:
            return jsonify({"ok": False, "msg": "该页面没有找到图片"})
        return jsonify({"ok": True, "url": url, "images": imgs[:60], "total": len(imgs)})
    except requests.exceptions.Timeout:
        return jsonify({"ok": False, "msg": "请求超时"})
    except Exception as e:
        return jsonify({"ok": False, "msg": f"抓取失败: {str(e)[:60]}"})


@app.route("/api/image/save-url", methods=["POST"])
@login_required
def image_save_url():
    """将远程图片 URL 下载到本地存储"""
    data = request.get_json(force=True)
    img_url = (data or {}).get("url", "").strip()
    if not img_url:
        return jsonify({"ok": False, "msg": "缺少 URL"})
    result = _download_one_image(img_url)
    if result.get("ok"):
        # 补充用户信息到元数据
        try:
            mp = IMAGE_DIR / f"{result['uid']}.meta.json"
            meta = json.loads(mp.read_text(encoding="utf-8"))
            meta["user"] = session["user"]
            mp.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass
        log_activity(session["user"], "图片", "链接导入", result.get("filename", img_url), result.get("uid", ""))
        return jsonify(result)
    return jsonify(result)


# 防盗链重试策略：依次尝试不同 headers 组合
_RETRY_HEADERS = [
    # 策略 1：标准浏览器 + 本页 Referer
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
     "Referer": "",   # 替换为图片 URL 自身
     "Accept": "image/avif,image/webp,image/*,*/*;q=0.8"},
    # 策略 2：不发送 Referer
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
     "Accept": "image/avif,image/webp,image/*,*/*;q=0.8"},
    # 策略 3：模拟图片 CDN 请求（无 Referer, Chrome UA）
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
     "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8"},
    # 策略 4：宽松模式，允许所有
    {"User-Agent": "curl/8.0",
     "Accept": "*/*"},
]


def _try_download(url: str) -> requests.Response | None:
    """用多种 headers 策略尝试下载，返回第一个成功的响应"""
    for strategy in _RETRY_HEADERS:
        headers = dict(strategy)
        # 把空的 Referer 替换为图片 URL
        if "Referer" in headers and not headers["Referer"]:
            headers["Referer"] = url
        try:
            r = requests.get(url, headers=headers, timeout=12,
                           allow_redirects=True, stream=False)
            if r.status_code == 200 and len(r.content) >= 50:
                ct = r.headers.get("Content-Type", "").lower()
                if ct and "text/html" in ct:
                    continue  # 跳转到了网页，不可能是图片
                return r
        except Exception:
            continue
    return None


def _download_one_image(img_url: str) -> dict:
    """下载一张远程图片到本地。多策略重试防盗链。"""
    try:
        r = _try_download(img_url)
        if r is None:
            return {"url": img_url, "ok": False, "msg": "下载失败，图片源设置了防盗链"}

        ct = r.headers.get("Content-Type", "").lower()
        if ct and "image" not in ct and "octet-stream" not in ct and "svg" not in ct:
            # 可能是重定向到了网页
            return {"url": img_url, "ok": False, "msg": "该 URL 返回的不是图片"}

        # 智能提取文件名和扩展名
        parsed = urlparse(img_url)
        fname = parsed.path.rsplit("/", 1)[-1] if parsed.path else ""
        fname = fname.split("?")[0] or "image.jpg"
        got_ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""

        if got_ext not in ALLOWED_IMG_EXT:
            qs = parse_qs(parsed.query)
            for key in ("e", "ext", "format", "type"):
                if key in qs:
                    maybe = qs[key][0].lstrip(".").lower()
                    if maybe in ALLOWED_IMG_EXT:
                        fname = fname + "." + maybe
                        got_ext = maybe
                        break
        if got_ext not in ALLOWED_IMG_EXT:
            ct_to_ext = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp",
                         "image/gif": "gif", "image/bmp": "bmp",
                         "image/svg+xml": "svg", "image/svg": "svg"}
            for mime, ext in ct_to_ext.items():
                if mime in ct:
                    fname = fname.rsplit(".", 1)[0] + "." + ext
                    got_ext = ext
                    break
        if got_ext not in ALLOWED_IMG_EXT:
            fname = fname.rsplit(".", 1)[0] + ".jpg"

        uid = _save_image(fname, r.content)
        mp = IMAGE_DIR / f"{uid}.meta.json"
        meta = json.loads(mp.read_text(encoding="utf-8"))
        meta["source"] = "fetch"
        meta["origin_url"] = img_url
        mp.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
        return {"url": img_url, "ok": True, "uid": uid, "filename": fname, "size": len(r.content)}
    except (requests.RequestException, OSError, json.JSONDecodeError) as e:
        return {"url": img_url, "ok": False, "msg": str(e)[:80]}


@app.route("/api/image/save-batch", methods=["POST"])
@login_required
def image_save_batch():
    """批量下载远程图片，服务端并行"""
    data = request.get_json(force=True)
    urls = (data or {}).get("urls", [])
    if not urls:
        return jsonify({"ok": False, "msg": "缺少 urls"})
    urls = [u.strip() for u in urls if u.strip()][:50]

    results = []
    ok_count = 0
    # 5 线程并行下载，比浏览器排队快很多
    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(_download_one_image, u): u for u in urls}
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            if r.get("ok"):
                ok_count += 1

    log_activity(session["user"], "图片", "批量导入", f"{ok_count}/{len(urls)} 张成功", "")
    # 补充用户信息到所有成功保存的图片元数据
    for r in results:
        if r.get("ok") and r.get("uid"):
            try:
                mp = IMAGE_DIR / f"{r['uid']}.meta.json"
                meta = json.loads(mp.read_text(encoding="utf-8"))
                meta["user"] = session["user"]
                mp.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
            except Exception:
                pass
    return jsonify({"ok": True, "results": results, "saved": ok_count, "total": len(urls)})


@app.route("/api/image/view/<uid>")
@login_required
def image_view(uid):
    """提供图片文件（支持 .ext 后缀忽略）—— 需要登录 + 所有权检查"""
    # 所有权检查：非管理员只能看自己的图片
    err = _content_owner_required(uid, IMAGE_DIR, session)
    if err:
        return Response(status=err["status"])
    uid_clean = uid.rsplit(".", 1)[0]
    for ext in ALLOWED_IMG_EXT:
        path = IMAGE_DIR / f"{uid_clean}.{ext}"
        if path.exists():
            return send_file(path, mimetype=IMG_MIME.get(ext, "image/jpeg"))
    return Response(status=404)


@app.route("/api/image/list")
@login_required
def image_list():
    """列出当前用户已存储的图片（管理员看全部），可选附带标签"""
    with_tags = request.args.get("with_tags", "0") == "1"
    is_admin = session.get("role") == "admin"
    current_user = session.get("user")
    my_tags = _get_my_tags(current_user, is_admin) if with_tags else {}
    items = []
    for mp in sorted(IMAGE_DIR.glob("*.meta.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        meta = json.loads(mp.read_text(encoding="utf-8"))
        if not is_admin and meta.get("user") != current_user:
            continue
        meta["view_url"] = f"/api/image/view/{meta['uid']}"
        if with_tags:
            meta["tags"] = my_tags.get(meta["uid"], [])
        items.append(meta)
    return jsonify({"ok": True, "items": items})


@app.route("/api/image/delete/<uid>", methods=["POST"])
@login_required
def image_delete(uid):
    """删除图片"""
    err = _content_owner_required(uid, IMAGE_DIR, session)
    if err:
        return jsonify({"ok": False, "msg": err["msg"]}), err["status"]
    uid_clean = uid.rsplit(".", 1)[0]
    # 读取文件名用于日志
    fname = uid_clean
    mp = IMAGE_DIR / f"{uid_clean}.meta.json"
    if mp.exists():
        try:
            m = json.loads(mp.read_text(encoding="utf-8"))
            fname = m.get("filename", uid_clean)
        except Exception:
            pass
    for ext in ALLOWED_IMG_EXT:
        (IMAGE_DIR / f"{uid_clean}.{ext}").unlink(missing_ok=True)
    mp.unlink(missing_ok=True)
    log_activity(session["user"], "图片", "删除", fname, uid)
    return jsonify({"ok": True})


# ============================================================
#  更多工具 API
# ============================================================

@app.route("/api/image/search", methods=["POST"])
@login_required
def image_search_engine():
    """搜图引擎：从百度图片搜索结果页提取图片URL，支持翻页"""
    data = request.get_json(force=True)
    keyword = (data or {}).get("keyword", "").strip()
    page = max(0, (data or {}).get("page", 0) or 0)
    if not keyword:
        return jsonify({"ok": False, "msg": "请输入关键词"})
    img_urls = _search_baidu_images(keyword, page)
    if not img_urls:
        return jsonify({"ok": False, "msg": "未找到图片或百度搜图暂时不可用"})
    return jsonify({"ok": True, "images": [{"url": u} for u in img_urls][:40],
                    "keyword": keyword, "total": len(img_urls), "page": page})


def _search_baidu_images(keyword: str, page: int = 0) -> list[str]:
    """从百度图片搜索页提取图片直链，支持翻页"""
    pn = page * 30
    url = f"https://image.baidu.com/search/flip?tn=baiduimage&word={requests.utils.quote(keyword)}&pn={pn}"
    try:
        resp = requests.get(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml",
            "Referer": "https://image.baidu.com/",
        }, timeout=10)
        if resp.status_code != 200:
            return []
        # 百度搜图页面在 objURL 字段中存放图片直链
        urls = re.findall(r'"objURL":"([^"]+)"', resp.text)
        return urls
    except Exception:
        return []


# ============================================================
#  标签 API
# ============================================================
TAG_FILE = IMAGE_DIR / "tags.json"


def _content_owner_required(uid: str, directory: Path, session) -> dict | None:
    """检查内容所有权。管理员返回 None；普通用户检查 meta.user"""
    if session.get("role") == "admin":
        return None
    uid_clean = uid.rsplit(".", 1)[0] if "." in uid else uid
    meta_path = directory / f"{uid_clean}.meta.json"
    if not meta_path.exists():
        return {"ok": False, "msg": "内容不存在", "status": 404}
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return {"ok": False, "msg": "元数据读取失败", "status": 500}
    if meta.get("user") != session.get("user"):
        return {"ok": False, "msg": "无权访问此内容", "status": 403}
    return None


def _load_tags() -> dict:
    """加载标签数据。格式：{username: {uid: [tags]}}（按用户）。
    旧格式 {uid: [tags]} 自动迁移到 {"_legacy": {uid: [tags]}}。"""
    if not TAG_FILE.exists():
        return {}
    data = json.loads(TAG_FILE.read_text(encoding="utf-8"))
    # 检测旧格式：值不是 dict 说明是扁平 {uid: [tags]}
    if data and not any(isinstance(v, dict) for v in data.values()):
        data = {"_legacy": data}
        TAG_FILE.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return data


def _save_all_tags(data: dict):
    TAG_FILE.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def _get_my_tags(username: str, is_admin: bool = False) -> dict[str, list[str]]:
    """获取当前用户可见的标签。管理员看合并所有用户后的视图。"""
    all_data = _load_tags()
    if is_admin:
        merged = {}
        for user_tags in all_data.values():
            merged.update(user_tags)
        return merged
    return all_data.get(username, {})


def _save_my_tags(username: str, user_tags: dict[str, list[str]]):
    all_data = _load_tags()
    all_data[username] = user_tags
    _save_all_tags(all_data)


@app.route("/api/image/tags/<uid>")
@login_required
def image_get_tags(uid):
    """获取某图片的标签"""
    uid_clean = uid.rsplit(".", 1)[0]
    tags = _get_my_tags(session["user"], session.get("role") == "admin")
    return jsonify({"ok": True, "uid": uid_clean, "tags": tags.get(uid_clean, [])})


@app.route("/api/image/tags/<uid>", methods=["POST"])
@login_required
def image_set_tags(uid):
    """设置某图片的标签"""
    uid_clean = uid.rsplit(".", 1)[0]
    data = request.get_json(force=True)
    tags_input = (data or {}).get("tags", [])
    if isinstance(tags_input, str):
        tags_input = [t.strip() for t in tags_input.split(",") if t.strip()]
    tags_input = [t.strip() for t in tags_input if t.strip()][:20]
    is_admin = session.get("role") == "admin"
    all_tags = _get_my_tags(session["user"], is_admin)
    all_tags[uid_clean] = tags_input
    _save_my_tags(session["user"], all_tags)
    log_activity(session["user"], "图片", "编辑标签", f"设置 {len(tags_input)} 个标签", uid_clean)
    return jsonify({"ok": True, "uid": uid_clean, "tags": tags_input})


@app.route("/api/image/tags")
@login_required
def image_all_tags():
    """获取所有标签及计数（按用户隔离，管理员看全部）"""
    my_tags = _get_my_tags(session["user"], session.get("role") == "admin")
    tag_count: dict[str, int] = {}
    for tags in my_tags.values():
        for t in tags:
            tag_count[t] = tag_count.get(t, 0) + 1
    sorted_tags = sorted(tag_count.items(), key=lambda x: -x[1])
    return jsonify({"ok": True, "tags": [{"name": k, "count": v} for k, v in sorted_tags]})


@app.route("/api/image/tags/<uid>/<tag>", methods=["DELETE"])
@login_required
def image_delete_single_tag(uid, tag):
    """从某张图片上删除一个特定标签"""
    uid_clean = uid.rsplit(".", 1)[0]
    is_admin = session.get("role") == "admin"
    all_tags = _get_my_tags(session["user"], is_admin)
    current = all_tags.get(uid_clean, [])
    if tag in current:
        current.remove(tag)
        if current:
            all_tags[uid_clean] = current
        else:
            all_tags.pop(uid_clean, None)
        _save_my_tags(session["user"], all_tags)
    return jsonify({"ok": True, "uid": uid_clean, "tags": all_tags.get(uid_clean, [])})


@app.route("/api/image/tag/<tag>", methods=["DELETE"])
@login_required
def image_delete_tag_global(tag):
    """全局删除一个标签，从所有拥有该标签的图片中移除（仅当前用户范围）"""
    is_admin = session.get("role") == "admin"
    all_tags = _get_my_tags(session["user"], is_admin)
    removed = 0
    for uid in list(all_tags.keys()):
        if tag in all_tags[uid]:
            all_tags[uid].remove(tag)
            removed += 1
            if not all_tags[uid]:
                all_tags.pop(uid, None)
    _save_my_tags(session["user"], all_tags)
    return jsonify({"ok": True, "tag": tag, "removed_from": removed})


@app.route("/api/image/tag/rename", methods=["POST"])
@login_required
def image_rename_tag_global():
    """全局重命名标签，所有拥有旧标签的图片改为新标签名"""
    data = request.get_json(force=True)
    old_name = (data or {}).get("old_name", "").strip()
    new_name = (data or {}).get("new_name", "").strip()
    if not old_name or not new_name:
        return jsonify({"ok": False, "msg": "新旧标签名不能为空"})
    is_admin = session.get("role") == "admin"
    all_tags = _get_my_tags(session["user"], is_admin)
    changed = 0
    for uid in list(all_tags.keys()):
        tags = all_tags[uid]
        if old_name in tags:
            new_tags = [new_name if t == old_name else t for t in tags]
            if new_tags.count(new_name) > 1:
                new_tags = list(dict.fromkeys(new_tags))
            all_tags[uid] = new_tags
            changed += 1
    _save_my_tags(session["user"], all_tags)
    return jsonify({"ok": True, "old_name": old_name, "new_name": new_name, "changed": changed})


@app.route("/api/image/tag/bulk-add", methods=["POST"])
@login_required
def image_bulk_add_tag():
    """给多张图片批量添加同一个标签"""
    data = request.get_json(force=True)
    tag_name = (data or {}).get("tag_name", "").strip()
    uids = (data or {}).get("uids") or []
    if not tag_name:
        return jsonify({"ok": False, "msg": "标签名不能为空"})
    if not uids:
        return jsonify({"ok": False, "msg": "请选择至少一张图片"})
    uids = [u.rsplit(".", 1)[0] for u in uids]
    is_admin = session.get("role") == "admin"
    all_tags = _get_my_tags(session["user"], is_admin)
    added = 0
    for uid in uids:
        current = all_tags.get(uid, [])
        if tag_name not in current:
            current.append(tag_name)
            all_tags[uid] = current[:20]
            added += 1
    _save_my_tags(session["user"], all_tags)
    return jsonify({"ok": True, "tag_name": tag_name, "added_to": added})


# ============================================================
#  打包下载 API
# ============================================================
@app.route("/api/image/download-zip", methods=["POST"])
@login_required
def image_download_zip():
    """批量下载：选中的 uids 打包成 zip"""
    import zipfile
    import io as io_mod
    data = request.get_json(force=True)
    uids = (data or {}).get("uids", [])
    if not uids:
        return jsonify({"ok": False, "msg": "请选择要下载的图片"})

    # 验证所有权
    for uid_raw in uids:
        err = _content_owner_required(uid_raw, IMAGE_DIR, session)
        if err:
            return jsonify({"ok": False, "msg": err["msg"]}), err["status"]

    buf = io_mod.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for uid_raw in uids:
            uid_clean = uid_raw.rsplit(".", 1)[0]
            for ext in ALLOWED_IMG_EXT:
                p = IMAGE_DIR / f"{uid_clean}.{ext}"
                if p.exists():
                    meta_p = IMAGE_DIR / f"{uid_clean}.meta.json"
                    fname = uid_clean + "." + ext
                    if meta_p.exists():
                        m = json.loads(meta_p.read_text(encoding="utf-8"))
                        fname = m.get("filename", fname)
                    zf.write(p, fname)
                    break
    buf.seek(0)
    return Response(buf.getvalue(),
                    mimetype="application/zip",
                    headers={"Content-Disposition": f"attachment; filename=images_{len(uids)}.zip"})


# ============================================================
#  占用统计 API
# ============================================================
@app.route("/api/image/stats")
@login_required
def image_stats():
    """图片库占用统计（当前用户，管理员看全部）"""
    total_count = 0
    total_size = 0
    ext_count: dict[str, int] = {}
    current_user = session.get("user")
    is_admin = session.get("role") == "admin"
    for mp in IMAGE_DIR.glob("*.meta.json"):
        meta = json.loads(mp.read_text(encoding="utf-8"))
        if not is_admin and meta.get("user") != current_user:
            continue
        total_count += 1
        total_size += meta.get("size", 0)
        ext = meta.get("ext", "unknown")
        ext_count[ext] = ext_count.get(ext, 0) + 1
    return jsonify({
        "ok": True,
        "total_count": total_count,
        "total_size": total_size,
        "total_size_mb": round(total_size / 1024 / 1024, 2),
        "ext_count": ext_count,
    })


def _detect_encoding(raw: bytes, resp) -> str:
    """从响应内容检测编码"""
    import re as re_mod
    m = re_mod.search(rb'charset[="\s]+([a-zA-Z0-9_-]+)', raw[:2000], re_mod.IGNORECASE)
    if m:
        return m.group(1).decode("ascii")
    ct = resp.headers.get("Content-Type", "")
    m = re_mod.search(r"charset=([a-zA-Z0-9_-]+)", ct, re_mod.IGNORECASE)
    if m:
        return m.group(1)
    return "utf-8"


# ============================================================
#  主页面
# ============================================================
@app.route("/")
@login_required
def index():
    return render_template(
        "index.html",
        user=session.get("user"),
        role=session.get("role"),
    )


# ============================================================
#  启动
# ============================================================
if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000, threaded=True)


# 生产环境启动时初始化数据库（gunicorn 加载 app 时执行）
init_db()
