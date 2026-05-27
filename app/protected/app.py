"""
Protected Flask app — same business logic as vulnerable, with defense middleware.
Runs on port 5001.
"""
import os
import sqlite3
import hashlib
import subprocess

from flask import (
    Flask, request, session, redirect, url_for,
    render_template, flash, send_file, abort, g
)

from app.protected.middleware import (
    register_middleware,
    generate_csrf_token,
    record_login_failure,
    reset_rate_limit,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.join(BASE_DIR, "..", "..")
TEMPLATE_DIR = os.path.join(ROOT_DIR, "shared", "templates")
DB_PATH = os.path.join(ROOT_DIR, "app.db")
MESSAGES_DIR = os.path.join(ROOT_DIR, "messages")
UPLOADS_DIR = os.path.join(ROOT_DIR, "uploads")

app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.secret_key = "protected-secret-change-in-prod"
app.debug = False  # FIXED: no stack traces

register_middleware(app)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def _csrf():
    return generate_csrf_token()


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html", mode="protected", message=str(e)), 403


@app.errorhandler(429)
def too_many_requests(e):
    return render_template("429.html", mode="protected"), 429


@app.errorhandler(400)
def bad_request(e):
    return render_template("403.html", mode="protected", message="请求无效：" + str(e)), 400


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("messages"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ip = request.remote_addr or "unknown"
        db = get_db()
        # FIXED: parameterized query
        row = db.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, hash_password(password)),
        ).fetchone()
        if row:
            reset_rate_limit(ip)
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            flash("登录成功", "success")
            return redirect(url_for("messages"))
        record_login_failure(ip)
        flash("用户名或密码错误", "danger")
    return render_template("login.html", mode="protected", csrf_token=_csrf())


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password, role, email) VALUES (?,?,?,?)",
                (username, hash_password(password), "user", email),
            )
            db.commit()
            flash("注册成功，请登录", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("用户名已存在", "danger")
    return render_template("register.html", mode="protected", csrf_token=_csrf())


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

def _require_login():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    return None


@app.route("/messages", methods=["GET", "POST"])
def messages():
    redir = _require_login()
    if redir:
        return redir
    db = get_db()
    if request.method == "POST":
        # FIXED: use sanitized form values from g.safe_form (set by middleware)
        content = g.safe_form.get("content", "")
        uid = session["user_id"]
        uname = session["username"]
        db.execute(
            "INSERT INTO messages (user_id, username, content) VALUES (?,?,?)",
            (uid, uname, content),
        )
        db.commit()
        msg_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        filepath = os.path.join(MESSAGES_DIR, f"msg_{msg_id}_{uname}.txt")
        os.makedirs(MESSAGES_DIR, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        db.execute("UPDATE messages SET filepath=? WHERE id=?", (filepath, msg_id))
        db.commit()
        flash("留言发布成功", "success")
        return redirect(url_for("messages"))
    rows = db.execute(
        "SELECT * FROM messages ORDER BY created_at DESC"
    ).fetchall()
    return render_template("messages.html", messages=rows, mode="protected", csrf_token=_csrf())


@app.route("/messages/delete", methods=["POST"])
def delete_message():
    redir = _require_login()
    if redir:
        return redir
    msg_id = request.form.get("msg_id")
    db = get_db()
    # FIXED: ownership check
    row = db.execute(
        "SELECT * FROM messages WHERE id=? AND user_id=?",
        (msg_id, session["user_id"]),
    ).fetchone()
    if not row:
        abort(403)
    if row["filepath"] and os.path.exists(row["filepath"]):
        os.remove(row["filepath"])
    db.execute("DELETE FROM messages WHERE id=?", (msg_id,))
    db.commit()
    flash("留言已删除", "success")
    return redirect(url_for("messages"))


@app.route("/search")
def search():
    redir = _require_login()
    if redir:
        return redir
    q = g.safe_args.get("q", "")
    db = get_db()
    # FIXED: parameterized query
    results = db.execute(
        "SELECT * FROM messages WHERE content LIKE ? ORDER BY created_at DESC",
        (f"%{q}%",),
    ).fetchall()
    return render_template("search.html", q=q, results=results, mode="protected")


# ---------------------------------------------------------------------------
# File download — path traversal fixed
# ---------------------------------------------------------------------------

@app.route("/download")
def download():
    redir = _require_login()
    if redir:
        return redir
    filename = request.args.get("filename", "")
    # FIXED: normalize and restrict to messages dir
    safe_path = os.path.realpath(os.path.join(MESSAGES_DIR, filename))
    if not safe_path.startswith(os.path.realpath(MESSAGES_DIR)):
        abort(403)
    if os.path.exists(safe_path):
        return send_file(safe_path, as_attachment=True)
    abort(404)


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------

@app.route("/profile", methods=["GET"])
def profile():
    redir = _require_login()
    if redir:
        return redir
    return render_template("profile.html", mode="protected", csrf_token=_csrf())


@app.route("/profile/password", methods=["POST"])
def change_password():
    redir = _require_login()
    if redir:
        return redir
    # FIXED: CSRF validated by middleware
    new_pw = request.form.get("new_password", "")
    db = get_db()
    db.execute(
        "UPDATE users SET password=? WHERE id=?",
        (hash_password(new_pw), session["user_id"]),
    )
    db.commit()
    flash("密码已修改", "success")
    return redirect(url_for("profile"))


@app.route("/profile/avatar", methods=["POST"])
def upload_avatar():
    redir = _require_login()
    if redir:
        return redir
    # FIXED: extension check done by middleware before reaching here
    f = request.files.get("avatar")
    if not f or not f.filename:
        flash("请选择文件", "warning")
        return redirect(url_for("profile"))
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    save_path = os.path.join(UPLOADS_DIR, f.filename)
    f.save(save_path)
    flash(f"文件已上传: {f.filename}", "success")
    return redirect(url_for("profile"))


# ---------------------------------------------------------------------------
# Admin — role check enforced by middleware
# ---------------------------------------------------------------------------

@app.route("/admin/users")
def admin_users():
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    return render_template("admin_users.html", users=users, mode="protected", csrf_token=_csrf())


@app.route("/admin/users/delete", methods=["POST"])
def admin_delete_user():
    user_id = request.form.get("user_id")
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    flash("用户已删除", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/messages")
def admin_messages():
    files = []
    if os.path.exists(MESSAGES_DIR):
        files = os.listdir(MESSAGES_DIR)
    return render_template("admin_messages.html", files=files, mode="protected", csrf_token=_csrf())


@app.route("/admin/messages/delete", methods=["POST"])
def admin_delete_message_file():
    # FIXED: use list form (no shell=True), filename validated by middleware
    filename = request.form.get("filename", "")
    safe_path = os.path.realpath(os.path.join(MESSAGES_DIR, filename))
    if not safe_path.startswith(os.path.realpath(MESSAGES_DIR)):
        abort(403)
    if os.path.exists(safe_path):
        subprocess.run(["rm", safe_path], check=False)
        flash("文件已删除", "success")
    else:
        flash("文件不存在", "warning")
    return redirect(url_for("admin_messages"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
