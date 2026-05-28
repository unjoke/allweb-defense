"""
Vulnerable Flask app — intentionally insecure for demonstration.
Runs on port 5000. DO NOT expose to public network.
"""
import os
import sys
import sqlite3
import hashlib
import subprocess

from flask import (
    Flask, request, session, redirect, url_for,
    render_template, flash, send_file, abort, g
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.join(BASE_DIR, "..", "..")
TEMPLATE_DIR = os.path.join(ROOT_DIR, "shared", "templates")
DB_PATH = os.path.join(ROOT_DIR, "app.db")
MESSAGES_DIR = os.path.join(ROOT_DIR, "messages")
UPLOADS_DIR = os.path.join(ROOT_DIR, "uploads")

app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.secret_key = "vuln-secret-do-not-use"
app.debug = True  # VULN: exposes stack traces


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
        pw_hash = hash_password(password)
        db = get_db()
        # VULN: SQL injection — string concatenation
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{pw_hash}'"
        try:
            row = db.execute(query).fetchone()
        except Exception as e:
            # VULN: exposes raw SQL error
            return f"<pre>SQL Error: {e}\nQuery: {query}</pre>", 500
        if row:
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            session["role"] = row["role"]
            flash("登录成功", "success")
            return redirect(url_for("messages"))
        flash("用户名或密码错误", "danger")
    return render_template("login.html", mode="vulnerable")


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
    return render_template("register.html", mode="vulnerable")


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
        content = request.form.get("content", "")
        uid = session["user_id"]
        uname = session["username"]
        # VULN: content stored and rendered without sanitization (stored XSS)
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
    return render_template("messages.html", messages=rows, mode="vulnerable",
                           current_role=session.get("role", ""))


@app.route("/messages/delete", methods=["POST"])
def delete_message():
    redir = _require_login()
    if redir:
        return redir
    msg_id = request.form.get("msg_id")
    db = get_db()
    # VULN: no role check — vertical privilege escalation (any logged-in user can delete)
    row = db.execute("SELECT * FROM messages WHERE id=?", (msg_id,)).fetchone()
    if row:
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
    q = request.args.get("q", "")
    db = get_db()
    # VULN: SQL injection + reflected XSS — q injected into query and reflected
    query = f"SELECT * FROM messages WHERE content LIKE '%{q}%' ORDER BY created_at DESC"
    try:
        results = db.execute(query).fetchall()
    except Exception as e:
        return f"<pre>SQL Error: {e}\nQuery: {query}</pre>", 500
    return render_template("search.html", q=q, results=results, mode="vulnerable")


# ---------------------------------------------------------------------------
# File download — path traversal
# ---------------------------------------------------------------------------

@app.route("/download")
def download():
    redir = _require_login()
    if redir:
        return redir
    filename = request.args.get("filename", "")
    # VULN: path traversal — no normalization
    filepath = os.path.join(MESSAGES_DIR, filename)
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    # VULN: also try relative to ROOT_DIR for wider traversal demo
    filepath2 = os.path.join(ROOT_DIR, filename)
    if os.path.exists(filepath2):
        return send_file(filepath2, as_attachment=True)
    abort(404)


# ---------------------------------------------------------------------------
# Profile — CSRF + unsafe upload
# ---------------------------------------------------------------------------

@app.route("/profile", methods=["GET"])
def profile():
    redir = _require_login()
    if redir:
        return redir
    return render_template("profile.html", mode="vulnerable")


@app.route("/profile/password", methods=["POST"])
def change_password():
    redir = _require_login()
    if redir:
        return redir
    # VULN: no CSRF token check
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
    f = request.files.get("avatar")
    if not f or not f.filename:
        flash("请选择文件", "warning")
        return redirect(url_for("profile"))
    # VULN: no extension check — unsafe file upload
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    save_path = os.path.join(UPLOADS_DIR, f.filename)
    f.save(save_path)
    flash(f"文件已上传: {f.filename}", "success")
    return redirect(url_for("profile"))


# ---------------------------------------------------------------------------
# Admin — vertical privilege escalation (no role check)
# ---------------------------------------------------------------------------

@app.route("/admin/users")
def admin_users():
    # VULN: no role check — vertical privilege escalation
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    return render_template("admin_users.html", users=users, mode="vulnerable")


@app.route("/admin/users/delete", methods=["POST"])
def admin_delete_user():
    # VULN: no role check
    user_id = request.form.get("user_id")
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (user_id,))
    db.commit()
    flash("用户已删除", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/messages")
def admin_messages():
    # VULN: no role check
    files = []
    if os.path.exists(MESSAGES_DIR):
        files = os.listdir(MESSAGES_DIR)
    return render_template("admin_messages.html", files=files, mode="vulnerable")


@app.route("/admin/messages/delete", methods=["POST"])
def admin_delete_message_file():
    # VULN: no role check + command injection via subprocess shell=True
    filename = request.form.get("filename", "")
    cmd = f"rm {os.path.join(MESSAGES_DIR, filename)}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    output = result.stdout + result.stderr
    flash(f"执行结果: {output or '文件已删除'}", "info")
    return redirect(url_for("admin_messages"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
