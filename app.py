"""
OWASP Vulnerable Single-File Flask Lab
--------------------------------------
Deliberately vulnerable training app. Run only on localhost / isolated lab VM.

Vulnerabilities included:
- Reflected XSS
- Stored XSS
- Server-Side Template Injection (SSTI)
- SQL Injection
- Broken Authentication / weak login
- Broken Access Control / RBAC bypass
- IDOR
- Sensitive data exposure
- Insecure file upload
- Security misconfiguration
- Vulnerable deserialization
- SSRF-style unsafe URL fetch demo

Install:
    pip install Flask requests

Run:
    python app.py

Open:
    http://127.0.0.1:5000
"""

from flask import Flask, request, render_template_string, redirect, make_response
import sqlite3
import os
import pickle
import base64
import requests

app = Flask(__name__)
app.secret_key = "hardcoded-dev-secret-key"  # VULN: hardcoded secret

DB = "lab.db"
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

USERS = {
    "admin": {"password": "admin123", "role": "admin", "id": 1, "api_key": "ADMIN-SECRET-KEY-123"},
    "alice": {"password": "password", "role": "user", "id": 2, "api_key": "ALICE-SECRET-KEY-456"},
    "bob": {"password": "password", "role": "user", "id": 3, "api_key": "BOB-SECRET-KEY-789"},
}

stored_comments = []


def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY, name TEXT, price TEXT)")
    cur.execute("DELETE FROM products")
    cur.executemany(
        "INSERT INTO products (name, price) VALUES (?, ?)",
        [
            ("Laptop", "1000"),
            ("Phone", "700"),
            ("Keyboard", "100"),
        ],
    )
    conn.commit()
    conn.close()


def current_user():
    username = request.cookies.get("username")
    role = request.cookies.get("role")
    if username in USERS:
        user = dict(USERS[username])
        user["username"] = username

        # VULN: role is trusted from client-controlled cookie
        if role:
            user["role"] = role
        return user
    return None


@app.route("/")
def home():
    user = current_user()
    return f"""
    <h1>OWASP Vulnerable Single-File Lab</h1>
    <p><b>Warning:</b> deliberately vulnerable. Local lab use only.</p>
    <p>Current user: {user["username"] if user else "not logged in"} / role: {user["role"] if user else "none"}</p>

    <h2>Auth</h2>
    <ul>
      <li><a href="/login?username=alice&password=password">Login as alice</a></li>
      <li><a href="/login?username=admin&password=admin123">Login as admin</a></li>
      <li><a href="/logout">Logout</a></li>
    </ul>

    <h2>Vulnerable Routes</h2>
    <ul>
      <li><a href="/xss?q=%3Cscript%3Ealert(1)%3C/script%3E">Reflected XSS</a></li>
      <li><a href="/comment">Stored XSS</a></li>
      <li><a href="/ssti?name={{7*7}}">SSTI</a></li>
      <li><a href="/search?q=Laptop">SQL Injection</a></li>
      <li><a href="/profile?id=1">IDOR / Sensitive Data Exposure</a></li>
      <li><a href="/admin">RBAC Broken Access Control</a></li>
      <li><a href="/upload">Insecure File Upload</a></li>
      <li><a href="/debug-info">Security Misconfiguration</a></li>
      <li><a href="/deserialize?data=gASVCwAAAAAAAACMB2hlbGxvlC4=">Insecure Deserialization</a></li>
      <li><a href="/fetch?url=http://127.0.0.1:5000/debug-info">Unsafe URL Fetch / SSRF demo</a></li>
    </ul>
    """


# 1. Broken Authentication
@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")

    # VULN: credentials in URL, weak passwords, no rate limiting, no CSRF, no secure session
    if username in USERS and USERS[username]["password"] == password:
        resp = make_response(redirect("/"))
        resp.set_cookie("username", username)
        resp.set_cookie("role", USERS[username]["role"])  # VULN: client can modify role
        return resp

    return "Login failed. Try /login?username=alice&password=password", 401


@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("username")
    resp.delete_cookie("role")
    return resp


# 2. Reflected XSS
@app.route("/xss")
def reflected_xss():
    q = request.args.get("q", "")
    # VULN: raw user input reflected into HTML
    return f"""
    <h1>Reflected XSS</h1>
    <p>Search term: {q}</p>
    <a href="/">Back</a>
    """


# 3. Stored XSS
@app.route("/comment", methods=["GET", "POST"])
def stored_xss():
    if request.method == "POST":
        comment = request.form.get("comment", "")
        # VULN: stores raw HTML/JS
        stored_comments.append(comment)
        return redirect("/comment")

    comments_html = "".join(f"<li>{c}</li>" for c in stored_comments)
    return f"""
    <h1>Stored XSS</h1>
    <form method="POST">
      <input name="comment" placeholder='<script>alert(1)</script>'>
      <button>Post</button>
    </form>
    <ul>{comments_html}</ul>
    <a href="/">Back</a>
    """


# 4. SSTI
@app.route("/ssti")
def ssti():
    name = request.args.get("name", "")
    # FIX: Pass user input as a variable to the template, letting the templating engine handle escaping.
    template = """
    <h1>SSTI Demo</h1>
    <p>Hello {{ name }}</p>
    <a href="/">Back</a>
    """
    return render_template_string(template, name=name)


# 5. SQL Injection
@app.route("/search")
def sql_injection():
    q = request.args.get("q", "")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()

    # VULN: direct string concatenation into SQL
    sql = "SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'"
    try:
        rows = cur.execute(sql).fetchall()
    except Exception as e:
        rows = [(0, "SQL error", str(e))]
    conn.close()

    result = "".join(f"<li>{r}</li>" for r in rows)
    return f"""
    <h1>SQL Injection</h1>
    <p>Executed query: <code>{sql}</code></p>
    <p>Try: <code>' OR '1'='1</code></p>
    <ul>{result}</ul>
    <a href="/">Back</a>
    """


# 6. IDOR + Sensitive Data Exposure
@app.route("/profile")
def idor_profile():
    user_id = int(request.args.get("id", "1"))

    # VULN: no check that requested profile belongs to logged-in user
    for username, data in USERS.items():
        if data["id"] == user_id:
            return f"""
            <h1>IDOR Profile</h1>
            <p>Username: {username}</p>
            <p>Role: {data["role"]}</p>
            <p>API Key: {data["api_key"]}</p>
            <p>Password: {data["password"]}</p>
            <a href="/">Back</a>
            """

    return "No such user", 404


# 7. Broken Access Control / RBAC bypass
@app.route("/admin")
def admin_panel():
    user = current_user()
    if not user:
        return "Login required", 401

    # VULN: trusts client-side role cookie; change role=admin to bypass
    if user.get("role") != "admin":
        return "Forbidden: admin role required. Hint: role is stored client-side.", 403

    return """
    <h1>Admin Panel</h1>
    <p>RBAC bypass successful.</p>
    <p>Admin-only data: payroll.csv, prod-secrets.env, customer-export.zip</p>
    <a href="/">Back</a>
    """


# 8. Insecure File Upload
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        uploaded = request.files.get("file")
        if not uploaded:
            return "No file uploaded", 400

        # VULN: no extension allowlist, no content validation, path traversal possible via filename
        save_path = os.path.join(UPLOAD_DIR, uploaded.filename)
        uploaded.save(save_path)
        return f"Saved to {save_path}. <a href='/'>Back</a>"

    return """
    <h1>Insecure File Upload</h1>
    <form method="POST" enctype="multipart/form-data">
      <input type="file" name="file">
      <button>Upload</button>
    </form>
    <a href="/">Back</a>
    """


# 9. Security Misconfiguration + Sensitive Data Exposure
@app.route("/debug-info")
def debug_info():
    # VULN: exposes environment and secrets
    return {
        "debug": True,
        "secret_key": app.secret_key,
        "database": DB,
        "environment": dict(os.environ),
        "users": USERS,
    }


# 10. Vulnerable Deserialization
@app.route("/deserialize")
def insecure_deserialize():
    data = request.args.get("data", "")

    # VULN: unpickles user-controlled data
    try:
        raw = base64.b64decode(data)
        obj = pickle.loads(raw)
        return f"<h1>Deserialized Object</h1><pre>{obj}</pre><a href='/'>Back</a>"
    except Exception as e:
        return f"Deserialize error: {e}", 400


# 11. SSRF-style unsafe URL fetch
@app.route("/fetch")
def unsafe_fetch():
    url = request.args.get("url", "")

    # VULN: server fetches arbitrary user-controlled URL
    try:
        r = requests.get(url, timeout=2)
        return f"""
        <h1>Unsafe Fetch</h1>
        <p>Fetched: {url}</p>
        <pre>{r.text[:2000]}</pre>
        <a href="/">Back</a>
        """
    except Exception as e:
        return f"Fetch error: {e}", 400


if __name__ == "__main__":
    init_db()

    # VULN: debug=True exposes Werkzeug debugger in some configs
    app.run(host="127.0.0.1", port=5000, debug=True)
