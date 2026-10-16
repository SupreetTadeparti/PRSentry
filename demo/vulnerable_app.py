"""Deliberately vulnerable Flask app for demoing the reviewer.

Add this file in a PR to see the bot comment on it. DO NOT deploy.
Planted issues (the answer key):
  1. line 23  hardcoded secret                      (CWE-798)
  2. line 30  SQL injection via string formatting   (CWE-89)
  3. line 37  command injection via shell=True      (CWE-78)
  4. line 44  path traversal in file download       (CWE-22)
  5. line 48  admin route with no auth check        (CWE-862)  <- Semgrep can't see this one
  6. line 58  IDOR: any user can read any invoice   (CWE-639)  <- nor this one
  7. line 64  insecure deserialization (pickle)     (CWE-502)
Safe decoy (should NOT be flagged):
  8. line 71  parameterized query scoped to the session user
"""
import os
import pickle
import sqlite3
import subprocess

from flask import Flask, request, send_file, session

app = Flask(__name__)
app.config["SECRET_KEY"] = "prsentry-demo-not-a-real-secret-7f3a9c"
db = sqlite3.connect("app.db", check_same_thread=False)


@app.route("/users")
def search_users():
    name = request.args.get("name", "")
    rows = db.execute(f"SELECT id, email FROM users WHERE name = '{name}'").fetchall()
    return {"users": rows}


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return out.stdout


@app.route("/download")
def download():
    filename = request.args.get("file")
    return send_file(os.path.join("/srv/uploads", filename))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id):
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    return {"deleted": user_id}


@app.route("/invoices/<int:invoice_id>")
def get_invoice(invoice_id):
    if "user_id" not in session:
        return {"error": "login required"}, 401
    row = db.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    return {"invoice": row}


@app.route("/import", methods=["POST"])
def import_settings():
    settings = pickle.loads(request.data)
    return {"ok": True, "keys": list(settings)}


@app.route("/me")
def me():
    uid = session.get("user_id")
    row = db.execute("SELECT id, email FROM users WHERE id = ?", (uid,)).fetchone()
    return {"user": row}
