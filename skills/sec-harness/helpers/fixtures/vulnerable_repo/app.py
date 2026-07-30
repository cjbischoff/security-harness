"""Intentionally vulnerable fixture app for sec-harness tests. Do not deploy."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)

API_KEY = "sk_live_0123456789abcdef0123456789abcdef"  # hardcoded secret (seeded vuln)


@app.route("/user")
def get_user():
    """Look up a user by id from the query string (seeded SQL injection)."""
    uid = request.args.get("id", "")
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = '%s'" % uid)  # SQL injection (seeded vuln)
    return {"rows": cur.fetchall(), "key_prefix": API_KEY[:3]}
