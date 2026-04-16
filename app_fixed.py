"""
Secure CI/CD Pipeline Demo — FIXED Flask Application
=====================================================
This is the REMEDIATED version of app.py.
Apply these changes after the pipeline fails to make it PASS.

Changes from the vulnerable version:
  1. ✅ No hardcoded secrets — all credentials via environment variables
  2. ✅ SQL injection fixed — parameterised queries used
  3. ✅ Debug mode controlled via environment variable
  4. ✅ Input validation added
  5. ✅ Proper error handling (no stack traces exposed)
  6. ✅ Security headers added
"""

import logging
import os
import sqlite3

from flask import Flask, jsonify, request

# ── Logging setup ────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ============================================================
# FIX #1 — Load credentials from environment variables ONLY
# Never hardcode secrets in source code.
# Set these via GitHub Secrets → injected as env vars at runtime.
# ============================================================
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
DATABASE_PASSWORD     = os.environ.get("DATABASE_PASSWORD")
API_TOKEN             = os.environ.get("API_TOKEN")

# Warn at startup if required secrets are missing (don't crash — demo friendliness)
for var in ["AWS_SECRET_ACCESS_KEY", "DATABASE_PASSWORD", "API_TOKEN"]:
    if not os.environ.get(var):
        logger.warning("Environment variable %s is not set", var)


# ============================================================
# FIX #2 — Parameterised SQL query (no string concatenation)
# ============================================================
def get_user(username: str) -> list:
    """Look up a user by username using a safe parameterised query."""
    # Input validation: only allow alphanumeric usernames
    if not username.isalnum():
        logger.warning("Invalid username format attempted: %r", username)
        return []

    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()

    # Create demo table
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT)"
    )
    cursor.execute("INSERT INTO users (username) VALUES (?)", ("alice",))
    cursor.execute("INSERT INTO users (username) VALUES (?)", ("bob",))
    conn.commit()

    # SAFE: parameterised query — user input never interpolated into SQL string
    cursor.execute("SELECT id, username FROM users WHERE username = ?", (username,))
    rows = cursor.fetchall()
    conn.close()
    return rows


# ============================================================
# FIX #3 — Security response headers
# ============================================================
@app.after_request
def add_security_headers(response):
    """Add OWASP-recommended security headers to every response."""
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"]           = "no-referrer"
    response.headers["Cache-Control"]             = "no-store"
    return response


@app.route("/")
def index():
    """Home endpoint."""
    return jsonify({
        "status": "running",
        "app":    "Secure CI/CD Demo — FIXED version",
        "note":   "All vulnerabilities remediated.",
    })


@app.route("/user")
def user():
    """Safe user lookup endpoint with input validation."""
    username = request.args.get("name", "")
    if not username:
        return jsonify({"error": "name parameter is required"}), 400

    results = get_user(username)
    # Return only safe fields — never expose raw DB objects
    return jsonify({"results": [{"id": r[0], "username": r[1]} for r in results]})


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({"health": "ok"}), 200


# ============================================================
# FIX #4 — Debug mode via environment variable
# ============================================================
if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    port       = int(os.environ.get("PORT", "5000"))
    logger.info("Starting app | debug=%s | port=%d", debug_mode, port)
    app.run(host="0.0.0.0", port=port, debug=debug_mode)