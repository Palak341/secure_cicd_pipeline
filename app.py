"""
Secure CI/CD Pipeline Demo - Vulnerable Flask Application
==========================================================
PURPOSE: This app is INTENTIONALLY vulnerable for demonstration.
It contains:
  1. A hardcoded secret (triggers Gitleaks)
  2. An outdated dependency (triggers OWASP Dependency-Check)
  3. SQL injection (triggers static analysis)
  4. Debug mode enabled (bad practice)
 
After the pipeline FAILS, you fix these issues and the pipeline PASSES.
"""
 
from flask import Flask, request, jsonify
import sqlite3
import os
 
app = Flask(__name__)
 
# ============================================================
# INTENTIONAL VULNERABILITY #1 — Hardcoded Secret
# Gitleaks will detect this AWS key pattern and fail the build.
# FIX: Move to environment variable / GitHub Secret.
# ============================================================
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_PASSWORD = "SuperSecret123!"
API_TOKEN = "ghp_FakeGitHubTokenForDemoOnly1234567890"
 
# ============================================================
# INTENTIONAL VULNERABILITY #2 — Insecure DB query (SQL Injection)
# Bandit / SonarQube will flag this.
# FIX: Use parameterised queries.
# ============================================================
def get_user(username):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # BAD: string formatting opens SQL injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()
 
 
@app.route("/")
def index():
    """Home endpoint — returns app status."""
    return jsonify({
        "status": "running",
        "app": "Secure CI/CD Demo",
        "warning": "This app is intentionally vulnerable for demo purposes."
    })
 
 
@app.route("/user")
def user():
    """Vulnerable user lookup endpoint."""
    username = request.args.get("name", "guest")
    # SQL injection possible here
    results = get_user(username)
    return jsonify({"results": results})
 
 
@app.route("/health")
def health():
    """Health check endpoint used by Docker/k8s."""
    return jsonify({"health": "ok"}), 200
 
 
if __name__ == "__main__":
    # INTENTIONAL VULNERABILITY #3 — Debug mode exposes stack traces
    # FIX: Set debug=False in production; use FLASK_ENV env var.
    app.run(host="0.0.0.0", port=5000, debug=True)
 