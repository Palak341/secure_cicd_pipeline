# 🔐 Secure CI/CD Pipeline with Secret Detection, Vulnerability Scanning & Alerts

> **Academic + Industry-Level DevSecOps Project**  
> A complete, production-quality demonstration of a security-integrated CI/CD pipeline using GitHub Actions.

---

## 📋 Table of Contents

1. [Project Overview](#-project-overview)
2. [Architecture Diagram](#-architecture-diagram)
3. [Project Structure](#-project-structure)
4. [Security Tools Used](#-security-tools-used)
5. [Setup Instructions](#-setup-instructions)
6. [GitHub Secrets Required](#-github-secrets-required)
7. [Running the Pipeline](#-running-the-pipeline)
8. [Understanding Failures and Fixes](#-understanding-failures-and-fixes)
9. [Viewing Reports and Dashboard](#-viewing-reports-and-dashboard)
10. [Email Alerts](#-email-alerts)
11. [Local Development](#-local-development)
12. [Pipeline Flow](#-pipeline-flow)
13. [Remediation Guide](#-remediation-guide)

---

## 🎯 Project Overview

This project demonstrates a **Shift-Left Security** approach by embedding security scanning directly into the CI/CD pipeline. The pipeline is designed to:

- **FAIL initially** because the sample app contains intentional vulnerabilities
- **PASS after remediation** once all security issues are fixed
- **Alert** the team via email whenever the pipeline fails
- **Report** all findings in structured JSON + a visual HTML dashboard

### What is intentionally vulnerable:
| Issue | Location | Scanner that catches it |
|-------|----------|------------------------|
| Hardcoded AWS key, GitHub token, DB password | `app/app.py` | Gitleaks |
| Outdated Flask 0.12.2 (CVE-2018-1000656) | `app/requirements.txt` | pip-audit |
| Outdated Jinja2 2.10 (CVE-2019-10906) | `app/requirements.txt` | pip-audit |
| Outdated requests 2.18.4 (CVE-2018-18074) | `app/requirements.txt` | pip-audit |
| SQL Injection via string formatting | `app/app.py` | Bandit |
| Debug mode enabled in production | `app/app.py` | Bandit |
| Container CVEs (from vulnerable base packages) | `Dockerfile` | Trivy |

---

## 🏗️ Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        GitHub Repository                         │
│                          git push / PR                           │
└──────────────────────────────┬──────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     GitHub Actions Pipeline                      │
│                                                                  │
│  ┌─────────────┐   ┌─────────────┐   ┌──────────────────────┐  │
│  │  🔑 Secret  │   │ 📦 Dep Scan │   │  🧪 Static Analysis  │  │
│  │  Detection  │   │ (pip-audit) │   │      (Bandit)        │  │
│  │ (Gitleaks)  │   │             │   │                      │  │
│  └──────┬──────┘   └──────┬──────┘   └──────────┬───────────┘  │
│         │                 │                      │               │
│         └────────────┬────┘──────────────────────┘               │
│                      │                                           │
│                      ▼                                           │
│              ┌───────────────┐                                   │
│              │ 🐳 Build Image│                                   │
│              │   (Docker)    │                                   │
│              └───────┬───────┘                                   │
│                      │                                           │
│                      ▼                                           │
│              ┌───────────────┐                                   │
│              │  🛡️ Container │                                   │
│              │  Scan (Trivy) │                                   │
│              └───────┬───────┘                                   │
│                      │                                           │
│                      ▼                                           │
│  ┌───────────────────────────────────┐                          │
│  │  📊 Generate HTML Dashboard       │  ← Always runs           │
│  │  📁 Upload Artifacts              │                          │
│  └───────────────────────────────────┘                          │
│                      │                                           │
│                      ▼                                           │
│              ┌───────────────┐                                   │
│              │ 🚦 Security   │                                   │
│              │    Gate       │                                   │
│              └───────┬───────┘                                   │
│                      │                                           │
│            ┌────Pass─┴─Fail────┐                                 │
│            ▼                   ▼                                  │
│      ✅ Deploy             📧 Email Alert                        │
│      (next stage)          (SMTP/Gmail)                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
secure-cicd-pipeline/
├── app/
│   ├── app.py                  # Flask app (intentionally vulnerable)
│   └── requirements.txt        # Outdated dependencies (intentional)
│
├── .github/
│   └── workflows/
│       └── cicd.yml            # Full GitHub Actions pipeline
│
├── scripts/
│   ├── generate_dashboard.py   # Parses JSON reports → HTML dashboard
│   └── generate_email.py       # Generates HTML email body for alerts
│
├── reports/                    # Generated by CI (gitignored)
│   ├── gitleaks-report.json
│   ├── dependency-report.json
│   ├── bandit-report.json
│   └── trivy-report.json
│
├── dashboard/
│   └── report.html             # Generated by CI (gitignored)
│
├── Dockerfile                  # Container definition
├── .gitleaks.toml              # Gitleaks custom rules & allowlist
├── trivy.yaml                  # Trivy scan configuration
├── bandit.yaml                 # Bandit SAST configuration
├── .gitignore
└── README.md
```

---

## 🛡️ Security Tools Used

| Tool | Purpose | Report Format | Fails On |
|------|---------|---------------|----------|
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret/credential detection in code | JSON | Any secret found |
| [pip-audit](https://github.com/pypa/pip-audit) | Python dependency vulnerability scan | JSON | Any known CVE |
| [Bandit](https://github.com/PyCQA/bandit) | Python SAST (static analysis) | JSON | Medium+ severity issues |
| [Trivy](https://github.com/aquasecurity/trivy) | Container image vulnerability scan | JSON | CRITICAL/HIGH CVEs |

---

## ⚙️ Setup Instructions

### 1. Fork / Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/secure-cicd-pipeline.git
cd secure-cicd-pipeline
```

### 2. Add GitHub Secrets

Go to your GitHub repository → **Settings** → **Secrets and variables** → **Actions** → **New repository secret**

Add the following secrets (see [GitHub Secrets Required](#-github-secrets-required) section):

| Secret Name | Value |
|-------------|-------|
| `SMTP_USERNAME` | Your Gmail address |
| `SMTP_PASSWORD` | Gmail App Password (not your login password) |
| `ALERT_EMAIL_TO` | Recipient email address for alerts |

### 3. Enable GitHub Actions

Make sure GitHub Actions is enabled in your repository settings:  
**Settings** → **Actions** → **General** → **Allow all actions**

### 4. Push to Trigger Pipeline

```bash
git add .
git commit -m "feat: initial commit — intentionally vulnerable demo"
git push origin main
```

The pipeline will start automatically and **FAIL** (by design).

---

## 🔑 GitHub Secrets Required

### Setting up Gmail SMTP

1. Enable 2-Factor Authentication on your Google account
2. Go to: [https://myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
3. Create a new App Password for "Mail"
4. Use that 16-character password as `SMTP_PASSWORD`

```
SMTP_USERNAME  = your.email@gmail.com
SMTP_PASSWORD  = xxxx xxxx xxxx xxxx   ← 16-char App Password
ALERT_EMAIL_TO = recipient@example.com
```

> ⚠️ **Never commit credentials to the repository.** Always use GitHub Secrets.

---

## 🚀 Running the Pipeline

### Automatic (recommended)
The pipeline runs automatically on:
- Every `git push` to `main`, `develop`, or `feature/**` branches
- Every Pull Request targeting `main`
- Manual trigger from **Actions** tab → **Run workflow**

### Manual Trigger
1. Go to **Actions** tab in your GitHub repository
2. Select **Secure CI/CD Pipeline**
3. Click **Run workflow** → select branch → **Run workflow**

---

## ⚠️ Understanding Failures and Fixes

### Phase 1: Pipeline FAILS (Initial State)

When you first push, the pipeline will fail because:

**Gitleaks** detects:
```python
# app/app.py
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  ← FAIL
DATABASE_PASSWORD = "SuperSecret123!"                                    ← FAIL
API_TOKEN = "ghp_FakeGitHubTokenForDemoOnly1234567890"                  ← FAIL
```

**pip-audit** detects:
```
Flask==0.12.2      → CVE-2018-1000656
Jinja2==2.10       → CVE-2019-10906
requests==2.18.4   → CVE-2018-18074
PyYAML==3.13       → CVE-2017-18342
```

**Bandit** detects:
```python
query = "SELECT * FROM users WHERE username = '" + username + "'"  ← SQL injection
app.run(..., debug=True)                                            ← Debug mode
```

---

### Phase 2: Fix Issues → Pipeline PASSES

#### Fix 1 — Remove Hardcoded Secrets

Replace `app/app.py` secrets with environment variables:

```python
# BEFORE (vulnerable):
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# AFTER (secure):
import os
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
if not AWS_SECRET_ACCESS_KEY:
    raise ValueError("AWS_SECRET_ACCESS_KEY environment variable not set")
```

#### Fix 2 — Upgrade Dependencies

Update `app/requirements.txt`:

```
# BEFORE (vulnerable):
Flask==0.12.2
Jinja2==2.10
requests==2.18.4
PyYAML==3.13

# AFTER (secure):
Flask>=3.0.0
Jinja2>=3.1.4
requests>=2.32.0
PyYAML>=6.0.1
Werkzeug>=3.0.1
```

#### Fix 3 — Fix SQL Injection

```python
# BEFORE (vulnerable):
query = "SELECT * FROM users WHERE username = '" + username + "'"
cursor.execute(query)

# AFTER (secure — parameterised query):
query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```

#### Fix 4 — Disable Debug Mode

```python
# BEFORE:
app.run(host="0.0.0.0", port=5000, debug=True)

# AFTER:
debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
app.run(host="0.0.0.0", port=5000, debug=debug_mode)
```

After applying all fixes:
```bash
git add .
git commit -m "fix: remove hardcoded secrets, upgrade deps, fix SQL injection"
git push origin main
```

The pipeline should now **PASS** ✅

---

## 📊 Viewing Reports and Dashboard

### GitHub Actions Artifacts

After each pipeline run:

1. Go to **Actions** tab
2. Click on the pipeline run
3. Scroll to **Artifacts** section
4. Download:
   - `gitleaks-report` — Secret detection JSON
   - `dependency-report` — pip-audit JSON
   - `bandit-report` — Bandit SAST JSON
   - `trivy-report` — Trivy container JSON
   - `security-dashboard` — HTML visual report

### Viewing the Dashboard

```bash
# Download security-dashboard artifact
# Unzip it
# Open in browser:
open dashboard/report.html
# or:
python3 -m http.server 8080  # then visit http://localhost:8080/dashboard/report.html
```

### Generating Dashboard Locally

```bash
pip install pip-audit bandit
pip-audit --requirement app/requirements.txt --format json --output reports/dependency-report.json || true
bandit -r app/ -f json -o reports/bandit-report.json || true
python3 scripts/generate_dashboard.py \
    --reports-dir reports \
    --output dashboard/report.html \
    --commit $(git rev-parse HEAD) \
    --branch $(git branch --show-current) \
    --run-id 0
open dashboard/report.html
```

---

## 📧 Email Alerts

Email alerts are sent **only when the pipeline fails**. The email includes:
- Repository name and branch
- Commit SHA
- Per-scanner pass/fail status with issue counts
- List of specific failure reasons
- Recommended remediation actions
- Direct link to the GitHub Actions run
- JSON reports as email attachments

### Email Configuration

The pipeline uses [dawidd6/action-send-mail](https://github.com/dawidd6/action-send-mail) with:
- **Server**: `smtp.gmail.com:465` (SSL)
- **Auth**: GitHub Secrets (`SMTP_USERNAME` + `SMTP_PASSWORD`)
- **Format**: HTML email with JSON attachments

---

## 💻 Local Development

### Run the Flask App Locally

```bash
cd app
pip install -r requirements.txt
python app.py
# App runs at http://localhost:5000
```

### Run Security Scans Locally

```bash
# Install tools
pip install pip-audit bandit

# Secret detection
brew install gitleaks  # macOS
gitleaks detect --source . --report-format json --report-path reports/gitleaks-report.json

# Dependency scan
pip-audit --requirement app/requirements.txt --format json --output reports/dependency-report.json

# SAST
bandit -r app/ -f json -o reports/bandit-report.json

# Container scan (requires Docker + Trivy)
brew install trivy  # macOS
docker build -t secure-cicd-demo:local .
trivy image --format json --output reports/trivy-report.json secure-cicd-demo:local
```

### Build Docker Image Locally

```bash
docker build -t secure-cicd-demo:local .
docker run -p 5000:5000 secure-cicd-demo:local
```

---

## 🔄 Pipeline Flow

```
git push
    │
    ├──► [Parallel] Secret Detection (Gitleaks)
    │         └── Fail if secrets found
    │
    ├──► [Parallel] Dependency Scan (pip-audit)
    │         └── Fail if CVEs found
    │
    ├──► [Parallel] Static Analysis (Bandit)
    │         └── Fail if SAST issues found (medium+)
    │
    └──► [After Secret Detection] Build Docker Image
              └──► Container Scan (Trivy)
                        └── Fail if CRITICAL/HIGH CVEs
    
    [All scans complete — always runs]
    └──► Generate HTML Dashboard
              └──► Upload all artifacts (30-day retention)

    [Security Gate — evaluates all results]
    ├── PASS → Ready for deployment stage
    └── FAIL → Send email alert → Block deployment
```

---

## 🔧 Remediation Guide

| Finding | Risk | Fix |
|---------|------|-----|
| Hardcoded AWS key | **CRITICAL** | Use `os.environ.get()` + GitHub Secret |
| Hardcoded DB password | **CRITICAL** | Use `os.environ.get()` + GitHub Secret |
| Hardcoded API token | **HIGH** | Use `os.environ.get()` + GitHub Secret |
| Flask 0.12.2 CVE | **HIGH** | Upgrade to `Flask>=3.0.0` |
| Jinja2 2.10 SSTI | **HIGH** | Upgrade to `Jinja2>=3.1.4` |
| SQL Injection | **HIGH** | Use parameterised queries |
| Debug mode on | **MEDIUM** | Use `FLASK_DEBUG` env variable |
| PyYAML RCE | **CRITICAL** | Upgrade to `PyYAML>=6.0.1` |

---

## 📚 Learning Outcomes

By working through this project you will understand:

1. **Shift-Left Security** — catching vulnerabilities early in the development cycle
2. **Secret Management** — why credentials must never be in source code
3. **Dependency Management** — keeping packages up-to-date with known CVEs in mind
4. **SAST** — automated detection of code-level security bugs
5. **Container Security** — scanning images before deployment
6. **Security Gates** — automatically blocking insecure deployments
7. **Alerting** — notifying teams of security failures in real time
8. **Reporting** — structured reports for audit trails and compliance

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m 'feat: add your feature'`
4. Push: `git push origin feature/your-feature`
5. Open a Pull Request

---

## 📄 License

MIT License — free to use for educational and commercial purposes.

---

*Built as an academic + industry-level DevSecOps demonstration project.*