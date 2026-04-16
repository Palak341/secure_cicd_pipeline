#!/usr/bin/env bash
# scripts/run_local_scans.sh
# ============================================================
# Local Security Scan Runner
# ============================================================
# Mirrors the GitHub Actions pipeline locally so you can
# catch issues before pushing.
#
# Usage:
#   chmod +x scripts/run_local_scans.sh
#   ./scripts/run_local_scans.sh
#
# Prerequisites:
#   - Python 3.8+
#   - Docker (for container scan)
#   - gitleaks (brew install gitleaks / apt install gitleaks)
#   - trivy   (brew install trivy   / see https://trivy.dev)
# ============================================================

set -euo pipefail

# ── Colours ──────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Config ────────────────────────────────────────────────────
REPORTS_DIR="reports"
DASHBOARD_OUT="dashboard/report.html"
IMAGE_NAME="secure-cicd-demo"
IMAGE_TAG="local-scan"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Helpers ───────────────────────────────────────────────────
log_header() { echo -e "\n${CYAN}${BOLD}══════════════════════════════════════${RESET}"; echo -e "${CYAN}${BOLD}  $1${RESET}"; echo -e "${CYAN}${BOLD}══════════════════════════════════════${RESET}"; }
log_pass()   { echo -e "  ${GREEN}✅ PASS${RESET} — $1"; }
log_fail()   { echo -e "  ${RED}❌ FAIL${RESET} — $1"; }
log_warn()   { echo -e "  ${YELLOW}⚠️  WARN${RESET} — $1"; }
log_info()   { echo -e "  ${CYAN}ℹ️  ${RESET}$1"; }

check_tool() {
  if ! command -v "$1" &>/dev/null; then
    log_warn "$1 not found — skipping that scan. Install: $2"
    return 1
  fi
  return 0
}

# ── Setup ─────────────────────────────────────────────────────
cd "$PROJECT_ROOT"
mkdir -p "$REPORTS_DIR" dashboard

FAILED_SCANS=()
PASSED_SCANS=()
SKIPPED_SCANS=()

echo -e "\n${BOLD}🔐 Secure CI/CD Pipeline — Local Scan Runner${RESET}"
echo -e "   Project: $(pwd)"
echo -e "   Reports: $REPORTS_DIR/"
echo -e "   Time:    $(date '+%Y-%m-%d %H:%M:%S')"

# ────────────────────────────────────────────────────────────
# STEP 1 — Secret Detection (Gitleaks)
# ────────────────────────────────────────────────────────────
log_header "1/5  Secret Detection — Gitleaks"

if check_tool "gitleaks" "brew install gitleaks"; then
  if gitleaks detect \
      --source . \
      --report-format json \
      --report-path "$REPORTS_DIR/gitleaks-report.json" \
      --exit-code 1 \
      --redact \
      2>&1; then
    log_pass "No secrets detected"
    PASSED_SCANS+=("Gitleaks")
  else
    log_fail "Secrets found! See $REPORTS_DIR/gitleaks-report.json"
    FAILED_SCANS+=("Gitleaks")
  fi
else
  SKIPPED_SCANS+=("Gitleaks")
fi

# ────────────────────────────────────────────────────────────
# STEP 2 — Dependency Scan (pip-audit)
# ────────────────────────────────────────────────────────────
log_header "2/5  Dependency Vulnerability Scan — pip-audit"

log_info "Installing pip-audit..."
pip install --quiet pip-audit 2>/dev/null || true

if command -v pip-audit &>/dev/null; then
  if pip-audit \
      --requirement app/requirements.txt \
      --format json \
      --output "$REPORTS_DIR/dependency-report.json" \
      --progress-spinner off \
      2>&1; then
    log_pass "No vulnerable dependencies"
    PASSED_SCANS+=("pip-audit")
  else
    VULN_COUNT=$(python3 -c "
import json
try:
    d = json.load(open('$REPORTS_DIR/dependency-report.json'))
    print(len(d.get('vulnerabilities', [])))
except: print('?')
")
    log_fail "$VULN_COUNT vulnerable package(s). See $REPORTS_DIR/dependency-report.json"
    FAILED_SCANS+=("pip-audit")
  fi
  # Human-readable output
  echo ""
  pip-audit --requirement app/requirements.txt --progress-spinner off 2>&1 || true
else
  log_warn "pip-audit install failed — skipping"
  SKIPPED_SCANS+=("pip-audit")
fi

# ────────────────────────────────────────────────────────────
# STEP 3 — Static Analysis (Bandit)
# ────────────────────────────────────────────────────────────
log_header "3/5  Static Analysis — Bandit (SAST)"

log_info "Installing bandit..."
pip install --quiet bandit 2>/dev/null || true

if command -v bandit &>/dev/null; then
  if bandit \
      -r app/ \
      -f json \
      -o "$REPORTS_DIR/bandit-report.json" \
      --severity-level medium \
      --confidence-level medium \
      2>&1; then
    log_pass "No SAST issues found"
    PASSED_SCANS+=("Bandit")
  else
    ISSUE_COUNT=$(python3 -c "
import json
try:
    d = json.load(open('$REPORTS_DIR/bandit-report.json'))
    print(len(d.get('results', [])))
except: print('?')
")
    log_fail "$ISSUE_COUNT issue(s). See $REPORTS_DIR/bandit-report.json"
    FAILED_SCANS+=("Bandit")
  fi
  # Human-readable output
  echo ""
  bandit -r app/ --severity-level medium 2>&1 || true
else
  log_warn "bandit install failed — skipping"
  SKIPPED_SCANS+=("Bandit")
fi

# ────────────────────────────────────────────────────────────
# STEP 4 — Build Docker Image
# ────────────────────────────────────────────────────────────
log_header "4/5  Build & Container Scan — Docker + Trivy"

if check_tool "docker" "https://docs.docker.com/get-docker/"; then
  log_info "Building Docker image $IMAGE_NAME:$IMAGE_TAG ..."
  if docker build -t "$IMAGE_NAME:$IMAGE_TAG" . --quiet 2>&1; then
    log_pass "Docker image built successfully"

    # ── Trivy Container Scan ──────────────────────────────
    if check_tool "trivy" "brew install trivy"; then
      log_info "Running Trivy container scan..."
      if trivy image \
          --format json \
          --output "$REPORTS_DIR/trivy-report.json" \
          --severity CRITICAL,HIGH \
          --exit-code 1 \
          --ignore-unfixed \
          "$IMAGE_NAME:$IMAGE_TAG" \
          2>&1; then
        log_pass "No CRITICAL/HIGH container vulnerabilities"
        PASSED_SCANS+=("Trivy")
      else
        TRIVY_COUNT=$(python3 -c "
import json
try:
    d = json.load(open('$REPORTS_DIR/trivy-report.json'))
    total = sum(len(r.get('Vulnerabilities') or []) for r in d.get('Results', []))
    print(total)
except: print('?')
")
        log_fail "$TRIVY_COUNT CVE(s). See $REPORTS_DIR/trivy-report.json"
        FAILED_SCANS+=("Trivy")
      fi
      # Human-readable table output
      echo ""
      trivy image \
        --format table \
        --severity CRITICAL,HIGH,MEDIUM \
        --ignore-unfixed \
        --exit-code 0 \
        "$IMAGE_NAME:$IMAGE_TAG" 2>&1 || true
    else
      SKIPPED_SCANS+=("Trivy")
    fi
  else
    log_fail "Docker build failed"
    FAILED_SCANS+=("Docker Build")
    SKIPPED_SCANS+=("Trivy")
  fi
else
  SKIPPED_SCANS+=("Docker Build" "Trivy")
fi

# ────────────────────────────────────────────────────────────
# STEP 5 — Generate HTML Dashboard
# ────────────────────────────────────────────────────────────
log_header "5/5  Generating HTML Dashboard"

python3 scripts/generate_dashboard.py \
  --reports-dir "$REPORTS_DIR" \
  --output "$DASHBOARD_OUT" \
  --commit "$(git rev-parse --short HEAD 2>/dev/null || echo 'local')" \
  --branch "$(git branch --show-current 2>/dev/null || echo 'local')" \
  --run-id "0-local"

log_pass "Dashboard written to $DASHBOARD_OUT"

# Try to open in browser (macOS/Linux)
if command -v open &>/dev/null; then
  open "$DASHBOARD_OUT" 2>/dev/null || true
elif command -v xdg-open &>/dev/null; then
  xdg-open "$DASHBOARD_OUT" 2>/dev/null || true
fi

# ────────────────────────────────────────────────────────────
# SUMMARY
# ────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Scan Summary${RESET}"
echo -e "${BOLD}════════════════════════════════════════${RESET}"

for s in "${PASSED_SCANS[@]:-}";  do echo -e "  ${GREEN}✅ PASS${RESET}  — $s"; done
for s in "${FAILED_SCANS[@]:-}";  do echo -e "  ${RED}❌ FAIL${RESET}  — $s"; done
for s in "${SKIPPED_SCANS[@]:-}"; do echo -e "  ${YELLOW}⏭  SKIP${RESET}  — $s"; done

echo ""
if [ ${#FAILED_SCANS[@]} -gt 0 ]; then
  echo -e "  ${RED}${BOLD}Overall: FAILED${RESET} (${#FAILED_SCANS[@]} scanner(s) found issues)"
  echo -e "  Fix the issues above, then re-run this script."
  echo ""
  exit 1
else
  echo -e "  ${GREEN}${BOLD}Overall: PASSED${RESET} — all scans clean 🎉"
  echo ""
  exit 0
fi