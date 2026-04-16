# Makefile
# ============================================================
# Convenient shortcuts for local development.
# Run: make <target>
# ============================================================

.PHONY: help install run test scan scan-secrets scan-deps scan-sast \
        build scan-container dashboard clean fix-app

# ── Default target ────────────────────────────────────────────
help:
	@echo ""
	@echo "  🔐 Secure CI/CD Pipeline — Make Targets"
	@echo "  ─────────────────────────────────────────"
	@echo "  make install          Install Python dependencies"
	@echo "  make run              Run the Flask app locally"
	@echo "  make test             Run unit tests"
	@echo "  make scan             Run ALL security scans (+ dashboard)"
	@echo "  make scan-secrets     Run Gitleaks only"
	@echo "  make scan-deps        Run pip-audit only"
	@echo "  make scan-sast        Run Bandit only"
	@echo "  make build            Build Docker image"
	@echo "  make scan-container   Run Trivy on Docker image"
	@echo "  make dashboard        Generate HTML dashboard"
	@echo "  make fix-app          Apply fixes (copy fixed files over originals)"
	@echo "  make clean            Remove generated reports and cache"
	@echo ""

# ── Setup ─────────────────────────────────────────────────────
install:
	@echo "📦 Installing dependencies..."
	pip install -r app/requirements.txt
	pip install pip-audit bandit pytest

# ── Run App ───────────────────────────────────────────────────
run:
	@echo "🚀 Starting Flask app on http://localhost:5000"
	cd app && python app.py

# ── Tests ─────────────────────────────────────────────────────
test:
	@echo "🧪 Running unit tests..."
	pytest tests/ -v --tb=short

# ── Full Scan ─────────────────────────────────────────────────
scan:
	@echo "🔐 Running all security scans..."
	@bash scripts/run_local_scans.sh

# ── Individual Scans ──────────────────────────────────────────
scan-secrets:
	@echo "🔑 Running Gitleaks secret detection..."
	@mkdir -p reports
	gitleaks detect \
		--source . \
		--report-format json \
		--report-path reports/gitleaks-report.json \
		--exit-code 1 \
		--redact \
	&& echo "✅ No secrets found" \
	|| echo "❌ Secrets detected — see reports/gitleaks-report.json"

scan-deps:
	@echo "📦 Running pip-audit dependency scan..."
	@mkdir -p reports
	pip-audit \
		--requirement app/requirements.txt \
		--format json \
		--output reports/dependency-report.json \
		--progress-spinner off \
	&& echo "✅ No vulnerable dependencies" \
	|| echo "❌ Vulnerabilities found — see reports/dependency-report.json"

scan-sast:
	@echo "🧪 Running Bandit SAST..."
	@mkdir -p reports
	bandit \
		-r app/ \
		-f json \
		-o reports/bandit-report.json \
		--severity-level medium \
	&& echo "✅ No SAST issues" \
	|| echo "❌ Issues found — see reports/bandit-report.json"

# ── Docker ────────────────────────────────────────────────────
build:
	@echo "🐳 Building Docker image..."
	docker build -t secure-cicd-demo:local .

scan-container: build
	@echo "🛡️  Running Trivy container scan..."
	@mkdir -p reports
	trivy image \
		--format json \
		--output reports/trivy-report.json \
		--severity CRITICAL,HIGH \
		--ignore-unfixed \
		--exit-code 1 \
		secure-cicd-demo:local \
	&& echo "✅ No CRITICAL/HIGH CVEs" \
	|| echo "❌ CVEs found — see reports/trivy-report.json"

# ── Dashboard ─────────────────────────────────────────────────
dashboard:
	@echo "📊 Generating security dashboard..."
	@mkdir -p dashboard
	python3 scripts/generate_dashboard.py \
		--reports-dir reports \
		--output dashboard/report.html \
		--commit "$$(git rev-parse --short HEAD 2>/dev/null || echo local)" \
		--branch "$$(git branch --show-current 2>/dev/null || echo local)" \
		--run-id "0"
	@echo "✅ Dashboard: dashboard/report.html"
	@command -v open >/dev/null && open dashboard/report.html || true

# ── Apply Fixes ───────────────────────────────────────────────
fix-app:
	@echo "🔧 Applying security fixes..."
	cp app/app_fixed.py app/app.py
	cp app/requirements_fixed.txt app/requirements.txt
	@echo "✅ Fixed app.py and requirements.txt"
	@echo "   Now run: git add . && git commit -m 'fix: remediate security issues'"

# ── Clean ─────────────────────────────────────────────────────
clean:
	@echo "🧹 Cleaning generated files..."
	rm -f reports/*.json reports/*.txt reports/*.html
	rm -f dashboard/report.html
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	@echo "✅ Clean complete"