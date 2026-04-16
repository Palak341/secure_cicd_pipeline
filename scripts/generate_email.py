#!/usr/bin/env python3
"""
generate_email.py
=================
Generates an HTML email body for the security pipeline failure alert.
Called by the GitHub Actions notify-on-failure job.
 
Usage:
    python3 scripts/generate_email.py \
        --reports-dir reports \
        --commit abc1234 \
        --branch main \
        --run-id 123456 \
        --repo myorg/myrepo \
        --output /tmp/email_body.html
"""
 
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
 
 
def count_findings(path: Path, key: str = None) -> int:
    """Safely count findings in a JSON report."""
    if not path.exists():
        return -1  # -1 = not run
    try:
        data = json.loads(path.read_text())
        if data is None:
            return 0
        if key:
            return len(data.get(key, []))
        if isinstance(data, list):
            return len(data)
        # pip-audit format
        if "vulnerabilities" in data:
            return len(data["vulnerabilities"])
        # Bandit format
        if "results" in data:
            return len(data["results"])
        # Trivy format
        if "Results" in data:
            total = sum(len(r.get("Vulnerabilities") or []) for r in data["Results"])
            return total
        return 0
    except Exception:
        return -1
 
 
def status_row(label: str, count: int, icon: str) -> str:
    """Generate a status row for the email table."""
    if count < 0:
        status_text = "Not run"
        color = "#6b7280"
        bg = "#1f2937"
    elif count == 0:
        status_text = "✅ PASS — No issues"
        color = "#22c55e"
        bg = "#052e16"
    else:
        status_text = f"❌ FAIL — {count} issue(s)"
        color = "#ef4444"
        bg = "#450a0a"
 
    return f"""
    <tr>
      <td style="padding:12px 16px; border-bottom:1px solid #374151; font-weight:600;">
        {icon} {label}
      </td>
      <td style="padding:12px 16px; border-bottom:1px solid #374151; background:{bg}; color:{color}; font-weight:700;">
        {status_text}
      </td>
    </tr>"""
 
 
def generate_email(
    reports_dir: Path,
    commit: str,
    branch: str,
    run_id: str,
    repo: str,
) -> str:
    """Generate the full HTML email body."""
 
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    run_url = f"https://github.com/{repo}/actions/runs/{run_id}"
 
    # Count findings from each report
    gl_count  = count_findings(reports_dir / "gitleaks-report.json")
    dep_count = count_findings(reports_dir / "dependency-report.json")
    ban_count = count_findings(reports_dir / "bandit-report.json")
    tri_count = count_findings(reports_dir / "trivy-report.json")
 
    total = sum(c for c in [gl_count, dep_count, ban_count, tri_count] if c > 0)
 
    # Determine primary failure reasons
    failures = []
    if gl_count  > 0: failures.append(f"{gl_count} hardcoded secret(s) detected by Gitleaks")
    if dep_count > 0: failures.append(f"{dep_count} vulnerable dependency/ies found by pip-audit")
    if ban_count > 0: failures.append(f"{ban_count} SAST issue(s) found by Bandit")
    if tri_count > 0: failures.append(f"{tri_count} container CVE(s) found by Trivy")
 
    failure_list = "\n".join(
        f'<li style="margin-bottom:6px;">{f}</li>' for f in failures
    ) or "<li>See scan logs for details</li>"
 
    rows = (
        status_row("Secret Detection (Gitleaks)", gl_count, "🔑")
        + status_row("Dependency Scan (pip-audit)", dep_count, "📦")
        + status_row("Static Analysis (Bandit)", ban_count, "🧪")
        + status_row("Container Scan (Trivy)", tri_count, "🐳")
    )
 
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Pipeline Failed</title>
</head>
<body style="margin:0;padding:0;background:#0b0f1a;font-family:'Segoe UI',Arial,sans-serif;color:#e2e8f0;">
 
  <!-- Wrapper -->
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0b0f1a;padding:32px 16px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0"
               style="background:#111827;border-radius:12px;overflow:hidden;border:1px solid #374151;max-width:600px;">
 
          <!-- Header Banner -->
          <tr>
            <td style="background:linear-gradient(135deg,#1e3a5f,#0f172a);padding:28px 32px;border-bottom:1px solid #374151;">
              <div style="font-size:2rem;margin-bottom:8px;">🚨</div>
              <h1 style="margin:0;font-size:1.4rem;font-weight:700;color:#ef4444;letter-spacing:-0.02em;">
                Security Pipeline FAILED
              </h1>
              <p style="margin:6px 0 0;color:#94a3b8;font-size:0.88rem;">
                Automated security scans detected {total} issue(s) that must be resolved.
              </p>
            </td>
          </tr>
 
          <!-- Pipeline Info -->
          <tr>
            <td style="padding:24px 32px;border-bottom:1px solid #1f2937;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding:4px 0;color:#94a3b8;font-size:0.82rem;width:120px;">Repository</td>
                  <td style="padding:4px 0;font-size:0.88rem;font-weight:600;">{repo}</td>
                </tr>
                <tr>
                  <td style="padding:4px 0;color:#94a3b8;font-size:0.82rem;">Branch</td>
                  <td style="padding:4px 0;font-size:0.88rem;font-weight:600;">{branch}</td>
                </tr>
                <tr>
                  <td style="padding:4px 0;color:#94a3b8;font-size:0.82rem;">Commit</td>
                  <td style="padding:4px 0;font-family:monospace;font-size:0.85rem;">{commit[:8]}</td>
                </tr>
                <tr>
                  <td style="padding:4px 0;color:#94a3b8;font-size:0.82rem;">Run ID</td>
                  <td style="padding:4px 0;font-size:0.88rem;">#{run_id}</td>
                </tr>
                <tr>
                  <td style="padding:4px 0;color:#94a3b8;font-size:0.82rem;">Timestamp</td>
                  <td style="padding:4px 0;font-size:0.88rem;">{ts}</td>
                </tr>
              </table>
            </td>
          </tr>
 
          <!-- Scan Results Table -->
          <tr>
            <td style="padding:24px 32px 0;border-bottom:1px solid #1f2937;">
              <h2 style="margin:0 0 12px;font-size:1rem;font-weight:700;color:#38bdf8;text-transform:uppercase;letter-spacing:.08em;">
                Scan Results
              </h2>
              <table width="100%" cellpadding="0" cellspacing="0"
                     style="border:1px solid #374151;border-radius:8px;overflow:hidden;margin-bottom:24px;">
                <thead>
                  <tr style="background:#1c2536;">
                    <th style="padding:10px 16px;text-align:left;font-size:0.75rem;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8;">
                      Scanner
                    </th>
                    <th style="padding:10px 16px;text-align:left;font-size:0.75rem;text-transform:uppercase;letter-spacing:.08em;color:#94a3b8;">
                      Result
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {rows}
                </tbody>
              </table>
            </td>
          </tr>
 
          <!-- Failure Summary -->
          <tr>
            <td style="padding:24px 32px;border-bottom:1px solid #1f2937;">
              <h2 style="margin:0 0 12px;font-size:1rem;font-weight:700;color:#ef4444;text-transform:uppercase;letter-spacing:.08em;">
                Failure Reasons
              </h2>
              <ul style="margin:0;padding-left:20px;color:#fca5a5;font-size:0.88rem;line-height:1.8;">
                {failure_list}
              </ul>
            </td>
          </tr>
 
          <!-- Remediation Tips -->
          <tr>
            <td style="padding:24px 32px;border-bottom:1px solid #1f2937;">
              <h2 style="margin:0 0 12px;font-size:1rem;font-weight:700;color:#f59e0b;text-transform:uppercase;letter-spacing:.08em;">
                Recommended Actions
              </h2>
              <ol style="margin:0;padding-left:20px;color:#e2e8f0;font-size:0.88rem;line-height:1.9;">
                <li>Review the full report in GitHub Actions artifacts</li>
                <li>Remove any hardcoded credentials and use GitHub Secrets instead</li>
                <li>Upgrade all vulnerable dependencies to their patched versions</li>
                <li>Fix SAST issues (SQL injection, debug mode, etc.)</li>
                <li>Rebuild Docker image after dependency upgrades</li>
                <li>Re-run the pipeline after fixes and verify it passes</li>
              </ol>
            </td>
          </tr>
 
          <!-- CTA Button -->
          <tr>
            <td style="padding:28px 32px;text-align:center;">
              <a href="{run_url}"
                 style="display:inline-block;background:#2563eb;color:#fff;text-decoration:none;
                        padding:12px 28px;border-radius:8px;font-weight:700;font-size:0.95rem;
                        letter-spacing:.02em;">
                🔍 View Full Pipeline Run →
              </a>
              <p style="margin:16px 0 0;font-size:0.78rem;color:#6b7280;">
                JSON reports are attached to this email. Open the dashboard artifact for a visual summary.
              </p>
            </td>
          </tr>
 
          <!-- Footer -->
          <tr>
            <td style="padding:16px 32px;background:#0b0f1a;text-align:center;border-top:1px solid #374151;">
              <p style="margin:0;font-size:0.75rem;color:#4b5563;">
                This alert was sent automatically by the <strong>Secure CI/CD Pipeline</strong> ·
                Do not reply to this email
              </p>
            </td>
          </tr>
 
        </table>
      </td>
    </tr>
  </table>
 
</body>
</html>"""
 
 
def main():
    parser = argparse.ArgumentParser(description="Generate security alert email")
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--commit", default="unknown")
    parser.add_argument("--branch", default="unknown")
    parser.add_argument("--run-id", default="0")
    parser.add_argument("--repo", default="unknown/unknown")
    parser.add_argument("--output", default="/tmp/email_body.html")
    args = parser.parse_args()
 
    html = generate_email(
        reports_dir=Path(args.reports_dir),
        commit=args.commit,
        branch=args.branch,
        run_id=args.run_id,
        repo=args.repo,
    )
 
    Path(args.output).write_text(html, encoding="utf-8")
    print(f"✅ Email body written to: {args.output}")
 
 
if __name__ == "__main__":
    main()