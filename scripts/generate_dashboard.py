#!/usr/bin/env python3
"""
generate_dashboard.py
=====================
Reads all JSON security scan reports and produces a single
self-contained HTML security dashboard (dashboard/report.html).
 
Usage:
    python3 scripts/generate_dashboard.py \
        --reports-dir reports \
        --output dashboard/report.html \
        --commit abc1234 \
        --branch main \
        --run-id 123456
"""
 
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
 
 
# ──────────────────────────────────────────────────────────────
# JSON Parsers — one per tool
# ──────────────────────────────────────────────────────────────
 
def parse_gitleaks(path: Path) -> dict:
    """Parse Gitleaks JSON report."""
    result = {"status": "not_run", "findings": [], "count": 0}
    if not path.exists():
        return result
    try:
        data = json.loads(path.read_text())
        if data is None:
            result["status"] = "pass"
            return result
        findings = data if isinstance(data, list) else []
        result["findings"] = [
            {
                "rule": f.get("RuleID", "unknown"),
                "file": f.get("File", "unknown"),
                "line": f.get("StartLine", 0),
                "description": f.get("Description", ""),
                "secret": "[REDACTED]",
            }
            for f in findings
        ]
        result["count"] = len(findings)
        result["status"] = "fail" if findings else "pass"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result
 
 
def parse_dependency(path: Path) -> dict:
    """Parse pip-audit JSON report."""
    result = {"status": "not_run", "findings": [], "count": 0}
    if not path.exists():
        return result
    try:
        data = json.loads(path.read_text())
        vulns = data.get("vulnerabilities", [])
        result["findings"] = [
            {
                "package": v.get("name", "unknown"),
                "version": v.get("version", "?"),
                "vuln_id": v.get("id", "?"),
                "description": v.get("description", "")[:200],
                "fix_versions": ", ".join(v.get("fix_versions", [])) or "No fix available",
            }
            for v in vulns
        ]
        result["count"] = len(vulns)
        result["status"] = "fail" if vulns else "pass"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result
 
 
def parse_bandit(path: Path) -> dict:
    """Parse Bandit SAST JSON report."""
    result = {"status": "not_run", "findings": [], "count": 0, "metrics": {}}
    if not path.exists():
        return result
    try:
        data = json.loads(path.read_text())
        issues = data.get("results", [])
        result["findings"] = [
            {
                "test_id": i.get("test_id", "?"),
                "test_name": i.get("test_name", "?"),
                "severity": i.get("issue_severity", "?"),
                "confidence": i.get("issue_confidence", "?"),
                "file": i.get("filename", "?"),
                "line": i.get("line_number", 0),
                "text": i.get("issue_text", ""),
            }
            for i in issues
        ]
        result["count"] = len(issues)
        result["metrics"] = data.get("metrics", {})
        result["status"] = "fail" if issues else "pass"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result
 
 
def parse_trivy(path: Path) -> dict:
    """Parse Trivy container scan JSON report."""
    result = {"status": "not_run", "findings": [], "count": 0, "image": ""}
    if not path.exists():
        return result
    try:
        data = json.loads(path.read_text())
        result["image"] = data.get("ArtifactName", "unknown")
        all_vulns = []
        for target in data.get("Results", []):
            for v in target.get("Vulnerabilities", []) or []:
                all_vulns.append({
                    "vuln_id": v.get("VulnerabilityID", "?"),
                    "package": v.get("PkgName", "?"),
                    "installed": v.get("InstalledVersion", "?"),
                    "fixed": v.get("FixedVersion", "No fix"),
                    "severity": v.get("Severity", "?"),
                    "title": v.get("Title", "")[:120],
                    "target": target.get("Target", ""),
                })
        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        all_vulns.sort(key=lambda x: sev_order.get(x["severity"], 99))
        result["findings"] = all_vulns
        result["count"] = len(all_vulns)
        result["status"] = "fail" if all_vulns else "pass"
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
    return result
 
 
# ──────────────────────────────────────────────────────────────
# HTML Generation
# ──────────────────────────────────────────────────────────────
 
STATUS_BADGE = {
    "pass":    ('<span class="badge badge-pass">✅ PASS</span>', "section-pass"),
    "fail":    ('<span class="badge badge-fail">❌ FAIL</span>', "section-fail"),
    "not_run": ('<span class="badge badge-skip">⏭ NOT RUN</span>', "section-skip"),
    "error":   ('<span class="badge badge-error">⚠️ ERROR</span>', "section-error"),
}
 
SEV_CLASS = {
    "CRITICAL": "sev-critical",
    "HIGH": "sev-high",
    "MEDIUM": "sev-medium",
    "LOW": "sev-low",
    "UNKNOWN": "sev-unknown",
}
 
 
def rows_gitleaks(findings):
    if not findings:
        return "<tr><td colspan='4' class='no-issues'>No secrets detected 🎉</td></tr>"
    return "\n".join(
        f"<tr><td><code>{f['rule']}</code></td><td>{f['file']}</td>"
        f"<td>{f['line']}</td><td>{f['description']}</td></tr>"
        for f in findings
    )
 
 
def rows_dependency(findings):
    if not findings:
        return "<tr><td colspan='5' class='no-issues'>No vulnerable dependencies 🎉</td></tr>"
    return "\n".join(
        f"<tr><td><code>{f['package']}</code></td><td>{f['version']}</td>"
        f"<td><code>{f['vuln_id']}</code></td><td>{f['fix_versions']}</td>"
        f"<td class='desc-cell'>{f['description']}</td></tr>"
        for f in findings
    )
 
 
def rows_bandit(findings):
    if not findings:
        return "<tr><td colspan='6' class='no-issues'>No SAST issues 🎉</td></tr>"
    rows = []
    for f in findings:
        sev_cls = SEV_CLASS.get(f["severity"], "")
        rows.append(
            f"<tr><td><code>{f['test_id']}</code></td><td>{f['test_name']}</td>"
            f"<td><span class='sev-badge {sev_cls}'>{f['severity']}</span></td>"
            f"<td>{f['confidence']}</td><td>{f['file']}:{f['line']}</td>"
            f"<td class='desc-cell'>{f['text']}</td></tr>"
        )
    return "\n".join(rows)
 
 
def rows_trivy(findings):
    if not findings:
        return "<tr><td colspan='6' class='no-issues'>No container vulnerabilities 🎉</td></tr>"
    rows = []
    for f in findings:
        sev_cls = SEV_CLASS.get(f["severity"], "")
        rows.append(
            f"<tr><td><code>{f['vuln_id']}</code></td><td><code>{f['package']}</code></td>"
            f"<td>{f['installed']}</td><td>{f['fixed']}</td>"
            f"<td><span class='sev-badge {sev_cls}'>{f['severity']}</span></td>"
            f"<td class='desc-cell'>{f['title']}</td></tr>"
        )
    return "\n".join(rows)
 
 
def overall_status(scans: dict) -> tuple[str, str]:
    """Return (label, css_class) for overall pipeline status."""
    statuses = [s["status"] for s in scans.values()]
    if any(s == "fail" for s in statuses):
        return "FAILED", "overall-fail"
    if any(s == "error" for s in statuses):
        return "ERROR", "overall-error"
    if all(s == "pass" for s in statuses):
        return "PASSED", "overall-pass"
    return "PARTIAL", "overall-warn"
 
 
def generate_html(scans: dict, commit: str, branch: str, run_id: str) -> str:
    gl = scans["gitleaks"]
    dep = scans["dependency"]
    ban = scans["bandit"]
    tri = scans["trivy"]
 
    ov_label, ov_class = overall_status(scans)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
 
    total_issues = gl["count"] + dep["count"] + ban["count"] + tri["count"]
 
    def badge(key):
        return STATUS_BADGE.get(key, STATUS_BADGE["not_run"])[0]
 
    def sec_class(key):
        return STATUS_BADGE.get(key, STATUS_BADGE["not_run"])[1]
 
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Scan Report — {branch} @ {commit[:8]}</title>
<style>
  /* ── Reset & Base ── */
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  :root {{
    --bg:        #0b0f1a;
    --surface:   #111827;
    --surface2:  #1c2536;
    --border:    #2a3448;
    --text:      #e2e8f0;
    --muted:     #8b9ab3;
    --accent:    #38bdf8;
    --pass:      #22c55e;
    --fail:      #ef4444;
    --warn:      #f59e0b;
    --skip:      #6b7280;
    --crit:      #dc2626;
    --high:      #f97316;
    --med:       #eab308;
    --low:       #3b82f6;
    --font-mono: 'JetBrains Mono', 'Fira Code', monospace;
    --font-sans: 'IBM Plex Sans', system-ui, sans-serif;
    --radius:    8px;
  }}
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
  html {{ scroll-behavior: smooth; }}
  body {{
    font-family: var(--font-sans);
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    line-height: 1.6;
  }}
  /* ── Layout ── */
  .header {{
    background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
    border-bottom: 1px solid var(--border);
    padding: 2.5rem 2rem 2rem;
    position: sticky; top: 0; z-index: 100;
  }}
  .header-inner {{
    max-width: 1200px; margin: 0 auto;
    display: flex; align-items: flex-start; gap: 1.5rem; flex-wrap: wrap;
  }}
  .logo {{ font-size: 2rem; flex-shrink: 0; }}
  .header-text h1 {{
    font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em;
    color: var(--accent);
  }}
  .header-meta {{ font-size: 0.8rem; color: var(--muted); margin-top: 0.25rem; }}
  .header-meta span {{ margin-right: 1.5rem; }}
  .overall-badge {{
    margin-left: auto; align-self: center;
    font-size: 1.1rem; font-weight: 700; padding: 0.6rem 1.4rem;
    border-radius: 50px; letter-spacing: 0.05em;
  }}
  .overall-pass  {{ background: rgba(34,197,94,.15);  color: var(--pass);  border: 1px solid var(--pass);  }}
  .overall-fail  {{ background: rgba(239,68,68,.15);  color: var(--fail);  border: 1px solid var(--fail);  }}
  .overall-error {{ background: rgba(245,158,11,.15); color: var(--warn);  border: 1px solid var(--warn);  }}
  .overall-warn  {{ background: rgba(245,158,11,.15); color: var(--warn);  border: 1px solid var(--warn);  }}
  .main {{ max-width: 1200px; margin: 2rem auto; padding: 0 1.5rem 4rem; }}
  /* ── Summary Cards ── */
  .summary-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1rem; margin-bottom: 2.5rem;
  }}
  .card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 1.25rem 1.5rem;
    transition: transform .15s, box-shadow .15s;
  }}
  .card:hover {{ transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,0,0,.4); }}
  .card-label {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: .1em; color: var(--muted); }}
  .card-value {{ font-size: 2rem; font-weight: 700; margin: 0.25rem 0; }}
  .card-sub   {{ font-size: 0.82rem; color: var(--muted); }}
  .card.total .card-value {{ color: var(--accent); }}
  .card.secrets  .card-value {{ color: {("var(--fail)" if gl['count'] else "var(--pass)")}; }}
  .card.deps     .card-value {{ color: {("var(--fail)" if dep['count'] else "var(--pass)")}; }}
  .card.sast     .card-value {{ color: {("var(--fail)" if ban['count'] else "var(--pass)")}; }}
  .card.container .card-value {{ color: {("var(--fail)" if tri['count'] else "var(--pass)")}; }}
  /* ── Sections ── */
  .section {{ margin-bottom: 2rem; }}
  .section-header {{
    display: flex; align-items: center; gap: 1rem;
    padding: 1rem 1.5rem; border-radius: var(--radius) var(--radius) 0 0;
    border: 1px solid var(--border); border-bottom: none;
    cursor: pointer; user-select: none;
  }}
  .section-pass   {{ background: rgba(34,197,94,.07);  border-color: rgba(34,197,94,.3); }}
  .section-fail   {{ background: rgba(239,68,68,.07);  border-color: rgba(239,68,68,.3); }}
  .section-skip   {{ background: rgba(107,114,128,.07); border-color: rgba(107,114,128,.3); }}
  .section-error  {{ background: rgba(245,158,11,.07); border-color: rgba(245,158,11,.3); }}
  .section-title  {{ font-size: 1rem; font-weight: 600; flex: 1; }}
  .section-desc   {{ font-size: 0.82rem; color: var(--muted); }}
  .section-toggle {{ font-size: 1.2rem; transition: transform .2s; }}
  .section-body {{
    background: var(--surface); border: 1px solid var(--border);
    border-top: none; border-radius: 0 0 var(--radius) var(--radius);
    overflow: hidden;
  }}
  /* ── Badges ── */
  .badge {{ display: inline-flex; align-items: center; gap: .3rem; padding: .2rem .65rem; border-radius: 50px; font-size: .78rem; font-weight: 600; }}
  .badge-pass  {{ background: rgba(34,197,94,.15);  color: var(--pass);  }}
  .badge-fail  {{ background: rgba(239,68,68,.15);  color: var(--fail);  }}
  .badge-skip  {{ background: rgba(107,114,128,.15); color: var(--skip); }}
  .badge-error {{ background: rgba(245,158,11,.15); color: var(--warn);  }}
  /* ── Tables ── */
  .table-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.83rem; }}
  th {{ background: var(--surface2); color: var(--muted); font-weight: 600;
        text-transform: uppercase; letter-spacing: .06em; font-size: .72rem;
        padding: .65rem 1rem; text-align: left; white-space: nowrap; }}
  td {{ padding: .6rem 1rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,.02); }}
  .no-issues {{ text-align: center; color: var(--pass); padding: 2rem !important; font-weight: 600; }}
  code {{ font-family: var(--font-mono); font-size: .85em; background: rgba(255,255,255,.07); padding: .1em .35em; border-radius: 3px; }}
  .desc-cell {{ max-width: 300px; color: var(--muted); font-size: .8rem; }}
  /* ── Severity Badges ── */
  .sev-badge {{ display: inline-block; padding: .15rem .55rem; border-radius: 4px; font-size: .72rem; font-weight: 700; letter-spacing: .05em; }}
  .sev-critical {{ background: rgba(220,38,38,.2);  color: #fca5a5; }}
  .sev-high     {{ background: rgba(249,115,22,.2); color: #fdba74; }}
  .sev-medium   {{ background: rgba(234,179,8,.2);  color: #fde047; }}
  .sev-low      {{ background: rgba(59,130,246,.2); color: #93c5fd; }}
  .sev-unknown  {{ background: rgba(107,114,128,.2); color: #d1d5db; }}
  /* ── Footer ── */
  footer {{ text-align: center; padding: 2rem; font-size: .8rem; color: var(--muted); border-top: 1px solid var(--border); }}
  /* ── Scrollbar ── */
  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: var(--bg); }}
  ::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 3px; }}
</style>
</head>
<body>
 
<!-- ═══ HEADER ════════════════════════════════════════════ -->
<header class="header">
  <div class="header-inner">
    <div class="logo">🔐</div>
    <div class="header-text">
      <h1>Security Scan Report</h1>
      <div class="header-meta">
        <span>📦 Branch: <strong>{branch}</strong></span>
        <span>🔖 Commit: <code>{commit[:8]}</code></span>
        <span>🏃 Run: <strong>#{run_id}</strong></span>
        <span>🕒 {ts}</span>
      </div>
    </div>
    <div class="overall-badge {ov_class}">{ov_label}</div>
  </div>
</header>
 
<main class="main">
 
  <!-- ═══ SUMMARY CARDS ════════════════════════════════════ -->
  <div class="summary-grid">
    <div class="card total">
      <div class="card-label">Total Issues</div>
      <div class="card-value">{total_issues}</div>
      <div class="card-sub">Across all scanners</div>
    </div>
    <div class="card secrets">
      <div class="card-label">🔑 Secrets</div>
      <div class="card-value">{gl['count']}</div>
      <div class="card-sub">Gitleaks findings</div>
    </div>
    <div class="card deps">
      <div class="card-label">📦 Dep. Vulns</div>
      <div class="card-value">{dep['count']}</div>
      <div class="card-sub">pip-audit findings</div>
    </div>
    <div class="card sast">
      <div class="card-label">🧪 SAST Issues</div>
      <div class="card-value">{ban['count']}</div>
      <div class="card-sub">Bandit findings</div>
    </div>
    <div class="card container">
      <div class="card-label">🐳 Container CVEs</div>
      <div class="card-value">{tri['count']}</div>
      <div class="card-sub">Trivy findings</div>
    </div>
  </div>
 
  <!-- ═══ SECRET DETECTION ════════════════════════════════ -->
  <div class="section">
    <div class="section-header {sec_class(gl['status'])}" onclick="toggle('sec-body')">
      <span class="section-title">🔑 Secret Detection — Gitleaks</span>
      <span class="section-desc">{gl['count']} finding(s)</span>
      {badge(gl['status'])}
      <span class="section-toggle" id="sec-toggle">▼</span>
    </div>
    <div class="section-body" id="sec-body">
      <div class="table-wrap">
        <table>
          <thead><tr><th>Rule ID</th><th>File</th><th>Line</th><th>Description</th></tr></thead>
          <tbody>{rows_gitleaks(gl['findings'])}</tbody>
        </table>
      </div>
    </div>
  </div>
 
  <!-- ═══ DEPENDENCY SCAN ══════════════════════════════════ -->
  <div class="section">
    <div class="section-header {sec_class(dep['status'])}" onclick="toggle('dep-body')">
      <span class="section-title">📦 Dependency Vulnerabilities — pip-audit</span>
      <span class="section-desc">{dep['count']} vulnerable package(s)</span>
      {badge(dep['status'])}
      <span class="section-toggle" id="dep-toggle">▼</span>
    </div>
    <div class="section-body" id="dep-body">
      <div class="table-wrap">
        <table>
          <thead><tr><th>Package</th><th>Version</th><th>CVE / ID</th><th>Fix Version</th><th>Description</th></tr></thead>
          <tbody>{rows_dependency(dep['findings'])}</tbody>
        </table>
      </div>
    </div>
  </div>
 
  <!-- ═══ STATIC ANALYSIS ══════════════════════════════════ -->
  <div class="section">
    <div class="section-header {sec_class(ban['status'])}" onclick="toggle('sast-body')">
      <span class="section-title">🧪 Static Analysis — Bandit (SAST)</span>
      <span class="section-desc">{ban['count']} issue(s)</span>
      {badge(ban['status'])}
      <span class="section-toggle" id="sast-toggle">▼</span>
    </div>
    <div class="section-body" id="sast-body">
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>Test Name</th><th>Severity</th><th>Confidence</th><th>Location</th><th>Description</th></tr></thead>
          <tbody>{rows_bandit(ban['findings'])}</tbody>
        </table>
      </div>
    </div>
  </div>
 
  <!-- ═══ CONTAINER SCAN ═══════════════════════════════════ -->
  <div class="section">
    <div class="section-header {sec_class(tri['status'])}" onclick="toggle('trivy-body')">
      <span class="section-title">🐳 Container Security — Trivy</span>
      <span class="section-desc">{tri['count']} CVE(s) — image: {tri.get('image', 'n/a')}</span>
      {badge(tri['status'])}
      <span class="section-toggle" id="trivy-toggle">▼</span>
    </div>
    <div class="section-body" id="trivy-body">
      <div class="table-wrap">
        <table>
          <thead><tr><th>CVE ID</th><th>Package</th><th>Installed</th><th>Fixed</th><th>Severity</th><th>Title</th></tr></thead>
          <tbody>{rows_trivy(tri['findings'])}</tbody>
        </table>
      </div>
    </div>
  </div>
 
</main>
 
<footer>
  Generated by <strong>Secure CI/CD Pipeline</strong> &middot;
  Commit <code>{commit[:8]}</code> &middot; {ts}
</footer>
 
<script>
  function toggle(id) {{
    const body = document.getElementById(id);
    const key  = id.replace('-body', '-toggle');
    const tog  = document.getElementById(key);
    if (!body) return;
    const hidden = body.style.display === 'none';
    body.style.display = hidden ? '' : 'none';
    if (tog) tog.style.transform = hidden ? '' : 'rotate(-90deg)';
  }}
</script>
</body>
</html>
"""
 
 
# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────
 
def main():
    parser = argparse.ArgumentParser(description="Generate security dashboard HTML")
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--output", default="dashboard/report.html")
    parser.add_argument("--commit", default="unknown")
    parser.add_argument("--branch", default="unknown")
    parser.add_argument("--run-id", default="0")
    args = parser.parse_args()
 
    rdir = Path(args.reports_dir)
 
    scans = {
        "gitleaks":   parse_gitleaks(rdir / "gitleaks-report.json"),
        "dependency": parse_dependency(rdir / "dependency-report.json"),
        "bandit":     parse_bandit(rdir / "bandit-report.json"),
        "trivy":      parse_trivy(rdir / "trivy-report.json"),
    }
 
    html = generate_html(scans, args.commit, args.branch, args.run_id)
 
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
 
    print(f"✅ Dashboard written to: {out}")
    print(f"   Secrets:      {scans['gitleaks']['count']} findings")
    print(f"   Dep vulns:    {scans['dependency']['count']} findings")
    print(f"   SAST issues:  {scans['bandit']['count']} findings")
    print(f"   Container:    {scans['trivy']['count']} findings")
 
 
if __name__ == "__main__":
    main()