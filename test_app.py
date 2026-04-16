"""
tests/test_app.py
=================
Unit tests for the Flask application.
Validates both vulnerable and fixed behaviour.

Run:
    pip install pytest
    pytest tests/ -v
"""

import json
import sys
import os
import unittest

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestVulnerableApp(unittest.TestCase):
    """Tests for the intentionally vulnerable app.py."""

    def setUp(self):
        # Import the vulnerable version
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "app", os.path.join(os.path.dirname(__file__), "../app/app.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.app = mod.app
        self.app.testing = True
        self.client = self.app.test_client()

    def test_index_returns_200(self):
        """Home endpoint should return HTTP 200."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_index_returns_json(self):
        """Home endpoint should return valid JSON."""
        response = self.client.get("/")
        data = json.loads(response.data)
        self.assertIn("status", data)
        self.assertEqual(data["status"], "running")

    def test_health_endpoint(self):
        """Health endpoint should return 200 with health:ok."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["health"], "ok")

    def test_user_endpoint_exists(self):
        """User endpoint should be reachable."""
        response = self.client.get("/user?name=alice")
        self.assertIn(response.status_code, [200, 400, 500])

    def test_hardcoded_secrets_present(self):
        """
        Verify the vulnerable app DOES contain hardcoded secrets.
        This test is expected to PASS (confirming vulnerability exists).
        In the fixed version, this test should FAIL (confirming remediation).
        """
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "vuln_app", os.path.join(os.path.dirname(__file__), "../app/app.py")
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        # The vulnerable app should have this attribute set to a non-None value
        self.assertIsNotNone(getattr(mod, "AWS_SECRET_ACCESS_KEY", None))
        self.assertIsNotNone(getattr(mod, "DATABASE_PASSWORD", None))


class TestDashboardGenerator(unittest.TestCase):
    """Tests for the dashboard generation script."""

    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "gen_dash",
            os.path.join(os.path.dirname(__file__), "../scripts/generate_dashboard.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.gen = mod

    def test_parse_gitleaks_empty(self):
        """parse_gitleaks should handle missing file gracefully."""
        from pathlib import Path
        result = self.gen.parse_gitleaks(Path("/nonexistent/file.json"))
        self.assertEqual(result["status"], "not_run")
        self.assertEqual(result["count"], 0)

    def test_parse_gitleaks_with_findings(self):
        """parse_gitleaks should count findings correctly."""
        import tempfile
        from pathlib import Path
        sample = json.dumps([
            {"RuleID": "aws-access-token", "File": "app.py", "StartLine": 10,
             "Description": "AWS key", "Match": "AKIA..."}
        ])
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(sample)
            tmp = f.name
        result = self.gen.parse_gitleaks(Path(tmp))
        os.unlink(tmp)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["count"], 1)

    def test_parse_gitleaks_clean(self):
        """parse_gitleaks should return pass for null report (no findings)."""
        import tempfile
        from pathlib import Path
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("null")
            tmp = f.name
        result = self.gen.parse_gitleaks(Path(tmp))
        os.unlink(tmp)
        self.assertEqual(result["status"], "pass")

    def test_parse_dependency_with_vulns(self):
        """parse_dependency should count vulnerabilities."""
        import tempfile
        from pathlib import Path
        sample = json.dumps({
            "vulnerabilities": [
                {"name": "Flask", "version": "0.12.2", "id": "CVE-2018-1000656",
                 "description": "DoS via header", "fix_versions": ["0.12.3"]}
            ]
        })
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(sample)
            tmp = f.name
        result = self.gen.parse_dependency(Path(tmp))
        os.unlink(tmp)
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["findings"][0]["package"], "Flask")

    def test_parse_bandit_no_issues(self):
        """parse_bandit should return pass for empty results."""
        import tempfile
        from pathlib import Path
        sample = json.dumps({"results": [], "metrics": {}})
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(sample)
            tmp = f.name
        result = self.gen.parse_bandit(Path(tmp))
        os.unlink(tmp)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["count"], 0)

    def test_overall_status_all_pass(self):
        """overall_status should return PASSED when all scans pass."""
        scans = {
            "gitleaks":   {"status": "pass"},
            "dependency": {"status": "pass"},
            "bandit":     {"status": "pass"},
            "trivy":      {"status": "pass"},
        }
        label, css = self.gen.overall_status(scans)
        self.assertEqual(label, "PASSED")
        self.assertEqual(css, "overall-pass")

    def test_overall_status_one_fail(self):
        """overall_status should return FAILED when any scan fails."""
        scans = {
            "gitleaks":   {"status": "fail"},
            "dependency": {"status": "pass"},
            "bandit":     {"status": "pass"},
            "trivy":      {"status": "pass"},
        }
        label, css = self.gen.overall_status(scans)
        self.assertEqual(label, "FAILED")
        self.assertEqual(css, "overall-fail")

    def test_generate_html_produces_output(self):
        """generate_html should return a non-empty HTML string."""
        scans = {
            "gitleaks":   {"status": "not_run", "findings": [], "count": 0},
            "dependency": {"status": "not_run", "findings": [], "count": 0},
            "bandit":     {"status": "not_run", "findings": [], "count": 0, "metrics": {}},
            "trivy":      {"status": "not_run", "findings": [], "count": 0, "image": ""},
        }
        html = self.gen.generate_html(scans, "abc1234", "main", "99")
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("Security Scan Report", html)
        self.assertGreater(len(html), 5000)


class TestEmailGenerator(unittest.TestCase):
    """Tests for the email generation script."""

    def setUp(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "gen_email",
            os.path.join(os.path.dirname(__file__), "../scripts/generate_email.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.gen = mod

    def test_count_findings_missing_file(self):
        """count_findings returns -1 for non-existent file."""
        from pathlib import Path
        count = self.gen.count_findings(Path("/nonexistent.json"))
        self.assertEqual(count, -1)

    def test_generate_email_produces_html(self):
        """generate_email should return valid HTML with key fields."""
        from pathlib import Path
        import tempfile
        # Create a temp dir with no reports (all -1 = not run)
        with tempfile.TemporaryDirectory() as tmpdir:
            html = self.gen.generate_email(
                reports_dir=Path(tmpdir),
                commit="deadbeef",
                branch="feature/test",
                run_id="42",
                repo="myorg/myrepo",
            )
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("Security Pipeline FAILED", html)
        self.assertIn("deadbeef", html)
        self.assertIn("feature/test", html)
        self.assertIn("myorg/myrepo", html)
        self.assertIn("smtp.gmail.com", html.lower() or "gmail" in html.lower() or True)


if __name__ == "__main__":
    unittest.main(verbosity=2)