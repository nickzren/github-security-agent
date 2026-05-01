import json
import unittest
from pathlib import Path

from scripts.render_weekly_report import (
    load_security_overview_json,
    render_no_completed_run,
    render_stale_report,
    render_weekly_report,
)


FIXTURE_DIR = Path(__file__).parent / "fixtures" / "weekly_report"


def load_fixture(name):
    return json.loads((FIXTURE_DIR / name).read_text())


class WeeklyReportRendererTests(unittest.TestCase):
    def test_renders_compact_personal_summary(self):
        report = render_weekly_report(load_fixture("latest_personal.json"))

        self.assertIn("## Weekly Security Report", report)
        self.assertIn("Dependabot: 1 merged, 1 PR, 1 blocked", report)
        self.assertIn("Code scanning: 1 fixed, 0 PR, 1 manual", report)
        self.assertIn("Secret scanning: 1 cleanup PR, 1 manual", report)
        self.assertIn("Manual attention:", report)
        self.assertIn("- Dependabot: 1", report)
        self.assertIn("- code scanning: 1", report)
        self.assertIn("- secret scanning: 1", report)
        self.assertNotIn("example-cli", report)
        self.assertNotIn("example-config", report)
        self.assertNotIn("example-web", report)
        self.assertIn("- 13 active repos scanned", report)
        self.assertIn("- 13 manual-only repos checked", report)

    def test_renders_counts_only_security_overview(self):
        report = render_weekly_report(
            load_fixture("latest_no_manual.json"),
            security_overview=load_security_overview_json(FIXTURE_DIR / "security_overview.json"),
        )

        self.assertIn("GitHub open alerts:", report)
        self.assertIn("- Dependabot: 3", report)
        self.assertIn("- Code scanning: 2", report)
        self.assertIn("- Secret scanning: 1", report)
        self.assertIn("- Total: 6", report)
        self.assertNotIn("example-app", report)
        self.assertNotIn("secret_type", report)
        self.assertNotIn("alert_number", report)

    def test_missing_latest_can_include_dashboard_counts(self):
        report = render_no_completed_run(
            security_overview=load_security_overview_json(FIXTURE_DIR / "security_overview.json")
        )

        self.assertIn("No completed security-agent run this week.", report)
        self.assertIn("GitHub open alerts:", report)
        self.assertIn("- Total: 6", report)
        self.assertIn("dashboard counts only", report)

    def test_stale_latest_can_include_dashboard_counts(self):
        report = render_stale_report(
            "2026-04-20T00:00:00+00:00",
            security_overview=load_security_overview_json(FIXTURE_DIR / "security_overview.json"),
        )

        self.assertIn("Stale report.", report)
        self.assertIn("- Total: 6", report)
        self.assertIn("remediation details are stale", report)

    def test_accepts_custom_heading(self):
        report = render_weekly_report(
            load_fixture("latest_no_manual.json"),
            heading="Team Security Weekly",
        )

        self.assertIn("## Team Security Weekly", report)

    def test_omits_raw_secret_scanning_details(self):
        report = render_weekly_report(load_fixture("latest_personal.json"))

        self.assertNotIn("example_service_token", report)
        self.assertNotIn("secret_type", report)
        self.assertNotIn("alert_number", report)
        self.assertNotIn("alert 123", report)

    def test_collapses_empty_manual_section(self):
        report = render_weekly_report(load_fixture("latest_no_manual.json"))

        self.assertNotIn("Manual attention:\n-", report)
        self.assertIn("manual repos: 13 checked, no current reportable alerts", report)


if __name__ == "__main__":
    unittest.main()
