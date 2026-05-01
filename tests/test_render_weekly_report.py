import json
import unittest
from pathlib import Path

from scripts.render_weekly_report import render_weekly_report


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
