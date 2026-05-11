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
        self.assertIn("Run summary:", report)
        self.assertIn("- Initial alerts: 6 (Dependabot 3, code scanning 2, secret scanning 1)", report)
        self.assertIn("- Patched by automation: 4 alerts across 4 PRs", report)
        self.assertIn("- Auto-merged: 2 alerts across 2 PRs", report)
        self.assertIn("- Manual review required: 3 alerts across 3 items", report)
        self.assertIn("By alert class:", report)
        self.assertIn("Dependabot: 1 merged, 1 PR, 1 manual review", report)
        self.assertIn("Code scanning: 1 fixed, 0 PR, 1 manual", report)
        self.assertIn("Secret scanning: 1 cleanup PR, 1 manual", report)
        self.assertIn("Manual review required:", report)
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

        self.assertIn(
            "- Current GitHub open alerts: 6 (Dependabot 3, code scanning 2, secret scanning 1)",
            report,
        )
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

        self.assertNotIn("Manual review required:\n-", report)
        self.assertIn("manual repos: 13 checked, no current reportable alerts", report)

    def test_lists_only_explicit_public_repo_details(self):
        report = render_weekly_report(
            {
                "owner": "nickzren",
                "repo_counts": {"active": 13, "manual_only": 13},
                "units": [
                    {
                        "repository": "public-app",
                        "repository_visibility": "public",
                        "alert_class": "dependabot",
                        "outcome": "opened_pr",
                        "pull_request_url": "https://github.com/nickzren/public-app/pull/2",
                        "pull_request_title": "chore(deps): remediate root security alerts",
                    },
                    {
                        "repository": "public-web",
                        "repository_visibility": "public",
                        "alert_class": "secret_scanning",
                        "outcome": "opened_pr",
                        "pull_request_url": "https://github.com/nickzren/public-web/pull/3",
                        "pull_request_title": "fix(secret-scanning): remove token from root",
                        "secret_type": "example_service_token",
                    },
                    {
                        "repository": "private-app",
                        "repository_visibility": "private",
                        "alert_class": "dependabot",
                        "outcome": "opened_pr",
                        "pull_request_url": "https://github.com/nickzren/private-app/pull/4",
                        "pull_request_title": "private dependency fix",
                    },
                    {
                        "repository": "unknown-app",
                        "alert_class": "code_scanning",
                        "outcome": "opened_pr",
                        "pull_request_url": "https://github.com/nickzren/unknown-app/pull/5",
                        "pull_request_title": "unknown visibility fix",
                    },
                    {
                        "repository": "public-cli",
                        "repository_visibility": "public",
                        "alert_class": "code_scanning",
                        "outcome": "skipped",
                        "reason_code": "unsupported_rule",
                        "manual_follow_up_actions": ["manual code scanning review"],
                    },
                    {
                        "repository": "private-config",
                        "repository_visibility": "private",
                        "alert_class": "dependabot",
                        "outcome": "blocked",
                        "reason_code": "verification_unavailable",
                    },
                ],
            }
        )

        self.assertIn("Patched by automation:", report)
        self.assertIn(
            "- public-app: [Dependabot remediation PR](https://github.com/nickzren/public-app/pull/2)",
            report,
        )
        self.assertIn("- public-web: [Secret scanning cleanup PR](https://github.com/nickzren/public-web/pull/3)", report)
        self.assertIn("- Private or undisclosed repos: 2 PRs created, updated, or merged", report)
        self.assertIn("Manual review required:", report)
        self.assertIn("- public-cli: code scanning 1 (unsupported_rule)", report)
        self.assertIn("- Private or undisclosed repos: 1 manual-review item", report)
        self.assertNotIn("private-app", report)
        self.assertNotIn("unknown-app", report)
        self.assertNotIn("private-config", report)
        self.assertNotIn("example_service_token", report)
        self.assertNotIn("remove token", report)

    def test_public_details_sanitize_freeform_reasons_and_pr_titles(self):
        report = render_weekly_report(
            {
                "owner": "nickzren",
                "repo_counts": {"active": 13, "manual_only": 13},
                "units": [
                    {
                        "repository": "public-app",
                        "repository_visibility": "public",
                        "alert_class": "dependabot",
                        "outcome": "merged",
                        "pull_request_url": "https://github.com/nickzren/public-app/pull/8",
                        "pull_request_title": "fix leaked token abc123 from private path",
                    },
                    {
                        "repository": "public-cli",
                        "repository_visibility": "public",
                        "alert_class": "code_scanning",
                        "outcome": "blocked",
                        "reason": "token-like raw alert detail from scanner",
                    },
                ],
            }
        )

        self.assertIn(
            "- public-app: [Dependabot remediation PR](https://github.com/nickzren/public-app/pull/8)",
            report,
        )
        self.assertIn("- public-cli: code scanning 1 (blocked)", report)
        self.assertNotIn("leaked token", report)
        self.assertNotIn("abc123", report)
        self.assertNotIn("raw alert detail", report)


if __name__ == "__main__":
    unittest.main()
