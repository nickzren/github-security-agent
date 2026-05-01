import base64
import gzip
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.dispatch_weekly_report import prepare_dispatch


def decode_body(encoded):
    return gzip.decompress(base64.b64decode(encoded)).decode("utf-8")


class WeeklyReportDispatcherTests(unittest.TestCase):
    def test_rejects_missing_report_only_mutation_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "profile.yaml"
            latest = Path(tmp) / "latest.json"
            profile.write_text(
                "\n".join(
                    [
                        "profile:",
                        "  owner: acme",
                        "  defaults:",
                        "    automation_mode: manual_only",
                    ]
                ),
                encoding="utf-8",
            )
            latest.write_text('{"repo_counts": {"active": 0, "manual_only": 0}, "units": []}', encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "mutation_mode"):
                prepare_dispatch(
                    profile_path=profile,
                    latest_json=latest,
                    publish_repo="acme/github-security-agent",
                    issue_repo="acme/github-security-agent",
                    now=datetime(2026, 5, 1, tzinfo=timezone.utc),
                )

    def test_rejects_owner_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = write_profile(tmp)
            latest = Path(tmp) / "latest.json"
            latest.write_text('{"repo_counts": {"active": 0, "manual_only": 0}, "units": []}', encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "owner mismatch"):
                prepare_dispatch(
                    profile_path=profile,
                    latest_json=latest,
                    publish_repo="other/github-security-agent",
                    issue_repo="acme/github-security-agent",
                    now=datetime(2026, 5, 1, tzinfo=timezone.utc),
                )

    def test_missing_latest_json_publishes_no_completed_run_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = write_profile(tmp)
            overview = write_security_overview(tmp)
            request = prepare_dispatch(
                profile_path=profile,
                latest_json=Path(tmp) / "missing.json",
                publish_repo="acme/github-security-agent",
                issue_repo="acme/github-security-agent",
                security_overview_json=overview,
                now=datetime(2026, 5, 1, tzinfo=timezone.utc),
            )

            body = decode_body(request.issue_body_gz_b64)
            self.assertEqual(request.publish_repo, "acme/github-security-agent")
            self.assertEqual(request.issue_repo, "acme/github-security-agent")
            self.assertIn("Weekly Security Report", request.issue_title)
            self.assertIn("No completed security-agent run this week.", body)
            self.assertIn("GitHub open alerts:", body)
            self.assertIn("- Total: 6", body)

    def test_accepts_custom_heading(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = write_profile(tmp)
            request = prepare_dispatch(
                profile_path=profile,
                latest_json=Path(tmp) / "missing.json",
                publish_repo="acme/github-security-agent",
                issue_repo="acme/github-security-agent",
                heading="Team Security Weekly",
                now=datetime(2026, 5, 1, tzinfo=timezone.utc),
            )

            body = decode_body(request.issue_body_gz_b64)
            self.assertIn("Team Security Weekly", request.issue_title)
            self.assertIn("## Team Security Weekly", body)

    def test_accepts_pull_request_mutation_mode_for_publish_after_autofix(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = write_profile(tmp, mutation_mode="pull_request")
            latest = Path(tmp) / "latest.json"
            latest.write_text(
                json.dumps(
                    {
                        "generated_at": "2026-05-01T13:00:00Z",
                        "repo_counts": {"active": 13, "manual_only": 13},
                        "units": [{"alert_class": "dependabot", "outcome": "opened_pr"}],
                    }
                ),
                encoding="utf-8",
            )

            request = prepare_dispatch(
                profile_path=profile,
                latest_json=latest,
                publish_repo="acme/github-security-agent",
                issue_repo="acme/github-security-agent",
                now=datetime(2026, 5, 1, 14, 0, tzinfo=timezone.utc),
            )

            body = decode_body(request.issue_body_gz_b64)
            self.assertIn("Dependabot: 0 merged, 1 PR, 0 blocked", body)

    def test_stale_latest_json_publishes_stale_report_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = write_profile(tmp)
            latest = Path(tmp) / "latest.json"
            latest.write_text(
                json.dumps(
                    {
                        "generated_at": "2026-04-20T00:00:00Z",
                        "repo_counts": {"active": 13, "manual_only": 13},
                        "units": [],
                    }
                ),
                encoding="utf-8",
            )

            request = prepare_dispatch(
                profile_path=profile,
                latest_json=latest,
                publish_repo="acme/github-security-agent",
                issue_repo="acme/github-security-agent",
                security_overview_json=write_security_overview(tmp),
                now=datetime(2026, 5, 1, tzinfo=timezone.utc),
            )

            body = decode_body(request.issue_body_gz_b64)
            self.assertIn("Stale report.", body)
            self.assertIn("Last completed run: 2026-04-20T00:00:00+00:00", body)
            self.assertIn("- Total: 6", body)


def write_profile(tmp, mutation_mode="report_only"):
    profile = Path(tmp) / "profile.yaml"
    profile.write_text(
        "\n".join(
            [
                "profile:",
                "  owner: 'acme' # public test owner",
                "  defaults:",
                "    automation_mode: manual_only",
                f"    mutation_mode: {mutation_mode}",
            ]
        ),
        encoding="utf-8",
    )
    return profile


def write_security_overview(tmp):
    overview = Path(tmp) / "security-overview.json"
    overview.write_text(
        json.dumps(
            {
                "open_alert_counts": {
                    "dependabot": 3,
                    "code_scanning": 2,
                    "secret_scanning": 1,
                    "total": 6,
                }
            }
        ),
        encoding="utf-8",
    )
    return overview


if __name__ == "__main__":
    unittest.main()
