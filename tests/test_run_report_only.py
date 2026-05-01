import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.run_report_only import (
    build_report_summary,
    load_profile_contract,
    write_report_artifacts,
)


class ReportOnlyRunnerTests(unittest.TestCase):
    def test_builds_sanitized_latest_json_from_open_alerts(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = write_profile(tmp)
            profile = load_profile_contract(profile_path)
            calls = []

            def fake_api(owner, repo, alert_class):
                calls.append((owner, repo, alert_class))
                if repo == "example-api" and alert_class == "dependabot":
                    return [{"number": 10}]
                if repo == "example-api" and alert_class == "code_scanning":
                    return [{"number": 20, "rule_id": "py/path-injection"}]
                if repo == "example-api" and alert_class == "secret_scanning":
                    return [
                        {
                            "number": 30,
                            "secret": "TOKEN_SHOULD_NOT_BE_REPORTED",
                            "secret_type": "example_service_token",
                        }
                    ]
                if repo == "example-cli" and alert_class == "dependabot":
                    return [{"number": 40}]
                return []

            summary = build_report_summary(
                profile,
                api_client=fake_api,
                now=datetime(2026, 5, 1, 13, 0, tzinfo=timezone.utc),
            )

            self.assertEqual(summary["generated_at"], "2026-05-01T13:00:00Z")
            self.assertEqual(summary["finished_at"], "2026-05-01T13:00:00Z")
            self.assertEqual(summary["profile_id"], "acme-local")
            self.assertEqual(summary["owner"], "acme")
            self.assertEqual(summary["repo_counts"], {"active": 1, "manual_only": 1, "ignored": 1})
            self.assertEqual(len(summary["units"]), 4)
            self.assertEqual(
                calls,
                [
                    ("acme", "example-api", "dependabot"),
                    ("acme", "example-api", "code_scanning"),
                    ("acme", "example-api", "secret_scanning"),
                    ("acme", "example-cli", "dependabot"),
                    ("acme", "example-cli", "secret_scanning"),
                ],
            )

            serialized = json.dumps(summary)
            self.assertNotIn("TOKEN_SHOULD_NOT_BE_REPORTED", serialized)
            self.assertNotIn("example_service_token", serialized)
            self.assertNotIn("secret_type", serialized)

            active_dependabot = find_unit(summary, "example-api", "dependabot")
            self.assertEqual(active_dependabot["outcome"], "blocked")
            self.assertEqual(active_dependabot["reason_code"], "report_only")

            manual_dependabot = find_unit(summary, "example-cli", "dependabot")
            self.assertEqual(manual_dependabot["repository_mode"], "manual_only")
            self.assertEqual(manual_dependabot["outcome"], "skipped")

    def test_requires_report_only_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = write_profile(tmp, mutation_mode="active")

            with self.assertRaisesRegex(ValueError, "mutation_mode must be report_only"):
                load_profile_contract(profile_path)

    def test_writes_latest_json_and_jsonl_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = write_profile(tmp)
            profile = load_profile_contract(profile_path)
            summary = build_report_summary(
                profile,
                api_client=lambda owner, repo, alert_class: [{"number": 1}]
                if repo == "example-api" and alert_class == "dependabot"
                else [],
                now=datetime(2026, 5, 1, 13, 0, tzinfo=timezone.utc),
            )

            paths = write_report_artifacts(summary, output_root=Path(tmp) / "runs")

            latest = json.loads(paths["latest_json"].read_text(encoding="utf-8"))
            jsonl_lines = paths["jsonl"].read_text(encoding="utf-8").splitlines()
            self.assertEqual(latest["profile_id"], "acme-local")
            self.assertEqual(len(jsonl_lines), 1)
            self.assertEqual(json.loads(jsonl_lines[0])["alert_class"], "dependabot")


def find_unit(summary, repo, alert_class):
    for unit in summary["units"]:
        if unit["repo"] == repo and unit["alert_class"] == alert_class:
            return unit
    raise AssertionError(f"unit not found for {repo} {alert_class}")


def write_profile(tmp, mutation_mode="report_only"):
    profile = Path(tmp) / "profile.yaml"
    profile.write_text(
        "\n".join(
            [
                "profile:",
                "  profile_id: acme-local",
                "  owner: acme",
                "  runtime:",
                f"    local_clone_root: {tmp}",
                "  defaults:",
                "    automation_mode: active",
                f"    mutation_mode: {mutation_mode}",
                "",
                "repositories:",
                "  - repo: example-api",
                "    automation_mode: active",
                "    targets:",
                "      - target_id: root",
                "        alert_classes:",
                "          - dependabot",
                "          - code_scanning",
                "          - secret_scanning",
                "  - repo: example-cli",
                "    automation_mode: manual_only",
                "    targets:",
                "      - target_id: root",
                "        alert_classes:",
                "          - dependabot",
                "          - secret_scanning",
                "  - repo: example-docs",
                "    automation_mode: ignored",
                "    targets: []",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return profile


if __name__ == "__main__":
    unittest.main()
