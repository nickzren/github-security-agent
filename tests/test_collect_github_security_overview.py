import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.collect_github_security_overview import (
    collect_security_overview,
    decode_paginated_json,
    load_profile_scope,
)


class SecurityOverviewCollectorTests(unittest.TestCase):
    def test_collects_counts_without_repo_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = load_profile_scope(write_profile(tmp))
            calls = []

            def fake_count(owner, repo, alert_class):
                calls.append((owner, repo, alert_class))
                if repo == "example-api" and alert_class == "dependabot":
                    return 2, False
                if repo == "example-api" and alert_class == "code_scanning":
                    return 1, False
                if repo == "example-cli" and alert_class == "secret_scanning":
                    return 1, True
                return 0, False

            overview = collect_security_overview(
                profile,
                count_client=fake_count,
                now=datetime(2026, 5, 1, 13, 5, tzinfo=timezone.utc),
            )

        self.assertEqual(overview["generated_at"], "2026-05-01T13:05:00Z")
        self.assertEqual(
            overview["open_alert_counts"],
            {"dependabot": 2, "code_scanning": 1, "secret_scanning": 1, "total": 4},
        )
        self.assertEqual(overview["unavailable_queries"]["total"], 1)
        self.assertEqual(
            calls,
            [
                ("acme", "example-api", "dependabot"),
                ("acme", "example-api", "code_scanning"),
                ("acme", "example-cli", "secret_scanning"),
            ],
        )
        serialized = json.dumps(overview)
        self.assertNotIn("example-api", serialized)
        self.assertNotIn("example-cli", serialized)

    def test_decode_paginated_json_handles_concatenated_arrays(self):
        pages = decode_paginated_json('[{"id": 1}]\n[{"id": 2}, {"id": 3}]\n[]\n')

        self.assertEqual([len(page) for page in pages], [1, 2, 0])


def write_profile(tmp):
    profile = Path(tmp) / "profile.yaml"
    profile.write_text(
        "\n".join(
            [
                "profile:",
                "  profile_id: acme-local",
                "  owner: acme",
                "  defaults:",
                "    automation_mode: active",
                "    mutation_mode: pull_request",
                "",
                "repositories:",
                "  - repo: example-api",
                "    automation_mode: active",
                "    targets:",
                "      - target_id: root",
                "        alert_classes:",
                "          - dependabot",
                "          - code_scanning",
                "  - repo: example-cli",
                "    automation_mode: manual_only",
                "    targets:",
                "      - target_id: root",
                "        alert_classes:",
                "          - secret_scanning",
                "  - repo: example-docs",
                "    automation_mode: ignored",
                "    targets:",
                "      - target_id: root",
                "        alert_classes:",
                "          - dependabot",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return profile


if __name__ == "__main__":
    unittest.main()
