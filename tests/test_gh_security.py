#!/usr/bin/env python3
"""Tests for shared GitHub security fetch helpers."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.gh_security import fetch_alerts


def fake_run_factory(responses):
    """responses: list of (substring_of_command, returncode, stdout, stderr)."""
    calls = []

    def fake_run(cmd, check=False, text=True, capture_output=True):
        command = " ".join(cmd)
        calls.append(command)
        for substring, returncode, stdout, stderr in responses:
            if substring in command:
                return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)
        return subprocess.CompletedProcess(cmd, 0, "[]", "")

    fake_run.calls = calls
    return fake_run


class FetchAlertsTests(unittest.TestCase):
    def test_org_fetch_uses_org_endpoint_and_returns_alerts(self) -> None:
        run = fake_run_factory(
            [("/orgs/acme/dependabot/alerts", 0, '[{"number": 1, "repository": {"name": "widget"}}]', "")]
        )

        alerts, issues = fetch_alerts("acme", "dependabot", owner_type="org", run=run)

        self.assertEqual([alert["number"] for alert in alerts], [1])
        self.assertEqual(issues, [])
        self.assertTrue(any("/orgs/acme/dependabot/alerts" in call for call in run.calls))

    def test_org_fetch_failure_raises(self) -> None:
        run = fake_run_factory([("/orgs/acme/dependabot/alerts", 1, "", "gh: boom (HTTP 500)")])

        with self.assertRaises(RuntimeError):
            fetch_alerts("acme", "dependabot", owner_type="org", run=run)

    def test_user_fetch_iterates_repos_and_attaches_repository(self) -> None:
        run = fake_run_factory(
            [
                ("/repos/nick/alpha/dependabot/alerts", 0, '[{"number": 3}]', ""),
                ("/repos/nick/beta/dependabot/alerts", 0, "[]", ""),
            ]
        )

        alerts, issues = fetch_alerts("nick", "dependabot", owner_type="user", repos=["alpha", "beta"], run=run)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["repository"], {"name": "alpha"})
        self.assertEqual(issues, [])

    def test_user_fetch_records_issue_on_403_and_continues(self) -> None:
        run = fake_run_factory(
            [
                (
                    "/repos/nick/alpha/code-scanning/alerts",
                    1,
                    "",
                    "gh: Code security must be enabled for this repository to use code scanning. (HTTP 403)",
                ),
                ("/repos/nick/beta/code-scanning/alerts", 0, '[{"number": 9}]', ""),
            ]
        )

        alerts, issues = fetch_alerts("nick", "code_scanning", owner_type="user", repos=["alpha", "beta"], run=run)

        self.assertEqual([alert["number"] for alert in alerts], [9])
        self.assertEqual(
            issues,
            [
                {
                    "repository": "alpha",
                    "alert_class": "code_scanning",
                    "http_status": 403,
                    "detail": "Code security must be enabled for this repository to use code scanning.",
                }
            ],
        )

    def test_unknown_owner_type_raises(self) -> None:
        run = fake_run_factory([])

        with self.assertRaises(RuntimeError):
            fetch_alerts("acme", "dependabot", owner_type="organization", run=run)

    def test_user_transport_error_without_http_status_raises(self) -> None:
        run = fake_run_factory(
            [("/repos/nick/alpha/dependabot/alerts", 1, "", "gh: dial tcp: network is unreachable")]
        )

        with self.assertRaises(RuntimeError):
            fetch_alerts("nick", "dependabot", owner_type="user", repos=["alpha"], run=run)


if __name__ == "__main__":
    unittest.main()
