#!/usr/bin/env python3
"""Tests for remediation-unit discovery."""

from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import yaml
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.discover_remediation_units import (
    alert_mapping_path,
    assemble_report,
    build_units,
    detect_coverage_gaps,
    fetch_repo_inventory,
    main,
    map_alert_to_target,
    parse_profile_document,
    resolve_base_branch,
    summarize_alert,
    triage_unit,
)


def make_target(**overrides) -> dict:
    target = {
        "target_id": "root",
        "path": ".",
        "alert_classes": ["dependabot", "code_scanning", "secret_scanning"],
        "ecosystems": ["uv"],
        "verification_commands": ["true"],
    }
    target.update(overrides)
    return target


def make_document() -> dict:
    return {
        "profile": {
            "profile_id": "test-profile",
            "owner": "Acme",
            "owner_type": "org",
            "defaults": {
                "default_base_branch": "auto",
                "protected_manual_repositories": ["Locked"],
                "code_scanning": {
                    "allowlisted_rules": ["actions/missing-workflow-permissions"],
                    "auto_merge_rules": ["actions/missing-workflow-permissions"],
                },
            },
        },
        "repositories": [
            {"repo": "Widget", "automation_mode": "active", "default_base_branch": "main", "targets": [make_target()]},
            {"repo": "Locked", "automation_mode": "manual_only", "targets": [make_target(verification_commands=[])]},
        ],
    }


class ParseProfileTests(unittest.TestCase):
    def test_parses_owner_defaults_and_repositories(self) -> None:
        profile = parse_profile_document(make_document())

        self.assertEqual(profile.owner, "Acme")
        self.assertEqual(profile.owner_type, "org")
        self.assertEqual(profile.profile_id, "test-profile")
        self.assertIsNone(profile.default_base_branch)  # auto -> unset
        self.assertEqual(profile.protected_manual, frozenset({"locked"}))
        self.assertEqual(profile.allowlisted_rules, frozenset({"actions/missing-workflow-permissions"}))
        self.assertEqual(set(profile.repositories), {"widget", "locked"})
        self.assertEqual(profile.repositories["widget"]["repo"], "Widget")

    def test_concrete_profile_default_base_branch_is_kept(self) -> None:
        document = make_document()
        document["profile"]["defaults"]["default_base_branch"] = "develop"

        self.assertEqual(parse_profile_document(document).default_base_branch, "develop")


class ResolveBaseBranchTests(unittest.TestCase):
    def test_repo_override_wins(self) -> None:
        self.assertEqual(resolve_base_branch("release", "develop", "main"), "release")

    def test_profile_default_used_when_repo_is_auto(self) -> None:
        self.assertEqual(resolve_base_branch("auto", "develop", "main"), "develop")

    def test_github_default_used_when_everything_is_auto(self) -> None:
        self.assertEqual(resolve_base_branch("auto", None, "trunk"), "trunk")

    def test_unknown_when_no_source_available(self) -> None:
        self.assertEqual(resolve_base_branch(None, "auto", None), "unknown")


DEPENDABOT_ALERT = {
    "number": 29,
    "repository": {"name": "widget"},
    "dependency": {"manifest_path": "analysis/uv.lock", "package": {"ecosystem": "pip", "name": "torch"}},
    "security_advisory": {"ghsa_id": "GHSA-rrmf-rvhw-rf47", "severity": "high", "description": "SECRET-ish text"},
}

CODE_SCANNING_ALERT = {
    "number": 5,
    "repository": {"name": "widget"},
    "rule": {"id": "actions/missing-workflow-permissions", "security_severity_level": "medium"},
    "most_recent_instance": {"location": {"path": ".github/workflows/ci.yml"}},
}

SECRET_ALERT = {
    "number": 7,
    "repository": {"name": "widget"},
    "secret_type": "github_personal_access_token",
    "locations_url": "https://api.github.com/...",
}


class SummarizeAlertTests(unittest.TestCase):
    def test_dependabot_record_is_minimal(self) -> None:
        record = summarize_alert(DEPENDABOT_ALERT, "dependabot")

        self.assertEqual(
            record,
            {"number": 29, "advisory_ids": ["GHSA-rrmf-rvhw-rf47"], "package": "torch", "severity": "high"},
        )

    def test_code_scanning_record_has_no_path(self) -> None:
        record = summarize_alert(CODE_SCANNING_ALERT, "code_scanning")

        self.assertEqual(record, {"number": 5, "rule_id": "actions/missing-workflow-permissions", "severity": "medium"})

    def test_secret_scanning_record_is_number_only(self) -> None:
        self.assertEqual(summarize_alert(SECRET_ALERT, "secret_scanning"), {"number": 7})


class TargetMappingTests(unittest.TestCase):
    def test_mapping_paths_per_class(self) -> None:
        self.assertEqual(alert_mapping_path(DEPENDABOT_ALERT, "dependabot"), "analysis/uv.lock")
        self.assertEqual(alert_mapping_path(CODE_SCANNING_ALERT, "code_scanning"), ".github/workflows/ci.yml")
        self.assertEqual(alert_mapping_path(SECRET_ALERT, "secret_scanning"), "")

    def test_longest_path_prefix_wins(self) -> None:
        root = make_target(target_id="root", path=".")
        analysis = make_target(target_id="analysis", path="analysis")

        chosen = map_alert_to_target(DEPENDABOT_ALERT, "dependabot", [root, analysis])

        self.assertEqual(chosen["target_id"], "analysis")

    def test_falls_back_to_root_when_no_specific_match(self) -> None:
        root = make_target(target_id="root", path=".")
        ui = make_target(target_id="ui", path="ui")

        chosen = map_alert_to_target(DEPENDABOT_ALERT, "dependabot", [root, ui])

        self.assertEqual(chosen["target_id"], "root")

    def test_secret_alert_prefers_root_target(self) -> None:
        analysis = make_target(target_id="analysis", path="analysis")
        root = make_target(target_id="root", path=".")

        chosen = map_alert_to_target(SECRET_ALERT, "secret_scanning", [analysis, root])

        self.assertEqual(chosen["target_id"], "root")

    def test_secret_alert_uses_first_enabled_target_without_root(self) -> None:
        analysis = make_target(target_id="analysis", path="analysis")
        pipeline = make_target(target_id="pipeline", path="data_pipeline")

        chosen = map_alert_to_target(SECRET_ALERT, "secret_scanning", [analysis, pipeline])

        self.assertEqual(chosen["target_id"], "analysis")

    def test_returns_none_when_no_target_enables_class(self) -> None:
        docs_only = make_target(target_id="root", alert_classes=["secret_scanning"])

        self.assertIsNone(map_alert_to_target(DEPENDABOT_ALERT, "dependabot", [docs_only]))


def make_profile(repositories, protected=None, owner="acme", owner_type="org"):
    return parse_profile_document(
        {
            "profile": {
                "profile_id": "test-profile",
                "owner": owner,
                "owner_type": owner_type,
                "defaults": {
                    "default_base_branch": "auto",
                    "protected_manual_repositories": protected or [],
                    "code_scanning": {"allowlisted_rules": ["actions/missing-workflow-permissions"]},
                },
            },
            "repositories": repositories,
        }
    )


def make_inventory(*names, archived=(), default_branch="main"):
    inventory = {}
    for name in names:
        inventory[name.lower()] = {
            "name": name,
            "archived": name in archived,
            "default_branch": default_branch,
        }
    return inventory


def dependabot_alert(repo, number, path="uv.lock", package="torch", ghsa="GHSA-x", severity="high"):
    return {
        "number": number,
        "repository": {"name": repo},
        "dependency": {"manifest_path": path, "package": {"ecosystem": "pip", "name": package}},
        "security_advisory": {"ghsa_id": ghsa, "severity": severity},
    }


class BuildUnitsTests(unittest.TestCase):
    def test_groups_dependabot_alerts_into_one_unit_per_target(self) -> None:
        profile = make_profile(
            [{"repo": "widget", "automation_mode": "active", "targets": [make_target()]}]
        )
        alerts = {
            "dependabot": [dependabot_alert("widget", 1, ghsa="GHSA-a"), dependabot_alert("widget", 2, ghsa="GHSA-b")],
            "code_scanning": [],
            "secret_scanning": [],
        }

        units = build_units(alerts, profile, make_inventory("widget"))

        self.assertEqual(len(units), 1)
        unit = units[0]
        self.assertEqual(unit["remediation_key"], "acme/widget|dependabot|main|root")
        self.assertEqual(unit["alert_count"], 2)
        self.assertEqual([a["number"] for a in unit["alerts"]], [1, 2])
        self.assertEqual(unit["ecosystem"], "pip")
        self.assertEqual(unit["base_branch"], "main")
        self.assertEqual(unit["triage_status"], "actionable")
        self.assertIsNone(unit["triage_reason"])

    def test_code_scanning_key_includes_rule_and_secret_key_includes_number(self) -> None:
        profile = make_profile(
            [{"repo": "widget", "automation_mode": "active", "targets": [make_target()]}]
        )
        alerts = {
            "dependabot": [],
            "code_scanning": [dict(CODE_SCANNING_ALERT)],
            "secret_scanning": [dict(SECRET_ALERT), dict(SECRET_ALERT, number=8)],
        }

        units = build_units(alerts, profile, make_inventory("widget"))

        keys = [unit["remediation_key"] for unit in units]
        self.assertIn("acme/widget|code_scanning|main|root|actions/missing-workflow-permissions", keys)
        self.assertIn("acme/widget|secret_scanning|main|root|7", keys)
        self.assertIn("acme/widget|secret_scanning|main|root|8", keys)
        self.assertEqual(len(units), 3)

    def test_archived_and_unlisted_repos_produce_no_units(self) -> None:
        profile = make_profile(
            [{"repo": "old", "automation_mode": "active", "targets": [make_target()]}]
        )
        alerts = {
            "dependabot": [dependabot_alert("old", 1), dependabot_alert("mystery", 2)],
            "code_scanning": [],
            "secret_scanning": [],
        }

        units = build_units(alerts, profile, make_inventory("old", "mystery", archived=("old",)))

        self.assertEqual(units, [])

    def test_base_branch_falls_back_to_inventory_default(self) -> None:
        profile = make_profile(
            [{"repo": "widget", "automation_mode": "active", "default_base_branch": "auto", "targets": [make_target()]}]
        )
        alerts = {"dependabot": [dependabot_alert("widget", 1)], "code_scanning": [], "secret_scanning": []}

        units = build_units(alerts, profile, make_inventory("widget", default_branch="trunk"))

        self.assertEqual(units[0]["base_branch"], "trunk")

    def test_unmapped_alert_gets_repository_target_id(self) -> None:
        docs_only = make_target(alert_classes=["secret_scanning"])
        profile = make_profile(
            [{"repo": "widget", "automation_mode": "active", "targets": [docs_only]}]
        )
        alerts = {"dependabot": [dependabot_alert("widget", 1)], "code_scanning": [], "secret_scanning": []}

        units = build_units(alerts, profile, make_inventory("widget"))

        self.assertEqual(units[0]["target_id"], "repository")
        self.assertEqual(units[0]["triage_status"], "unsupported")
        self.assertEqual(units[0]["triage_reason"], "target_alert_class_disabled")


class TriageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = make_profile(
            [
                {"repo": "ig", "automation_mode": "ignored", "targets": []},
                {"repo": "man", "automation_mode": "manual_only", "targets": [make_target()]},
                {"repo": "prot", "automation_mode": "manual_only", "targets": [make_target()]},
                {"repo": "active", "automation_mode": "active", "targets": [make_target()]},
            ],
            protected=["prot"],
        )

    def _entry(self, name):
        return self.profile.repositories[name]

    def test_ignored_repository(self) -> None:
        self.assertEqual(
            triage_unit(self._entry("ig"), None, "dependabot", None, self.profile),
            ("ignored", "ignored_repository"),
        )

    def test_protected_manual_beats_plain_manual(self) -> None:
        self.assertEqual(
            triage_unit(self._entry("prot"), make_target(), "dependabot", None, self.profile),
            ("manual_only", "protected_manual_repository"),
        )
        self.assertEqual(
            triage_unit(self._entry("man"), make_target(), "dependabot", None, self.profile),
            ("manual_only", "manual_only_repository"),
        )

    def test_dependabot_without_ecosystems_is_unsupported(self) -> None:
        target = make_target(ecosystems=[])
        self.assertEqual(
            triage_unit(self._entry("active"), target, "dependabot", None, self.profile),
            ("unsupported", "unsupported_ecosystem"),
        )

    def test_code_scanning_rule_not_allowlisted(self) -> None:
        self.assertEqual(
            triage_unit(self._entry("active"), make_target(), "code_scanning", "py/sql-injection", self.profile),
            ("unsupported", "unsupported_rule"),
        )

    def test_active_target_without_verification_is_unsupported(self) -> None:
        target = make_target(verification_commands=[])
        self.assertEqual(
            triage_unit(self._entry("active"), target, "dependabot", None, self.profile),
            ("unsupported", "verification_unavailable"),
        )

    def test_actionable(self) -> None:
        self.assertEqual(
            triage_unit(self._entry("active"), make_target(), "code_scanning", "actions/missing-workflow-permissions", self.profile),
            ("actionable", None),
        )


class CoverageGapTests(unittest.TestCase):
    def test_detects_all_three_gap_kinds(self) -> None:
        profile = make_profile(
            [
                {"repo": "widget", "automation_mode": "active", "targets": [make_target()]},
                {"repo": "old", "automation_mode": "manual_only", "targets": [make_target()]},
                {"repo": "ghost", "automation_mode": "active", "targets": [make_target()]},
            ]
        )
        inventory = make_inventory("widget", "old", "newbie", "fresh", archived=("old",))
        alerts = {"dependabot": [dependabot_alert("newbie", 1)], "code_scanning": [], "secret_scanning": []}

        gaps = detect_coverage_gaps(profile, inventory, alerts)

        self.assertEqual(
            gaps,
            [
                {"repository": "fresh", "gap": "unlisted_repository", "open_alert_count": 0},
                {"repository": "ghost", "gap": "profile_repository_missing_remote"},
                {"repository": "newbie", "gap": "unlisted_repository", "open_alert_count": 1},
                {"repository": "old", "gap": "archived_in_profile"},
            ],
        )

    def test_ignored_profile_entries_are_not_archived_gaps(self) -> None:
        profile = make_profile([{"repo": "junk", "automation_mode": "ignored", "targets": []}])
        inventory = make_inventory("junk", archived=("junk",))

        gaps = detect_coverage_gaps(profile, inventory, {"dependabot": [], "code_scanning": [], "secret_scanning": []})

        self.assertEqual(gaps, [])


class AssembleReportTests(unittest.TestCase):
    def test_summary_reconciles_with_records(self) -> None:
        profile = make_profile(
            [{"repo": "widget", "automation_mode": "active", "targets": [make_target()]}]
        )
        alerts = {
            "dependabot": [dependabot_alert("widget", 1), dependabot_alert("widget", 2)],
            "code_scanning": [],
            "secret_scanning": [dict(SECRET_ALERT, repository={"name": "widget"})],
        }
        inventory = make_inventory("widget", "newbie")
        units = build_units(alerts, profile, inventory)
        gaps = detect_coverage_gaps(profile, inventory, alerts)
        issues = [{"repository": "widget", "alert_class": "code_scanning", "http_status": 403, "detail": "disabled"}]

        report = assemble_report(profile, units, gaps, issues, generated_at="2026-07-07T00:00:00+00:00")

        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["owner"], "acme")
        self.assertEqual(report["owner_type"], "org")
        self.assertEqual(report["profile_id"], "test-profile")
        self.assertEqual(report["generated_at"], "2026-07-07T00:00:00+00:00")
        summary = report["summary"]
        self.assertEqual(summary["units_total"], 2)
        self.assertEqual(summary["alerts_total"], 3)
        self.assertEqual(summary["by_status"], {"actionable": 2, "manual_only": 0, "ignored": 0, "unsupported": 0})
        self.assertEqual(summary["by_alert_class"], {"dependabot": 1, "code_scanning": 0, "secret_scanning": 1})
        self.assertEqual(
            summary["coverage_gaps"],
            {
                "unlisted_with_alerts": 0,
                "unlisted_no_alerts": 1,
                "archived_in_profile": 0,
                "profile_repository_missing_remote": 0,
            },
        )
        self.assertEqual(summary["fetch_issues"], 1)
        self.assertEqual(report["remediation_units"], units)
        self.assertEqual(report["coverage_gaps"], gaps)
        self.assertEqual(report["fetch_issues"], issues)


def gh_fake_run(responses):
    def fake_run(cmd, check=False, text=True, capture_output=True):
        command = " ".join(cmd)
        for substring, returncode, stdout, stderr in responses:
            if substring in command:
                return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)
        return subprocess.CompletedProcess(cmd, 0, "[]", "")

    return fake_run


class ShellTests(unittest.TestCase):
    def test_fetch_repo_inventory_parses_gh_repo_list(self) -> None:
        payload = json.dumps(
            [
                {"name": "Widget", "isArchived": False, "defaultBranchRef": {"name": "trunk"}},
                {"name": "old", "isArchived": True, "defaultBranchRef": None},
            ]
        )
        run = gh_fake_run([("gh repo list acme", 0, payload, "")])

        inventory = fetch_repo_inventory("acme", run=run)

        self.assertEqual(
            inventory,
            {
                "widget": {"name": "Widget", "archived": False, "default_branch": "trunk"},
                "old": {"name": "old", "archived": True, "default_branch": None},
            },
        )

    def test_main_writes_report_for_org_profile(self) -> None:
        document = {
            "profile": {
                "profile_id": "test-profile",
                "owner": "acme",
                "owner_type": "org",
                "defaults": {"default_base_branch": "auto", "protected_manual_repositories": []},
            },
            "repositories": [
                {"repo": "widget", "automation_mode": "active", "targets": [make_target()]}
            ],
        }
        inventory_payload = json.dumps([{"name": "widget", "isArchived": False, "defaultBranchRef": {"name": "main"}}])
        alert_payload = json.dumps([dependabot_alert("widget", 1)])
        run = gh_fake_run(
            [
                ("gh repo list acme", 0, inventory_payload, ""),
                ("/orgs/acme/dependabot/alerts", 0, alert_payload, ""),
                ("/orgs/acme/code-scanning/alerts", 0, "[]", ""),
                ("/orgs/acme/secret-scanning/alerts", 0, "[]", ""),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "profile.yaml"
            profile_path.write_text(yaml.safe_dump(document), encoding="utf-8")
            output_path = Path(tmp) / "worklist.json"

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = main(["--profile", str(profile_path), "--output", str(output_path)], run=run)

            report = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(report["summary"]["units_total"], 1)
        self.assertEqual(report["remediation_units"][0]["repository"], "widget")

    def test_main_returns_one_when_org_endpoint_fails(self) -> None:
        document = {
            "profile": {"profile_id": "p", "owner": "acme", "owner_type": "org", "defaults": {}},
            "repositories": [],
        }
        run = gh_fake_run([("/orgs/acme/dependabot/alerts", 1, "", "gh: boom (HTTP 500)")])
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "profile.yaml"
            profile_path.write_text(yaml.safe_dump(document), encoding="utf-8")

            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                exit_code = main(["--profile", str(profile_path)], run=run)

        self.assertEqual(exit_code, 1)

    def test_main_user_profile_iterates_repos_and_records_issues(self) -> None:
        document = {
            "profile": {"profile_id": "p", "owner": "nick", "owner_type": "user", "defaults": {}},
            "repositories": [
                {"repo": "alpha", "automation_mode": "active", "targets": [make_target()]}
            ],
        }
        inventory_payload = json.dumps([{"name": "alpha", "isArchived": False, "defaultBranchRef": {"name": "main"}}])
        run = gh_fake_run(
            [
                ("gh repo list nick", 0, inventory_payload, ""),
                ("/repos/nick/alpha/dependabot/alerts", 0, json.dumps([dependabot_alert("alpha", 4)]), ""),
                ("/repos/nick/alpha/code-scanning/alerts", 1, "", "gh: Code security must be enabled. (HTTP 403)"),
                ("/repos/nick/alpha/secret-scanning/alerts", 0, "[]", ""),
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "profile.yaml"
            profile_path.write_text(yaml.safe_dump(document), encoding="utf-8")
            output_path = Path(tmp) / "worklist.json"

            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = main(["--profile", str(profile_path), "--output", str(output_path)], run=run)

            report = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(report["summary"]["units_total"], 1)
        self.assertEqual(report["summary"]["fetch_issues"], 1)
        self.assertEqual(report["fetch_issues"][0]["http_status"], 403)


if __name__ == "__main__":
    unittest.main()
