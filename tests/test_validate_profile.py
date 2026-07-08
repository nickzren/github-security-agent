#!/usr/bin/env python3
"""Tests for profile linting."""

from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.validate_profile import main, validate_profile_document


def make_target(
    target_id: str = "root",
    verification_commands: list[str] | None = None,
    alert_classes: list[str] | None = None,
    ecosystems: list[str] | None = None,
) -> dict:
    target = {
        "target_id": target_id,
        "verification_commands": ["true"] if verification_commands is None else verification_commands,
    }
    if alert_classes is not None:
        target["alert_classes"] = alert_classes
    if ecosystems is not None:
        target["ecosystems"] = ecosystems
    return target


def make_repo(
    name: str,
    mode: str = "active",
    targets: list[dict] | None = None,
    local_path: str | None = None,
) -> dict:
    entry = {
        "repo": name,
        "automation_mode": mode,
        "targets": [make_target()] if targets is None else targets,
    }
    if local_path is not None:
        entry["local_path"] = local_path
    return entry


def make_document(
    repositories: list[dict],
    protected_manual: list[str] | None = None,
    owner: str = "acme",
    owner_type: str | None = "org",
) -> dict:
    profile = {
        "profile_id": "test-profile",
        "owner": owner,
        "defaults": {"protected_manual_repositories": protected_manual or []},
    }
    if owner_type is not None:
        profile["owner_type"] = owner_type
    return {
        "profile": profile,
        "repositories": repositories,
    }


def violation_codes(violations) -> set[str]:
    return {violation.code for violation in violations}


class StructuralValidationTests(unittest.TestCase):
    def test_valid_profile_has_no_violations(self) -> None:
        document = make_document(
            [make_repo("alpha"), make_repo("beta", mode="manual_only", targets=[make_target(verification_commands=[])])],
            protected_manual=["beta"],
        )

        self.assertEqual(validate_profile_document(document), [])

    def test_active_repo_with_empty_verification_fails(self) -> None:
        document = make_document([make_repo("alpha", targets=[make_target(verification_commands=[])])])

        violations = validate_profile_document(document)

        self.assertEqual(violation_codes(violations), {"active_missing_verification"})
        self.assertEqual(violations[0].repo, "alpha")

    def test_active_repo_with_no_targets_fails(self) -> None:
        document = make_document([make_repo("alpha", targets=[])])

        self.assertEqual(
            violation_codes(validate_profile_document(document)),
            {"active_missing_verification"},
        )

    def test_manual_only_and_ignored_repos_skip_verification_check(self) -> None:
        document = make_document(
            [
                make_repo("alpha", mode="manual_only", targets=[make_target(verification_commands=[])]),
                make_repo("beta", mode="ignored", targets=[make_target(verification_commands=[])]),
            ]
        )

        self.assertEqual(validate_profile_document(document), [])

    def test_duplicate_target_ids_fail(self) -> None:
        document = make_document(
            [make_repo("alpha", targets=[make_target("root"), make_target("root")])]
        )

        self.assertEqual(
            violation_codes(validate_profile_document(document)),
            {"duplicate_target_id"},
        )

    def test_duplicate_repository_entries_fail(self) -> None:
        document = make_document([make_repo("alpha"), make_repo("alpha")])

        self.assertEqual(
            violation_codes(validate_profile_document(document)),
            {"duplicate_repository_entry"},
        )

    def test_protected_manual_repo_missing_from_repositories_fails(self) -> None:
        document = make_document([make_repo("alpha")], protected_manual=["ghost"])

        violations = validate_profile_document(document)

        self.assertEqual(violation_codes(violations), {"protected_manual_missing_entry"})
        self.assertEqual(violations[0].repo, "ghost")

    def test_protected_manual_repo_not_manual_only_fails(self) -> None:
        document = make_document([make_repo("alpha")], protected_manual=["alpha"])

        self.assertEqual(
            violation_codes(validate_profile_document(document)),
            {"protected_manual_not_manual_only"},
        )

    def test_active_dependabot_target_without_ecosystems_fails(self) -> None:
        document = make_document(
            [make_repo("alpha", targets=[make_target(alert_classes=["dependabot"], ecosystems=[])])]
        )

        violations = validate_profile_document(document)

        self.assertEqual(violation_codes(violations), {"active_missing_ecosystems"})
        self.assertEqual(violations[0].repo, "alpha")

    def test_active_scanning_only_target_without_ecosystems_passes(self) -> None:
        document = make_document(
            [
                make_repo(
                    "alpha",
                    targets=[make_target(alert_classes=["code_scanning", "secret_scanning"], ecosystems=[])],
                )
            ]
        )

        self.assertEqual(validate_profile_document(document), [])

    def test_manual_only_dependabot_target_without_ecosystems_passes(self) -> None:
        document = make_document(
            [
                make_repo(
                    "alpha",
                    mode="manual_only",
                    targets=[make_target(alert_classes=["dependabot"], ecosystems=[])],
                )
            ]
        )

        self.assertEqual(validate_profile_document(document), [])

    def test_invalid_automation_mode_fails(self) -> None:
        document = make_document([make_repo("alpha", mode="actve")])

        self.assertEqual(
            violation_codes(validate_profile_document(document)),
            {"invalid_automation_mode"},
        )

    def test_invalid_owner_type_fails(self) -> None:
        document = make_document([make_repo("alpha")], owner_type="organization")

        violations = validate_profile_document(document)

        self.assertEqual(violation_codes(violations), {"invalid_owner_type"})
        self.assertEqual(violations[0].repo, "<profile>")

    def test_missing_owner_type_fails(self) -> None:
        document = make_document([make_repo("alpha")], owner_type=None)

        self.assertEqual(
            violation_codes(validate_profile_document(document)),
            {"invalid_owner_type"},
        )


class LocalValidationTests(unittest.TestCase):
    def test_local_checks_are_skipped_without_flag(self) -> None:
        document = make_document([make_repo("alpha", local_path="/nonexistent/path/alpha")])

        self.assertEqual(validate_profile_document(document), [])

    def test_missing_local_path_fails_with_local_checks(self) -> None:
        document = make_document([make_repo("alpha", local_path="/nonexistent/path/alpha")])

        self.assertEqual(
            violation_codes(validate_profile_document(document, check_local=True)),
            {"local_path_missing"},
        )

    def test_local_path_that_is_not_a_git_repository_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            document = make_document([make_repo("alpha", local_path=tmp)])

            self.assertEqual(
                violation_codes(validate_profile_document(document, check_local=True)),
                {"local_path_missing"},
            )

    def test_stale_remote_fails_with_local_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            subprocess.run(
                ["git", "-C", tmp, "remote", "add", "origin", "https://github.com/other/elsewhere.git"],
                check=True,
            )
            document = make_document([make_repo("alpha", local_path=tmp)])

            violations = validate_profile_document(document, check_local=True)

        self.assertEqual(violation_codes(violations), {"stale_remote"})
        self.assertEqual(violations[0].repo, "alpha")

    def test_matching_ssh_remote_with_different_case_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            subprocess.run(["git", "init", "-q", tmp], check=True)
            subprocess.run(
                ["git", "-C", tmp, "remote", "add", "origin", "git@github.com:Acme/Alpha.git"],
                check=True,
            )
            document = make_document([make_repo("alpha", local_path=tmp)])

            self.assertEqual(validate_profile_document(document, check_local=True), [])


def run_main(argv: list[str]) -> int:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return main(argv)


class CommandLineTests(unittest.TestCase):
    def test_main_returns_zero_for_valid_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "profile.yaml"
            profile_path.write_text(yaml.safe_dump(make_document([make_repo("alpha")])), encoding="utf-8")

            self.assertEqual(run_main([str(profile_path)]), 0)

    def test_main_returns_one_for_invalid_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "profile.yaml"
            document = make_document([make_repo("alpha", targets=[make_target(verification_commands=[])])])
            profile_path.write_text(yaml.safe_dump(document), encoding="utf-8")

            self.assertEqual(run_main([str(profile_path)]), 1)

    def test_main_returns_one_for_missing_profile_file(self) -> None:
        self.assertEqual(run_main(["/nonexistent/profile.yaml"]), 1)

    def test_main_returns_one_for_empty_profile_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile_path = Path(tmp) / "profile.yaml"
            profile_path.write_text("", encoding="utf-8")

            self.assertEqual(run_main([str(profile_path)]), 1)


if __name__ == "__main__":
    unittest.main()
