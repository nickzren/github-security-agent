#!/usr/bin/env python3
"""Validate security-agent profiles against the operating-model contract.

Structural checks always run. Local-clone checks (--check-local) require the
profile's clones on disk, so CI runs structural-only and operator machines run
the full set.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

VALID_AUTOMATION_MODES = ("active", "manual_only", "ignored")
VALID_OWNER_TYPES = ("org", "user")


@dataclass
class Violation:
    profile_id: str
    repo: str
    code: str
    message: str


def validate_profile_document(document: dict, check_local: bool = False) -> list[Violation]:
    profile = document.get("profile") or {}
    profile_id = str(profile.get("profile_id", "unknown"))
    owner = str(profile.get("owner", ""))
    owner_type = profile.get("owner_type")
    defaults = profile.get("defaults") or {}
    repositories = document.get("repositories") or []
    violations: list[Violation] = []

    if owner_type not in VALID_OWNER_TYPES:
        violations.append(
            Violation(
                profile_id,
                "<profile>",
                "invalid_owner_type",
                f"profile.owner_type must be one of {VALID_OWNER_TYPES}, got {owner_type!r}",
            )
        )

    modes_by_repo: dict[str, str] = {}
    for entry in repositories:
        name = str(entry.get("repo", ""))
        mode = entry.get("automation_mode")

        if name in modes_by_repo:
            violations.append(
                Violation(profile_id, name, "duplicate_repository_entry", "repository is listed more than once")
            )
        modes_by_repo[name] = mode

        if mode not in VALID_AUTOMATION_MODES:
            violations.append(
                Violation(
                    profile_id,
                    name,
                    "invalid_automation_mode",
                    f"automation_mode must be one of {VALID_AUTOMATION_MODES}, got {mode!r}",
                )
            )

        targets = entry.get("targets") or []
        seen_target_ids = set()
        for target in targets:
            target_id = target.get("target_id")
            if target_id in seen_target_ids:
                violations.append(
                    Violation(profile_id, name, "duplicate_target_id", f"target_id {target_id!r} is not unique")
                )
            seen_target_ids.add(target_id)

            if (
                mode == "active"
                and "dependabot" in (target.get("alert_classes") or [])
                and not target.get("ecosystems")
            ):
                violations.append(
                    Violation(
                        profile_id,
                        name,
                        "active_missing_ecosystems",
                        f"target {target_id!r} enables dependabot but declares no ecosystems",
                    )
                )

        if mode == "active" and (
            not targets or any(not target.get("verification_commands") for target in targets)
        ):
            violations.append(
                Violation(
                    profile_id,
                    name,
                    "active_missing_verification",
                    "active repositories require verification_commands for every target",
                )
            )

        if check_local:
            violations.extend(_check_local_clone(profile_id, owner, entry))

    for name in defaults.get("protected_manual_repositories") or []:
        if name not in modes_by_repo:
            violations.append(
                Violation(
                    profile_id,
                    name,
                    "protected_manual_missing_entry",
                    "protected manual repository has no repository entry",
                )
            )
        elif modes_by_repo[name] != "manual_only":
            violations.append(
                Violation(
                    profile_id,
                    name,
                    "protected_manual_not_manual_only",
                    "protected manual repository must use automation_mode manual_only",
                )
            )

    return violations


def _check_local_clone(profile_id: str, owner: str, entry: dict) -> list[Violation]:
    name = str(entry.get("repo", ""))
    local_path = entry.get("local_path")
    if not local_path or not (Path(local_path) / ".git").exists():
        return [
            Violation(profile_id, name, "local_path_missing", f"local clone not found at {local_path}")
        ]

    result = subprocess.run(
        ["git", "-C", str(local_path), "remote", "get-url", "origin"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return [Violation(profile_id, name, "stale_remote", "origin remote is not configured")]

    url = result.stdout.strip()
    if not _remote_matches(url, owner, name):
        return [
            Violation(profile_id, name, "stale_remote", f"origin remote {url} does not match {owner}/{name}")
        ]
    return []


def _remote_matches(url: str, owner: str, name: str) -> bool:
    normalized = url.lower().rstrip("/")
    if normalized.endswith(".git"):
        normalized = normalized[: -len(".git")]
    normalized = normalized.replace(":", "/")
    return normalized.endswith(f"/{owner.lower()}/{name.lower()}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profiles", nargs="+", help="profile.yaml paths to validate")
    parser.add_argument(
        "--check-local",
        action="store_true",
        help="also validate local clone paths and origin remotes",
    )
    args = parser.parse_args(argv)

    exit_code = 0
    for profile_path in args.profiles:
        try:
            document = yaml.safe_load(Path(profile_path).read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            print(f"ERROR {profile_path}: unreadable profile: {error}", file=sys.stderr)
            exit_code = 1
            continue

        if not isinstance(document, dict):
            print(f"ERROR {profile_path}: not a profile document", file=sys.stderr)
            exit_code = 1
            continue

        violations = validate_profile_document(document, check_local=args.check_local)
        if violations:
            exit_code = 1
            for violation in violations:
                print(
                    f"ERROR {violation.profile_id} repo={violation.repo} "
                    f"{violation.code}: {violation.message}"
                )
            print(f"FAIL {profile_path}: {len(violations)} violations")
        else:
            print(f"OK {profile_path}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
