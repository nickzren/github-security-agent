#!/usr/bin/env python3
"""Discover remediation units and profile coverage gaps for one profile.

Read-only pre-flight pass: enumerates open alerts, groups them into
remediation units keyed by the operating-model dedup key, assigns a static
triage status + reason, and reports profile coverage gaps. Never verifies,
merges, or mutates anything. See docs/discovery-model.md.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

try:
    from scripts.gh_security import alert_repository_name, decode_paginated_json, fetch_alerts
except ImportError:
    from gh_security import alert_repository_name, decode_paginated_json, fetch_alerts

ALERT_CLASSES = ("dependabot", "code_scanning", "secret_scanning")


@dataclass(frozen=True)
class ProfileModel:
    owner: str
    owner_type: str
    profile_id: str
    default_base_branch: str | None
    protected_manual: frozenset[str]
    allowlisted_rules: frozenset[str]
    repositories: dict[str, dict]


def _unset_if_auto(value: Any) -> str | None:
    if isinstance(value, str) and value and value != "auto":
        return value
    return None


def parse_profile_document(document: dict) -> ProfileModel:
    profile = document.get("profile") or {}
    defaults = profile.get("defaults") or {}
    code_scanning = defaults.get("code_scanning") or {}
    repositories = {
        str(entry.get("repo", "")).lower(): entry
        for entry in document.get("repositories") or []
    }
    return ProfileModel(
        owner=str(profile.get("owner", "")),
        owner_type=str(profile.get("owner_type", "org")),
        profile_id=str(profile.get("profile_id", "unknown")),
        default_base_branch=_unset_if_auto(defaults.get("default_base_branch")),
        protected_manual=frozenset(
            str(name).lower() for name in defaults.get("protected_manual_repositories") or []
        ),
        allowlisted_rules=frozenset(code_scanning.get("allowlisted_rules") or []),
        repositories=repositories,
    )


def resolve_base_branch(repo_default: Any, profile_default: Any, github_default: Any) -> str:
    for candidate in (repo_default, profile_default, github_default):
        resolved = _unset_if_auto(candidate)
        if resolved:
            return resolved
    return "unknown"


def summarize_alert(alert: dict, alert_class: str) -> dict:
    """Sanitized alert record. Never include paths, payloads, or secret data."""
    if alert_class == "dependabot":
        advisory = alert.get("security_advisory") or {}
        package = (alert.get("dependency") or {}).get("package") or {}
        ghsa = advisory.get("ghsa_id")
        return {
            "number": alert.get("number"),
            "advisory_ids": [ghsa] if ghsa else [],
            "package": package.get("name"),
            "severity": advisory.get("severity"),
        }
    if alert_class == "code_scanning":
        rule = alert.get("rule") or {}
        return {
            "number": alert.get("number"),
            "rule_id": rule.get("id"),
            "severity": rule.get("security_severity_level") or rule.get("severity"),
        }
    return {"number": alert.get("number")}


def alert_mapping_path(alert: dict, alert_class: str) -> str:
    """Internal-only path used for target mapping; never emitted in output."""
    if alert_class == "dependabot":
        return str((alert.get("dependency") or {}).get("manifest_path") or "")
    if alert_class == "code_scanning":
        instance = alert.get("most_recent_instance") or {}
        return str((instance.get("location") or {}).get("path") or "")
    return ""


def _path_matches(target_path: str, alert_path: str) -> bool:
    if target_path in ("", "."):
        return True
    return alert_path == target_path or alert_path.startswith(target_path.rstrip("/") + "/")


def map_alert_to_target(alert: dict, alert_class: str, targets: list[dict]) -> dict | None:
    enabled = [t for t in targets if alert_class in (t.get("alert_classes") or [])]
    if not enabled:
        return None
    if alert_class == "secret_scanning":
        for target in enabled:
            if str(target.get("path", ".")) in ("", "."):
                return target
        return enabled[0]
    alert_path = alert_mapping_path(alert, alert_class)
    best = None
    best_length = -1
    for target in enabled:
        target_path = str(target.get("path", "."))
        if _path_matches(target_path, alert_path):
            length = 0 if target_path in ("", ".") else len(target_path)
            if length > best_length:
                best = target
                best_length = length
    return best


def triage_unit(
    repo_entry: dict,
    target: dict | None,
    alert_class: str,
    rule_id: str | None,
    profile: ProfileModel,
) -> tuple[str, str | None]:
    mode = repo_entry.get("automation_mode")
    name = str(repo_entry.get("repo", "")).lower()
    if mode == "ignored":
        return "ignored", "ignored_repository"
    if name in profile.protected_manual:
        return "manual_only", "protected_manual_repository"
    if mode == "manual_only":
        return "manual_only", "manual_only_repository"
    if target is None:
        return "unsupported", "target_alert_class_disabled"
    if alert_class == "dependabot" and not target.get("ecosystems"):
        return "unsupported", "unsupported_ecosystem"
    if alert_class == "code_scanning" and rule_id not in profile.allowlisted_rules:
        return "unsupported", "unsupported_rule"
    if not target.get("verification_commands"):
        return "unsupported", "verification_unavailable"
    return "actionable", None


def _dependabot_ecosystem(alert: dict) -> str | None:
    package = (alert.get("dependency") or {}).get("package") or {}
    return package.get("ecosystem")


def build_units(
    alerts_by_class: dict[str, list],
    profile: ProfileModel,
    repo_inventory: dict[str, dict],
) -> list[dict]:
    owner = profile.owner.lower()
    units: dict[str, dict] = {}
    for alert_class in ALERT_CLASSES:
        for alert in alerts_by_class.get(alert_class) or []:
            repo_l = alert_repository_name(alert)
            inventory_entry = repo_inventory.get(repo_l)
            if inventory_entry and inventory_entry.get("archived"):
                continue  # archived repos are always out of scope
            repo_entry = profile.repositories.get(repo_l)
            if repo_entry is None:
                continue  # unlisted repos surface as coverage gaps, not units
            targets = repo_entry.get("targets") or []
            target = map_alert_to_target(alert, alert_class, targets)
            target_id = str(target.get("target_id")) if target else "repository"
            base_branch = resolve_base_branch(
                repo_entry.get("default_base_branch"),
                profile.default_base_branch,
                (inventory_entry or {}).get("default_branch"),
            )
            key = f"{owner}/{repo_l}|{alert_class}|{base_branch}|{target_id}"
            rule_id = None
            if alert_class == "code_scanning":
                rule_id = (alert.get("rule") or {}).get("id")
                key = f"{key}|{rule_id}"
            elif alert_class == "secret_scanning":
                key = f"{key}|{alert.get('number')}"
            unit = units.get(key)
            if unit is None:
                status, reason = triage_unit(repo_entry, target, alert_class, rule_id, profile)
                unit = {
                    "remediation_key": key,
                    "repository": str(repo_entry.get("repo", repo_l)),
                    "alert_class": alert_class,
                    "base_branch": base_branch,
                    "target_id": target_id,
                    "ecosystem": _dependabot_ecosystem(alert) if alert_class == "dependabot" else None,
                    "triage_status": status,
                    "triage_reason": reason,
                    "alert_count": 0,
                    "alerts": [],
                }
                units[key] = unit
            unit["alerts"].append(summarize_alert(alert, alert_class))
            unit["alert_count"] = len(unit["alerts"])
    for unit in units.values():
        unit["alerts"].sort(key=lambda record: record.get("number") or 0)
    return sorted(units.values(), key=lambda unit: unit["remediation_key"])


def detect_coverage_gaps(
    profile: ProfileModel,
    repo_inventory: dict[str, dict],
    alerts_by_class: dict[str, list],
) -> list[dict]:
    open_alerts_per_repo: dict[str, int] = {}
    for alerts in alerts_by_class.values():
        for alert in alerts or []:
            repo_l = alert_repository_name(alert)
            open_alerts_per_repo[repo_l] = open_alerts_per_repo.get(repo_l, 0) + 1

    gaps: list[dict] = []
    for repo_l, entry in repo_inventory.items():
        if entry.get("archived"):
            continue
        if repo_l not in profile.repositories:
            gaps.append(
                {
                    "repository": entry.get("name", repo_l),
                    "gap": "unlisted_repository",
                    "open_alert_count": open_alerts_per_repo.get(repo_l, 0),
                }
            )
    for repo_l, repo_entry in profile.repositories.items():
        display = str(repo_entry.get("repo", repo_l))
        inventory_entry = repo_inventory.get(repo_l)
        if inventory_entry is None:
            gaps.append({"repository": display, "gap": "profile_repository_missing_remote"})
        elif inventory_entry.get("archived") and repo_entry.get("automation_mode") in ("active", "manual_only"):
            gaps.append({"repository": display, "gap": "archived_in_profile"})
    return sorted(gaps, key=lambda gap: (gap["repository"].lower(), gap["gap"]))


def assemble_report(
    profile: ProfileModel,
    units: list[dict],
    gaps: list[dict],
    fetch_issues: list[dict],
    generated_at: str,
) -> dict:
    by_status = {"actionable": 0, "manual_only": 0, "ignored": 0, "unsupported": 0}
    by_alert_class = {alert_class: 0 for alert_class in ALERT_CLASSES}
    for unit in units:
        by_status[unit["triage_status"]] += 1
        by_alert_class[unit["alert_class"]] += 1
    gap_counts = {
        "unlisted_with_alerts": 0,
        "unlisted_no_alerts": 0,
        "archived_in_profile": 0,
        "profile_repository_missing_remote": 0,
    }
    for gap in gaps:
        if gap["gap"] == "unlisted_repository":
            if gap.get("open_alert_count"):
                gap_counts["unlisted_with_alerts"] += 1
            else:
                gap_counts["unlisted_no_alerts"] += 1
        else:
            gap_counts[gap["gap"]] += 1
    sorted_issues = sorted(fetch_issues, key=lambda issue: (issue["repository"], issue["alert_class"]))
    return {
        "generated_at": generated_at,
        "schema_version": 1,
        "owner": profile.owner.lower(),
        "owner_type": profile.owner_type,
        "profile_id": profile.profile_id,
        "summary": {
            "units_total": len(units),
            "alerts_total": sum(unit["alert_count"] for unit in units),
            "by_status": by_status,
            "by_alert_class": by_alert_class,
            "coverage_gaps": gap_counts,
            "fetch_issues": len(sorted_issues),
        },
        "remediation_units": units,
        "coverage_gaps": gaps,
        "fetch_issues": sorted_issues,
    }


def load_profile(path: Path) -> ProfileModel:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise RuntimeError(f"not a profile document: {path}")
    return parse_profile_document(document)


def fetch_repo_inventory(owner: str, run=subprocess.run) -> dict[str, dict]:
    result = run(
        ["gh", "repo", "list", owner, "--json", "name,isArchived,defaultBranchRef", "--limit", "1000"],
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"gh repo list failed: {result.stderr.strip()}")
    inventory: dict[str, dict] = {}
    for entry in json.loads(result.stdout or "[]"):
        name = str(entry.get("name", ""))
        branch_ref = entry.get("defaultBranchRef") or {}
        inventory[name.lower()] = {
            "name": name,
            "archived": bool(entry.get("isArchived")),
            "default_branch": branch_ref.get("name") if isinstance(branch_ref, dict) else None,
        }
    return inventory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--owner", help="defaults to the profile owner")
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None, run=subprocess.run) -> int:
    args = build_parser().parse_args(argv)
    try:
        profile = load_profile(args.profile)
        owner = args.owner or profile.owner
        inventory = fetch_repo_inventory(owner, run=run)
        user_repos = sorted(
            repo["name"] for repo in inventory.values() if not repo["archived"]
        )
        alerts_by_class: dict[str, list] = {}
        fetch_issues: list[dict] = []
        for alert_class in ALERT_CLASSES:
            alerts, issues = fetch_alerts(
                owner,
                alert_class,
                owner_type=profile.owner_type,
                repos=user_repos if profile.owner_type == "user" else None,
                run=run,
            )
            alerts_by_class[alert_class] = alerts
            fetch_issues.extend(issues)
        units = build_units(alerts_by_class, profile, inventory)
        gaps = detect_coverage_gaps(profile, inventory, alerts_by_class)
        report = assemble_report(
            profile,
            units,
            gaps,
            fetch_issues,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
    except (OSError, RuntimeError, yaml.YAMLError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
