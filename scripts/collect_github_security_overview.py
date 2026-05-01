#!/usr/bin/env python3
"""Collect counts-only GitHub security alert totals for one profile."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    from scripts.run_report_only import SUPPORTED_ALERT_CLASSES, _load_yaml_subset, _repo_alert_classes
except ModuleNotFoundError:  # pragma: no cover - used when running from scripts/
    from run_report_only import SUPPORTED_ALERT_CLASSES, _load_yaml_subset, _repo_alert_classes


CountClient = Callable[[str, str, str], tuple[int, bool]]


@dataclass(frozen=True)
class RepositoryScope:
    repo: str
    alert_classes: tuple[str, ...]


@dataclass(frozen=True)
class ProfileScope:
    owner: str
    repositories: tuple[RepositoryScope, ...]


def load_profile_scope(path: str | Path) -> ProfileScope:
    data = _load_yaml_subset(Path(path))
    profile = data.get("profile") if isinstance(data, dict) else None
    if not isinstance(profile, dict):
        raise ValueError("profile section is required")
    owner = profile.get("owner")
    if not owner:
        raise ValueError("profile.owner is required")

    defaults = profile.get("defaults") if isinstance(profile.get("defaults"), dict) else {}
    default_mode = str(defaults.get("automation_mode") or "active")
    repositories: list[RepositoryScope] = []
    for entry in data.get("repositories") or []:
        if not isinstance(entry, dict) or not entry.get("repo"):
            continue
        mode = str(entry.get("automation_mode") or default_mode)
        if mode == "ignored":
            continue
        alert_classes = _repo_alert_classes(entry)
        if alert_classes:
            repositories.append(RepositoryScope(repo=str(entry["repo"]), alert_classes=alert_classes))

    return ProfileScope(owner=str(owner), repositories=tuple(repositories))


def collect_security_overview(
    profile: ProfileScope,
    *,
    count_client: CountClient,
    now: datetime | None = None,
) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    unavailable: Counter[str] = Counter()

    for repo in profile.repositories:
        for alert_class in repo.alert_classes:
            count, failed = count_client(profile.owner, repo.repo, alert_class)
            counts[alert_class] += count
            if failed:
                unavailable[alert_class] += 1

    open_counts = {alert_class: counts[alert_class] for alert_class in SUPPORTED_ALERT_CLASSES}
    unavailable_counts = {alert_class: unavailable[alert_class] for alert_class in SUPPORTED_ALERT_CLASSES}
    return {
        "schema_version": 1,
        "generated_at": _format_utc(now or datetime.now(timezone.utc)),
        "source": "github_profile_security_overview",
        "owner": profile.owner,
        "repo_scope": "profile",
        "open_alert_counts": {**open_counts, "total": sum(open_counts.values())},
        "unavailable_queries": {**unavailable_counts, "total": sum(unavailable_counts.values())},
    }


def fetch_open_alert_count(owner: str, repo: str, alert_class: str) -> tuple[int, bool]:
    endpoint = _alert_endpoint(owner, repo, alert_class)
    if not endpoint:
        return 0, False
    result = subprocess.run(
        ["gh", "api", "--paginate", endpoint],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return 0, True
    return sum(_page_length(page) for page in decode_paginated_json(result.stdout)), False


def decode_paginated_json(text: str) -> list[Any]:
    decoder = json.JSONDecoder()
    index = 0
    values: list[Any] = []
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        value, index = decoder.raw_decode(text, index)
        values.append(value)
    return values


def _alert_endpoint(owner: str, repo: str, alert_class: str) -> str:
    if alert_class == "dependabot":
        return f"/repos/{owner}/{repo}/dependabot/alerts?state=open&per_page=100"
    if alert_class == "code_scanning":
        return f"/repos/{owner}/{repo}/code-scanning/alerts?state=open&per_page=100"
    if alert_class == "secret_scanning":
        return f"/repos/{owner}/{repo}/secret-scanning/alerts?state=open&per_page=100"
    return ""


def _page_length(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return 1
    return 0


def _format_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc).replace(microsecond=0)
    return value.isoformat().replace("+00:00", "Z")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, help="Path to the selected profile.yaml")
    parser.add_argument("--output", type=Path, help="Write sanitized count JSON to this path")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    profile = load_profile_scope(args.profile)
    data = collect_security_overview(profile, count_client=fetch_open_alert_count)
    rendered = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
