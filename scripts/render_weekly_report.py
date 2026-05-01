#!/usr/bin/env python3
"""Render a compact weekly GitHub issue body from github-security-agent latest.json."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_HEADING = "Weekly Security Report"


def load_latest_json(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("latest.json must contain a JSON object")
    return data


def render_weekly_report(summary: dict[str, Any], heading: str = DEFAULT_HEADING) -> str:
    units = list(_iter_units(summary))
    repo_counts = summary.get("repo_counts") or {}
    active_count = _first_int(repo_counts, "active", "active_repos", "active_repositories")
    manual_count = _first_int(repo_counts, "manual_only", "manual_only_repos", "manual_only_repositories")

    dependabot = _counts_for(units, "dependabot")
    code_scanning = _counts_for(units, "code_scanning")
    secret_scanning = _counts_for(units, "secret_scanning")
    manual_by_class = _manual_actions_by_class(units)

    lines = [
        f"## {heading}",
        "",
        (
            "Dependabot: "
            f"{dependabot['merged']} merged, "
            f"{dependabot['opened_pr']} PR, "
            f"{dependabot['blocked']} blocked"
        ),
        (
            "Code scanning: "
            f"{code_scanning['merged']} fixed, "
            f"{code_scanning['opened_pr']} PR, "
            f"{code_scanning['manual']} manual"
        ),
        (
            "Secret scanning: "
            f"{secret_scanning['opened_pr']} cleanup PR, "
            f"{secret_scanning['manual']} manual"
        ),
        "",
    ]

    if manual_by_class:
        lines.append("Manual attention:")
        for alert_class in ("dependabot", "code_scanning", "secret_scanning"):
            count = manual_by_class.get(alert_class, 0)
            if count:
                lines.append(f"- {_class_label(alert_class)}: {count}")
        for alert_class, count in sorted(manual_by_class.items()):
            if alert_class not in {"dependabot", "code_scanning", "secret_scanning"}:
                lines.append(f"- {_class_label(alert_class)}: {count}")
        lines.append("")
    else:
        lines.append(f"manual repos: {manual_count} checked, no current reportable alerts")
        lines.append("")

    lines.append("Notes:")
    lines.append(f"- {active_count} active repos scanned")
    lines.append(f"- {manual_count} manual-only repos checked")

    return "\n".join(lines).strip() + "\n"


def _iter_units(summary: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("units", "remediation_units", "items", "records", "summaries"):
        value = summary.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _counts_for(units: list[dict[str, Any]], alert_class: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for unit in units:
        if _alert_class(unit) != alert_class:
            continue
        outcome = str(unit.get("outcome", "")).lower()
        if outcome == "merged":
            counts["merged"] += 1
        elif outcome == "opened_pr":
            counts["opened_pr"] += 1
        if _is_blocked_or_manual(unit):
            counts["blocked"] += 1
            counts["manual"] += 1
    return counts


def _manual_actions_by_class(units: list[dict[str, Any]]) -> Counter[str]:
    by_class: Counter[str] = Counter()
    for unit in units:
        if not _is_blocked_or_manual(unit):
            continue
        by_class[_alert_class(unit)] += 1
    return by_class


def _is_blocked_or_manual(unit: dict[str, Any]) -> bool:
    outcome = str(unit.get("outcome", "")).lower()
    repository_mode = str(unit.get("repository_mode", "")).lower()
    follow_up = unit.get("manual_follow_up_actions") or unit.get("manual_actions") or []
    return (
        repository_mode == "manual_only"
        or bool(follow_up)
        or outcome in {"blocked", "failed"}
    )


def _alert_class(unit: dict[str, Any]) -> str:
    raw = str(unit.get("alert_class") or unit.get("class") or "").lower()
    return raw.replace("-", "_").replace(" ", "_")


def _class_label(alert_class: str) -> str:
    if alert_class == "dependabot":
        return "Dependabot"
    if alert_class == "code_scanning":
        return "code scanning"
    if alert_class == "secret_scanning":
        return "secret scanning"
    return alert_class.replace("_", " ")


def _first_int(data: Any, *keys: str) -> int:
    if not isinstance(data, dict):
        return 0
    for key in keys:
        value = data.get(key)
        if isinstance(value, int):
            return value
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("latest_json", help="Path to github-security-agent latest.json")
    parser.add_argument("--heading", default=DEFAULT_HEADING, help="Markdown heading text")
    parser.add_argument("--output", help="Write Markdown to this file instead of stdout")
    args = parser.parse_args()

    markdown = render_weekly_report(load_latest_json(args.latest_json), heading=args.heading)
    if args.output:
        Path(args.output).write_text(markdown, encoding="utf-8")
    else:
        print(markdown, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
