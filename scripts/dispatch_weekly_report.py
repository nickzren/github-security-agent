#!/usr/bin/env python3
"""Dispatch the publish-only weekly security report workflow."""

from __future__ import annotations

import argparse
import base64
import gzip
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    yaml = None

try:
    from scripts.render_weekly_report import load_latest_json, render_weekly_report
except ModuleNotFoundError:  # pragma: no cover - used when running from scripts/
    from render_weekly_report import load_latest_json, render_weekly_report


HEADING = "Weekly Security Report"
WORKFLOW = "publish-weekly-report.yml"
STALE_AFTER_DAYS = 9


@dataclass(frozen=True)
class DispatchRequest:
    publish_repo: str
    issue_repo: str
    issue_title: str
    issue_body_gz_b64: str
    command: list[str]


def prepare_dispatch(
    *,
    profile_path: str | Path,
    latest_json: str | Path,
    publish_repo: str,
    issue_repo: str,
    heading: str = HEADING,
    now: datetime | None = None,
) -> DispatchRequest:
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    profile = _read_profile_contract(profile_path)
    _validate_repo_owner(profile["owner"], publish_repo, "publish repo")
    _validate_repo_owner(profile["owner"], issue_repo, "issue repo")
    if profile["mutation_mode"] != "report_only":
        raise ValueError("profile.defaults.mutation_mode must be report_only")

    latest_path = Path(latest_json)
    title = _issue_title(now, heading)
    if not latest_path.exists():
        body = f"## {heading}\n\nNo completed run this week.\n"
    else:
        summary = load_latest_json(latest_path)
        completed_at = _report_timestamp(summary, latest_path)
        if now - completed_at > timedelta(days=STALE_AFTER_DAYS):
            body = (
                f"## {heading}\n\n"
                "Stale report.\n\n"
                f"Last completed run: {completed_at.isoformat()}\n"
            )
        else:
            body = render_weekly_report(summary, heading=heading)

    encoded_body = _encode_body(body)
    command = [
        "gh",
        "workflow",
        "run",
        WORKFLOW,
        "--repo",
        publish_repo,
        "-f",
        f"issue_title={title}",
        "-f",
        f"issue_body_gz_b64={encoded_body}",
        "-f",
        f"issue_repo={issue_repo}",
    ]
    return DispatchRequest(
        publish_repo=publish_repo,
        issue_repo=issue_repo,
        issue_title=title,
        issue_body_gz_b64=encoded_body,
        command=command,
    )


def _read_profile_contract(path: str | Path) -> dict[str, str]:
    if yaml is not None:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        profile = data.get("profile") if isinstance(data, dict) else None
        defaults = profile.get("defaults") if isinstance(profile, dict) else None
        owner = profile.get("owner") if isinstance(profile, dict) else None
        mutation_mode = defaults.get("mutation_mode") if isinstance(defaults, dict) else None
        if not owner:
            raise ValueError("profile.owner is required")
        if mutation_mode is None:
            raise ValueError("profile.defaults.mutation_mode is required")
        return {"owner": str(owner), "mutation_mode": str(mutation_mode)}

    owner: str | None = None
    mutation_mode: str | None = None
    in_defaults = False

    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = _strip_inline_comment(raw_line).strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if indent == 2 and stripped.startswith("owner:"):
            owner = _yaml_scalar(stripped.split(":", 1)[1])
        elif indent == 2 and stripped == "defaults:":
            in_defaults = True
        elif indent <= 2 and in_defaults and not stripped.startswith("defaults:"):
            in_defaults = False
        elif in_defaults and indent == 4 and stripped.startswith("mutation_mode:"):
            mutation_mode = _yaml_scalar(stripped.split(":", 1)[1])

    if not owner:
        raise ValueError("profile.owner is required")
    if mutation_mode is None:
        raise ValueError("profile.defaults.mutation_mode is required")
    return {"owner": owner, "mutation_mode": mutation_mode}


def _validate_repo_owner(owner: str, repo: str, label: str) -> None:
    if "/" not in repo:
        raise ValueError(f"{label} must be owner/repo")
    repo_owner = repo.split("/", 1)[0]
    if repo_owner.lower() != owner.lower():
        raise ValueError(f"{label} owner mismatch: expected {owner}, got {repo_owner}")


def _report_timestamp(summary: dict[str, Any], latest_path: Path) -> datetime:
    for key in ("generated_at", "finished_at"):
        value = summary.get(key)
        if isinstance(value, str) and value:
            return _parse_datetime(value)
    return datetime.fromtimestamp(latest_path.stat().st_mtime, timezone.utc)


def _parse_datetime(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _issue_title(now: datetime, heading: str) -> str:
    iso_year, iso_week, _ = now.isocalendar()
    return f"{heading} - {iso_year}-W{iso_week:02d}"


def _encode_body(body: str) -> str:
    return base64.b64encode(gzip.compress(body.encode("utf-8"))).decode("ascii")


def _yaml_scalar(value: str) -> str:
    return value.strip().strip("'\"")


def _strip_inline_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char in {"'", '"'}:
            if quote == char:
                quote = None
            elif quote is None:
                quote = char
            continue
        if char == "#" and quote is None:
            return line[:index]
    return line


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, help="Path to the selected profile.yaml")
    parser.add_argument("--latest-json", required=True, help="Path to the latest.json run summary")
    parser.add_argument("--publish-repo", required=True, help="Repository containing the publish workflow")
    parser.add_argument("--issue-repo", required=True, help="Repository where the issue is created or updated")
    parser.add_argument("--heading", default=HEADING, help="Weekly issue heading and title prefix")
    parser.add_argument("--dry-run", action="store_true", help="Print the dispatch command and do not call gh")
    args = parser.parse_args()

    request = prepare_dispatch(
        profile_path=args.profile,
        latest_json=args.latest_json,
        publish_repo=args.publish_repo,
        issue_repo=args.issue_repo,
        heading=args.heading,
    )
    if args.dry_run:
        print(json.dumps({"command": request.command, "issue_title": request.issue_title}, indent=2))
        return 0
    subprocess.run(request.command, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
