#!/usr/bin/env python3
"""Collect open GitHub security alerts and write a sanitized report-only summary."""

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
    import yaml
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    yaml = None


AlertClient = Callable[[str, str, str], list[dict[str, Any]]]
SUPPORTED_ALERT_CLASSES = ("dependabot", "code_scanning", "secret_scanning")


@dataclass(frozen=True)
class RepositoryContract:
    repo: str
    automation_mode: str
    alert_classes: tuple[str, ...]


@dataclass(frozen=True)
class ProfileContract:
    profile_id: str
    owner: str
    local_clone_root: Path
    mutation_mode: str
    default_automation_mode: str
    repositories: tuple[RepositoryContract, ...]


class GitHubAlertReadError(RuntimeError):
    pass


def load_profile_contract(path: str | Path) -> ProfileContract:
    data = _load_yaml_subset(Path(path))
    profile = data.get("profile") if isinstance(data, dict) else None
    if not isinstance(profile, dict):
        raise ValueError("profile section is required")

    defaults = profile.get("defaults") if isinstance(profile.get("defaults"), dict) else {}
    runtime = profile.get("runtime") if isinstance(profile.get("runtime"), dict) else {}
    mutation_mode = _required_string(defaults, "mutation_mode", "profile.defaults.mutation_mode")
    if mutation_mode != "report_only":
        raise ValueError("profile.defaults.mutation_mode must be report_only")

    profile_id = _required_string(profile, "profile_id", "profile.profile_id")
    owner = _required_string(profile, "owner", "profile.owner")
    local_clone_root = Path(_required_string(runtime, "local_clone_root", "profile.runtime.local_clone_root"))
    default_mode = str(defaults.get("automation_mode") or "active")

    repositories = []
    for entry in data.get("repositories") or []:
        if not isinstance(entry, dict):
            continue
        repo = entry.get("repo")
        if not repo:
            continue
        mode = str(entry.get("automation_mode") or default_mode)
        repositories.append(
            RepositoryContract(
                repo=str(repo),
                automation_mode=mode,
                alert_classes=_repo_alert_classes(entry),
            )
        )

    return ProfileContract(
        profile_id=profile_id,
        owner=owner,
        local_clone_root=local_clone_root,
        mutation_mode=mutation_mode,
        default_automation_mode=default_mode,
        repositories=tuple(repositories),
    )


def build_report_summary(
    profile: ProfileContract,
    *,
    api_client: AlertClient,
    now: datetime | None = None,
) -> dict[str, Any]:
    timestamp = _format_utc(now or datetime.now(timezone.utc))
    repo_counts = {"active": 0, "manual_only": 0, "ignored": 0}
    open_alert_counts: Counter[str] = Counter()
    units: list[dict[str, Any]] = []
    notes: list[dict[str, str]] = []

    for repo in profile.repositories:
        mode = repo.automation_mode
        if mode in repo_counts:
            repo_counts[mode] += 1
        if mode == "ignored":
            continue

        for alert_class in repo.alert_classes:
            try:
                alerts = api_client(profile.owner, repo.repo, alert_class)
            except GitHubAlertReadError as exc:
                notes.append(
                    {
                        "repo": repo.repo,
                        "alert_class": alert_class,
                        "status": "unavailable",
                        "message": str(exc),
                    }
                )
                continue

            open_alert_counts[alert_class] += len(alerts)
            for alert in alerts:
                units.append(_unit_for_alert(profile.owner, repo, alert_class, alert))

    return {
        "schema_version": 1,
        "generated_at": timestamp,
        "finished_at": timestamp,
        "profile_id": profile.profile_id,
        "owner": profile.owner,
        "repo_counts": repo_counts,
        "open_alert_counts": {
            "dependabot": open_alert_counts["dependabot"],
            "code_scanning": open_alert_counts["code_scanning"],
            "secret_scanning": open_alert_counts["secret_scanning"],
            "total": sum(open_alert_counts.values()),
        },
        "units": units,
        "notes": notes,
    }


def write_report_artifacts(
    summary: dict[str, Any],
    *,
    output_root: str | Path | None = None,
) -> dict[str, Path]:
    if output_root is None:
        clone_root = Path(str(summary.get("local_clone_root") or "."))
        run_dir = clone_root / ".github-security-agent" / "runs" / str(summary["profile_id"])
    else:
        run_dir = Path(output_root)

    run_dir.mkdir(parents=True, exist_ok=True)
    stamp = _timestamp_for_filename(str(summary["finished_at"]))
    latest_json = run_dir / "latest.json"
    jsonl = run_dir / f"{stamp}.jsonl"

    latest_json.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with jsonl.open("w", encoding="utf-8") as handle:
        for unit in summary.get("units") or []:
            handle.write(json.dumps(unit, sort_keys=True) + "\n")

    return {"latest_json": latest_json, "jsonl": jsonl}


def fetch_open_alerts(owner: str, repo: str, alert_class: str) -> list[dict[str, Any]]:
    if alert_class == "dependabot":
        endpoint = f"/repos/{owner}/{repo}/dependabot/alerts?state=open&per_page=100"
        jq = ".[] | {number: .number, state: .state}"
    elif alert_class == "code_scanning":
        endpoint = f"/repos/{owner}/{repo}/code-scanning/alerts?state=open&per_page=100"
        jq = ".[] | {number: .number, state: .state, rule_id: .rule.id}"
    elif alert_class == "secret_scanning":
        endpoint = f"/repos/{owner}/{repo}/secret-scanning/alerts?state=open&per_page=100"
        jq = ".[] | {number: .number, state: .state}"
    else:
        return []

    result = subprocess.run(
        ["gh", "api", "--paginate", endpoint, "--jq", jq],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        message = _first_line(result.stderr) or "gh api failed"
        raise GitHubAlertReadError(message)

    return _parse_json_stream(result.stdout)


def _unit_for_alert(
    owner: str,
    repo: RepositoryContract,
    alert_class: str,
    alert: dict[str, Any],
) -> dict[str, Any]:
    alert_number = alert.get("number")
    outcome = "skipped" if repo.automation_mode == "manual_only" else "blocked"
    reason_code = "manual_only_repository" if repo.automation_mode == "manual_only" else "report_only"
    unit: dict[str, Any] = {
        "schema_version": 1,
        "owner": owner,
        "repo": repo.repo,
        "repository_mode": repo.automation_mode,
        "target_id": "repository",
        "alert_class": alert_class,
        "remediation_key": _remediation_key(owner, repo.repo, alert_class, alert_number),
        "outcome": outcome,
        "reason_code": reason_code,
        "manual_follow_up_actions": [_manual_action(repo.automation_mode)],
    }
    if alert_number is not None:
        unit["alert_number"] = alert_number
    if alert_class == "code_scanning" and alert.get("rule_id"):
        unit["rule_id"] = str(alert["rule_id"])
    return unit


def _load_yaml_subset(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        data = yaml.safe_load(text)
        if isinstance(data, dict):
            return data
    return _parse_profile_yaml_subset(text)


def _parse_profile_yaml_subset(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {"profile": {}, "repositories": []}
    section: str | None = None
    subsection: str | None = None
    current_repo: dict[str, Any] | None = None
    current_target: dict[str, Any] | None = None
    collecting_alert_classes = False

    for raw_line in text.splitlines():
        line = _strip_inline_comment(raw_line).rstrip()
        if not line.strip():
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = line.strip()

        if indent == 0:
            section = stripped[:-1] if stripped.endswith(":") else None
            subsection = None
            current_repo = None
            current_target = None
            collecting_alert_classes = False
            continue

        if section == "profile":
            profile = data["profile"]
            if indent == 2 and stripped in {"runtime:", "defaults:"}:
                subsection = stripped[:-1]
                profile.setdefault(subsection, {})
                continue
            if indent == 2 and ":" in stripped:
                subsection = None
                key, value = _split_yaml_pair(stripped)
                profile[key] = _yaml_scalar(value)
                continue
            if subsection and indent == 4 and ":" in stripped:
                key, value = _split_yaml_pair(stripped)
                profile[subsection][key] = _yaml_scalar(value)
                continue

        if section == "repositories":
            if indent == 2 and stripped.startswith("- repo:"):
                _, value = _split_yaml_pair(stripped[2:].strip())
                current_repo = {"repo": _yaml_scalar(value), "targets": []}
                data["repositories"].append(current_repo)
                current_target = None
                collecting_alert_classes = False
                continue
            if current_repo is None:
                continue
            if indent == 4 and stripped.startswith("automation_mode:"):
                _, value = _split_yaml_pair(stripped)
                current_repo["automation_mode"] = _yaml_scalar(value)
                continue
            if indent == 6 and stripped.startswith("- "):
                current_target = {}
                current_repo.setdefault("targets", []).append(current_target)
                collecting_alert_classes = False
                inline = stripped[2:].strip()
                if ":" in inline:
                    key, value = _split_yaml_pair(inline)
                    current_target[key] = _yaml_scalar(value)
                continue
            if current_target is None:
                continue
            if indent == 8 and stripped.startswith("alert_classes:"):
                current_target["alert_classes"] = []
                collecting_alert_classes = True
                continue
            if collecting_alert_classes and indent == 10 and stripped.startswith("- "):
                current_target.setdefault("alert_classes", []).append(_yaml_scalar(stripped[2:]))
                continue
            if indent <= 8:
                collecting_alert_classes = False

    return data


def _repo_alert_classes(entry: dict[str, Any]) -> tuple[str, ...]:
    classes: list[str] = []
    for target in entry.get("targets") or []:
        if not isinstance(target, dict):
            continue
        for alert_class in target.get("alert_classes") or []:
            normalized = _normalize_alert_class(str(alert_class))
            if normalized in SUPPORTED_ALERT_CLASSES and normalized not in classes:
                classes.append(normalized)
    return tuple(classes)


def _parse_json_stream(stdout: str) -> list[dict[str, Any]]:
    text = stdout.strip()
    if not text:
        return []

    decoder = json.JSONDecoder()
    index = 0
    parsed_items: list[dict[str, Any]] = []
    while index < len(text):
        while index < len(text) and text[index].isspace():
            index += 1
        if index >= len(text):
            break
        value, index = decoder.raw_decode(text, index)
        if isinstance(value, list):
            parsed_items.extend(item for item in value if isinstance(item, dict))
        elif isinstance(value, dict):
            parsed_items.append(value)
    return parsed_items


def _required_string(data: dict[str, Any], key: str, label: str) -> str:
    value = data.get(key)
    if value is None or value == "":
        raise ValueError(f"{label} is required")
    return str(value)


def _normalize_alert_class(value: str) -> str:
    return value.lower().replace("-", "_").replace(" ", "_")


def _manual_action(repository_mode: str) -> str:
    if repository_mode == "manual_only":
        return "manual remediation required by repository profile"
    return "report-only run; review locally before enabling mutations"


def _remediation_key(owner: str, repo: str, alert_class: str, alert_number: Any) -> str:
    suffix = str(alert_number) if alert_number is not None else "unknown"
    return f"{owner}/{repo}:{alert_class}:{suffix}"


def _format_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc).replace(microsecond=0)
    return value.isoformat().replace("+00:00", "Z")


def _timestamp_for_filename(value: str) -> str:
    return value.replace(":", "").replace("-", "").replace("Z", "Z")


def _first_line(value: str) -> str:
    return value.strip().splitlines()[0][:200] if value.strip() else ""


def _split_yaml_pair(stripped: str) -> tuple[str, str]:
    key, value = stripped.split(":", 1)
    return key.strip(), value.strip()


def _yaml_scalar(value: str) -> Any:
    stripped = value.strip()
    if stripped in {"[]", ""}:
        return [] if stripped == "[]" else ""
    if stripped.lower() in {"null", "~"}:
        return None
    return stripped.strip("'\"")


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
    parser.add_argument(
        "--output-root",
        help="Directory for latest.json and the JSONL run file; defaults under profile.runtime.local_clone_root",
    )
    args = parser.parse_args()

    profile = load_profile_contract(args.profile)
    summary = build_report_summary(profile, api_client=fetch_open_alerts)
    output_root = args.output_root
    if output_root is None:
        output_root = profile.local_clone_root / ".github-security-agent" / "runs" / profile.profile_id
    paths = write_report_artifacts(summary, output_root=output_root)
    print(
        json.dumps(
            {
                "latest_json": str(paths["latest_json"]),
                "jsonl": str(paths["jsonl"]),
                "units": len(summary["units"]),
                "notes": len(summary["notes"]),
                "repo_counts": summary["repo_counts"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
