#!/usr/bin/env python3
"""Shared GitHub security-alert fetch helpers for the agent scripts."""

from __future__ import annotations

import json
import re
import subprocess
from typing import Any

ORG_ALERT_ENDPOINTS = {
    "dependabot": "/orgs/{owner}/dependabot/alerts?state=open&per_page=100",
    "code_scanning": "/orgs/{owner}/code-scanning/alerts?state=open&per_page=100",
    "secret_scanning": "/orgs/{owner}/secret-scanning/alerts?state=open&per_page=100",
}

REPO_ALERT_ENDPOINTS = {
    "dependabot": "/repos/{owner}/{repo}/dependabot/alerts?state=open&per_page=100",
    "code_scanning": "/repos/{owner}/{repo}/code-scanning/alerts?state=open&per_page=100",
    "secret_scanning": "/repos/{owner}/{repo}/secret-scanning/alerts?state=open&per_page=100",
}


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


def alert_repository_name(alert: Any) -> str:
    if not isinstance(alert, dict):
        return ""
    repo = alert.get("repository")
    if isinstance(repo, dict):
        name = repo.get("name")
        if isinstance(name, str):
            return name.lower()
        full_name = repo.get("full_name")
        if isinstance(full_name, str):
            return full_name.split("/")[-1].lower()
    if isinstance(repo, str):
        return repo.split("/")[-1].lower()
    return ""


def _stderr_status_and_detail(stderr: str) -> tuple[int, str]:
    text = (stderr or "").strip().splitlines()
    first = text[0] if text else ""
    if first.startswith("gh: "):
        first = first[len("gh: "):]
    status = 0
    match = re.search(r"\(HTTP (\d+)\)", first)
    if match:
        status = int(match.group(1))
        first = first[: match.start()].strip()
    return status, first


def _fetch_endpoint(endpoint: str, run) -> subprocess.CompletedProcess:
    return run(["gh", "api", endpoint, "--paginate"], check=False, text=True, capture_output=True)


def fetch_alerts(
    owner: str,
    alert_class: str,
    *,
    owner_type: str = "org",
    repos: list[str] | None = None,
    run=subprocess.run,
) -> tuple[list[Any], list[dict]]:
    """Fetch open alerts for one class. Returns (alerts, fetch_issues).

    org: one org-wide call; failure is fatal (discovery would be incomplete).
    user: one call per repo; non-2xx is recorded as a fetch issue, not fatal.
    """
    if owner_type == "org":
        result = _fetch_endpoint(ORG_ALERT_ENDPOINTS[alert_class].format(owner=owner), run)
        if result.returncode != 0:
            raise RuntimeError(
                f"org alert endpoint failed for {alert_class}: {result.stderr.strip()}"
            )
        alerts: list[Any] = []
        for page in decode_paginated_json(result.stdout):
            alerts.extend(page if isinstance(page, list) else [page])
        return alerts, []

    if owner_type != "user":
        raise RuntimeError(f"unsupported owner_type {owner_type!r}: expected 'org' or 'user'")

    alerts = []
    issues: list[dict] = []
    for repo in repos or []:
        endpoint = REPO_ALERT_ENDPOINTS[alert_class].format(owner=owner, repo=repo)
        result = _fetch_endpoint(endpoint, run)
        if result.returncode != 0:
            status, detail = _stderr_status_and_detail(result.stderr)
            if status == 0:
                raise RuntimeError(
                    f"gh transport failure for {repo} {alert_class}: {detail or result.stderr.strip()}"
                )
            issues.append(
                {"repository": repo, "alert_class": alert_class, "http_status": status, "detail": detail}
            )
            continue
        for page in decode_paginated_json(result.stdout):
            for alert in page if isinstance(page, list) else [page]:
                if isinstance(alert, dict) and "repository" not in alert:
                    alert["repository"] = {"name": repo}
                alerts.append(alert)
    return alerts, issues
