# Discovery Model

## Purpose and Scope

`scripts/discover_remediation_units.py` is a read-only pre-flight pass, run
before any remediation. It:

- enumerates every open security alert in a profile's scope
- groups alerts into **remediation units**, keyed by the operating-model
  dedup key (see [operating-model.md](operating-model.md#remediation-unit))
- assigns each unit a static `triage_status` + `triage_reason`
- surfaces profile coverage gaps (unlisted, archived, or missing repos)

It emits one JSON artifact that a remediation agent can consume as a
deterministic work list instead of doing LLM-driven discovery across every
repository, and that doubles as an audit trail. It supports both `org` and
`user` profiles.

The script never runs verification commands, queries CI/check status,
predicts `merged`/`opened_pr` outcomes, or mutates the profile. Merge-vs-PR
is a runtime review-gate decision, out of scope here. Wiring this script into
the weekly Codex automation prompt is a separate follow-up.

## Owner-Type Fetch Behavior

Fetch strategy is driven by `profile.owner_type`.

- **`org`** — one paginated call per alert class to the org endpoint
  (`/orgs/{owner}/{alert_class}/alerts`). The result is **not** pre-filtered
  to profile repos: `build_units` keeps only in-scope repos, while the
  coverage sweep reuses the full set to detect `unlisted_repository` gaps.
  - Org endpoint failure is a **hard failure** (non-zero exit, not a
    recorded issue) — a failed org call makes the whole discovery
    fundamentally incomplete.
- **`user`** — the per-owner alert endpoint 404s for user accounts, so
  discovery iterates the full repo inventory (all non-archived repos, listed
  and unlisted in the profile) and calls the per-repo endpoint
  (`/repos/{owner}/{repo}/{alert_class}/alerts`) once per repo per alert
  class. This also makes unlisted user repos visible to the coverage sweep.
  - A non-2xx per-repo **HTTP** response (403/404 may mean a disabled
    feature, an auth-scope gap, private-repo visibility, or endpoint
    absence) does not crash the run. It is recorded as a `fetch_issues`
    entry — `{repository, alert_class, http_status, detail}`, with `detail`
    the short `gh` API error message — and counted in
    `summary.fetch_issues`. **A repo with fetch issues is incomplete, not
    clean: consumers must treat its unit list as partial.**
  - `fetch_issues` entries are HTTP-level failures only. A `gh` **transport**
    failure for a per-repo call (no `(HTTP n)` status in `gh`'s stderr —
    e.g. network unreachable, DNS failure) is a **hard failure**, same as
    an org endpoint failure: it aborts the run rather than being recorded
    as a fetch issue, for user profiles too.

The repo inventory
(`gh repo list <owner> --json name,isArchived,defaultBranchRef --limit 1000`)
is fetched once per run and reused for both alert iteration (`user`) and the
coverage sweep (both owner types).

## Remediation Key Composition

Base key: `owner/repo|alert_class|base_branch|target_id`

- `code_scanning` — append the normalized `rule_id`, so different
  allowlisted rules in one target do not share a key.
- `secret_scanning` — append the GitHub alert number, so distinct secret
  alerts in one target stay isolated.
- `dependabot` — base key only; multiple advisories against one target nest
  as alerts of a single unit.

### Base-branch resolution ladder

Resolved before key composition (many profile entries use
`default_base_branch: auto`), in order — first non-`auto`, non-empty value
wins:

1. the repository entry's own `default_base_branch`
2. the profile's `defaults.default_base_branch`
3. the repository's `defaultBranchRef` from the coverage-sweep inventory
4. `unknown`, if none of the above resolve (defensive fallback; in practice
   repos with no GitHub default branch —
   `profile_repository_missing_remote` — also return no alerts, so no unit
   is ever built with this fallback)

### Alert-to-target mapping

The alert's file path is matched against each enabled target's `path`,
choosing the longest (most specific) match; the root target (`path: "."` or
`""`) is the fallback for repository-level alerts or when no target path
matches. `secret_scanning` uses a simplified mapping — see
[Secret-Scanning Target Mapping](#secret-scanning-target-mapping). Paths are
used internally for mapping only — see [Sanitization](#sanitization).

## Output Schema

```json
{
  "generated_at": "2026-07-07T...Z",
  "schema_version": 1,
  "owner": "actiobio",
  "owner_type": "org",
  "profile_id": "actiobio-org",
  "summary": {
    "units_total": 0,
    "alerts_total": 0,
    "by_status": {"actionable": 0, "manual_only": 0, "ignored": 0, "unsupported": 0},
    "by_alert_class": {"dependabot": 0, "code_scanning": 0, "secret_scanning": 0},
    "coverage_gaps": {
      "unlisted_with_alerts": 0,
      "unlisted_no_alerts": 0,
      "archived_in_profile": 0,
      "profile_repository_missing_remote": 0
    },
    "fetch_issues": 0
  },
  "remediation_units": [
    {
      "remediation_key": "actiobio/actio-neo4j|dependabot|main|analysis",
      "repository": "actio-neo4j",
      "alert_class": "dependabot",
      "base_branch": "main",
      "target_id": "analysis",
      "ecosystem": "pip",
      "triage_status": "actionable",
      "triage_reason": null,
      "alert_count": 1,
      "alerts": [
        {"number": 29, "advisory_ids": ["GHSA-rrmf-rvhw-rf47"], "package": "torch", "severity": "high"}
      ]
    }
  ],
  "coverage_gaps": [
    {"repository": "new-repo", "gap": "unlisted_repository", "open_alert_count": 2},
    {"repository": "renamed-repo", "gap": "profile_repository_missing_remote"},
    {"repository": "old-repo", "gap": "archived_in_profile"}
  ],
  "fetch_issues": [
    {"repository": "private-repo", "alert_class": "code_scanning", "http_status": 403, "detail": "Code security must be enabled for this repository to use code scanning."}
  ]
}
```

- For `dependabot` units, `ecosystem` is GitHub's `dependency.package.ecosystem`
  taken from the unit's first alert (`null` for other alert classes) — it is
  **not** the profile-declared `ecosystems` list on the target.
- `summary.by_status` and `summary.by_alert_class` count remediation
  **units**, not alerts; `summary.alerts_total` counts alerts.
- `owner` is always emitted lowercased.
- Records are sorted deterministically so reruns produce stable diffs:
  `remediation_units` by `remediation_key`; `coverage_gaps` by `repository`
  (case-insensitive), then `gap`; `fetch_issues` by `repository`, then
  `alert_class`.
- The script writes JSON with `sort_keys=True`, so real output has
  alphabetized object keys at every level — the ordering above is
  illustrative, not literal.

## Triage Taxonomy

Four `triage_status` values. Discovery states what is worth attempting and
why the rest is not; the runtime review gate still decides merge-vs-PR.

| `triage_status` | Meaning |
| --- | --- |
| `ignored` | repo `automation_mode: ignored` |
| `manual_only` | repo `automation_mode: manual_only`, or any repo listed in `defaults.protected_manual_repositories` regardless of its `automation_mode` |
| `unsupported` | a static reason blocks automation for this unit |
| `actionable` | active repo, enabled target, supported ecosystem/rule, verification commands present |

`secret_scanning` units are `actionable` — the agent still opens a
review-required PR; that review gate is not discovery's concern.

`triage_reason` is `null` for `actionable` and otherwise one of a closed
vocabulary, evaluated in this order (first match wins):

1. `ignored_repository` — repo `automation_mode` is `ignored`
2. `protected_manual_repository` — repo name is in
   `defaults.protected_manual_repositories` (checked ahead of
   `automation_mode`, so it overrides `active`)
3. `manual_only_repository` — repo `automation_mode` is `manual_only` and
   the repo is not protected-manual
4. `target_alert_class_disabled` — no enabled target owns this alert:
   either no target in the repo entry lists this alert class in
   `alert_classes`, or no class-enabled target's path matches the alert's
   path
5. `unsupported_ecosystem` — `dependabot` alert but the mapped target
   declares no `ecosystems`
6. `unsupported_rule` — `code_scanning` `rule_id` not in
   `defaults.code_scanning.allowlisted_rules`
7. `verification_unavailable` — mapped target has no
   `verification_commands` (defensive; the profile linter should already
   prevent this)

Reason codes 5 and 6 apply only to their respective alert class; a
`code_scanning` alert is never checked against `unsupported_ecosystem`, and a
`dependabot` alert is never checked against `unsupported_rule`.

Values that coincide with operating-model outcome reason codes
(`unsupported_ecosystem`, `unsupported_rule`, `verification_unavailable`) are
reused intentionally; the `triage_reason` field name keeps them distinct from
runtime outcome reason codes.

## Coverage Gaps

The coverage sweep fetches **all** repos, without pre-filtering archived
repos (so `archived_in_profile` stays detectable):

```
gh repo list <owner> --json name,isArchived,defaultBranchRef --limit 1000
```

That inventory is diffed against the profile into three gap kinds:

- `unlisted_repository` — present on GitHub (non-archived), absent from the
  profile. Cross-referenced against fetched alerts: `open_alert_count` is
  included on every entry, and rolls up in `summary.coverage_gaps` as
  `unlisted_with_alerts` (count > 0) or `unlisted_no_alerts` (count 0).
- `archived_in_profile` — repo entry is `active` or `manual_only` in the
  profile but archived on GitHub (the operating model requires archived
  repos be excluded). A profile entry with `automation_mode: ignored` that
  is archived on GitHub does **not** produce this gap — it is already
  excluded from automation.
- `profile_repository_missing_remote` — repo entry is in the profile but
  absent from the GitHub repo list (renamed or deleted); flag for profile
  cleanup. These repos have no GitHub default branch, but they also return
  no alerts, so no remediation units are built for them (see
  [Base-branch resolution ladder](#base-branch-resolution-ladder)).

Gaps are sorted by `repository` (case-insensitive), then `gap`.

## Sanitization

Alert records carry only what dedup and prioritization need — never raw
payloads, secret values, secret locations, or file paths:

- `dependabot`: `number`, `advisory_ids` (GHSA ids only), `package` (name),
  `severity`. No advisory description text.
- `code_scanning`: `number`, `rule_id`, `severity`
  (`security_severity_level`, falling back to `severity`). The alert's file
  path is used internally for target mapping but never emitted.
- `secret_scanning`: `number` only. No secret type, value, or location. The
  alert's file path is used internally for target mapping but never
  emitted.

This mirrors the weekly-report sanitization contract: no raw alert payloads,
secret values, or raw secret types in output.

## Secret-Scanning Target Mapping

Documented simplification: discovery does not fetch per-alert secret
locations (`locations_url`), so it cannot map a secret alert to a target by
path the way it does for `dependabot` and `code_scanning`.

Instead, among the targets on the alert's repository that enable
`secret_scanning`:

1. prefer the root-path target (`path` is `""` or `"."`)
2. otherwise, fall back to the first enabled target in profile order

This is coarser than the path-based mapping used for the other two alert
classes and is a known approximation when a repository enables
`secret_scanning` on more than one non-root target.
