---
name: "github-security-code-scanning-triage"
description: "Use when asked to inspect GitHub code-scanning alerts across the repositories defined in one selected profile."
---

# GitHub Security Code Scanning Triage

Use this skill when the task is to classify open `code scanning` alerts for one selected `profile`.

## Source Of Truth

Read these files before changing anything:

1. `../../docs/runtime-contract.md`
2. `../../docs/operating-model.md`
3. `../../docs/code-scanning-policy.md`
4. the selected `profile.yaml`

## Scope

- query open `code scanning` alerts
- classify them by rule, path, severity, and fixability
- identify which alerts are eligible for the code-scanning remediator

This skill does not patch repositories.

## Required Workflow

1. Validate that the selected profile supports `code_scanning`.
2. Enumerate `active` repository entries.
3. Query open `code scanning` alerts for each repository entry.
4. If GitHub returns that code scanning is disabled, record `skipped` with reason `code_scanning_disabled`.
5. If GitHub returns that no analysis exists, record `skipped` with reason `no_analysis_found`.
6. Normalize open alerts by repository, rule id, path, and base branch.
7. Prefer explicit `target_id` mapping from the profile. For repository-level workflow alerts under `.github/workflows/**`, a single root target at `.` may serve as the stable target.
8. If the rule id is not listed in the selected profile's `defaults.code_scanning.allowlisted_rules`, record `skipped` with reason `unsupported_rule`.
9. If the rule id is allowlisted, confirm the fix shape matches the deterministic contract in `../../docs/code-scanning-policy.md`.
10. Hand only eligible deterministic findings to the code-scanning remediator.

## Execution Rules

- Do not edit repository files.
- Treat the selected profile as the live source of truth for allowlisted rules.
- Use the closed reason-code vocabulary from `../../docs/operating-model.md`.
- Distinguish `code_scanning_disabled` from `no_analysis_found`.

## Expected Output

Return, per repository entry:

- coverage status
- open code-scanning alerts by rule
- which findings are eligible for remediation
- which findings are skipped and why
