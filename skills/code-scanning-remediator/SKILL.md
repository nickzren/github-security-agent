---
name: "github-security-code-scanning-remediator"
description: "Use when asked to remediate allowlisted deterministic GitHub code-scanning alerts across the repositories defined in one selected profile."
---

# GitHub Security Code Scanning Remediator

Use this skill only after code-scanning triage identified allowlisted deterministic findings.

## Source Of Truth

Read these files before changing anything:

1. `../../docs/runtime-contract.md`
2. `../../docs/operating-model.md`
3. `../../docs/code-scanning-policy.md`
4. `../../docs/review-gate.md`
5. `../../docs/reporting-model.md`
6. the selected `profile.yaml`

## Scope

- allowlisted deterministic `code scanning` findings only
- one deduplicated PR per remediation unit
- merge only when the selected profile and review gate both allow it

This skill assumes the profile-scoped lock is already held by the canonical root `SKILL.md` flow. If it is invoked directly, validate that the lock is already held before mutating repository state.

## Required Workflow

1. Confirm the remediation unit came from code-scanning triage.
2. Confirm the rule id is in the selected profile's `defaults.code_scanning.allowlisted_rules`.
3. Compute the remediation dedup key using `owner/repo + alert_class + base_branch + target_id + normalized_rule_id`.
4. For `actions/missing-workflow-permissions`, only proceed when the workflow file matches the deterministic contract in `../../docs/code-scanning-policy.md`.
5. If the workflow appears to need broader token scopes, stop at `opened_pr` or `blocked` with reason `policy_blocked`.
6. Create or reuse the deduplicated branch for the remediation unit.
7. Apply only the minimal deterministic fix.
8. Before verification, enforce the mapped target's structured environment requirements:
   - if `required_env_vars` are missing, stop with `env_mismatch` or `registry_auth_missing`
   - if the current runner platform is not listed in `supported_platforms`, stop with `env_mismatch`
   - if `verification_workdir` is declared, run verification from that directory
9. Run rule-specific verification:
   - parse changed workflow files as YAML
   - run any additional repository validation commands that are relevant to the mapped target, using the profile's verification environment allowlist
10. Run the review gate.
11. Open or update the PR.
12. Merge only when the rule is also listed in the selected profile's `defaults.code_scanning.auto_merge_rules` and the review gate returns `merged`.

## Execution Rules

- Do not attempt generic secure-coding repair.
- Do not broaden a workflow-permissions fix into unrelated CI refactors.
- Keep the diff limited to the alert path and deterministic fix shape.
- Treat the selected profile's `defaults.code_scanning` section as the live source of truth.
- Use the closed reason-code vocabulary from `../../docs/operating-model.md`.

## Expected Output

Return one of:

- `merged`
- `opened_pr`
- `blocked`
- `skipped`
- `failed`

Attach a reason code to every non-`merged`, non-`opened_pr` outcome.
