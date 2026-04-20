---
name: "github-security-secret-scanning-response"
description: "Use when you need to triage open secret-scanning alerts, prepare deterministic cleanup PRs, and record required manual follow-up actions."
---

# GitHub Security Secret Scanning Response

Use this skill after `Dependabot` and `code_scanning` passes converge for the selected profile.

## Source Of Truth

Read these files first:

1. `../../docs/runtime-contract.md`
2. `../../docs/operating-model.md`
3. `../../docs/secret-scanning-policy.md`
4. `../../docs/review-gate.md`
5. `../../docs/reporting-model.md`
6. the selected `profile.yaml`

## Scope

This skill handles `secret_scanning` response only.

It may:

- classify open secret-scanning alerts
- prepare deterministic cleanup PRs
- record manual follow-up actions

It must not rotate credentials, dismiss alerts, rewrite history, or auto-merge secret-scanning PRs.

## Required Workflow

1. Confirm the selected profile supports `secret_scanning`.
2. Confirm the profile lock is already held. If this skill is invoked directly, acquire the same profile lock contract before any mutation.
3. Query open secret-scanning alerts once for every active repository entry that has at least one target with `secret_scanning` enabled.
4. If GitHub reports secret scanning is disabled or unavailable for a repository, return `skipped` with reason `secret_scanning_disabled`.
5. Map each alert to the nearest enabled `target_id` that owns the affected path. For repository-level or pathless alerts, use the enabled root target.
6. Build one remediation unit per secret-scanning alert. The remediation dedup key must include `owner/repo + alert_class + base_branch + target_id + alert_number`.
7. Record one incident triage state for each alert and carry it through reporting:
   - `active`
   - `revoked`
   - `historical`
   - `false_positive`
8. Classify each alert into one workflow bucket:
   - deterministic cleanup candidate on the current branch
   - history-rewrite case
   - manual incident-response case
9. Before preparing cleanup, enforce the selected profile's `defaults.secret_scanning` policy:
   - if `prepare_cleanup_prs` is `false`, do not prepare cleanup edits or PRs
   - if the selected cleanup requires placeholder or environment-variable replacement, require `allow_placeholder_replacements: true`
   - if the selected cleanup requires ignore patterns, require `allow_ignore_patterns: true`
10. For deterministic cleanup candidates allowed by policy, prepare the smallest reviewable change that removes the committed secret material or replaces it with a placeholder, environment-variable reference, or ignore pattern only when the selected profile allows that cleanup shape.
11. Before validation, enforce the mapped target's structured environment requirements:
   - if `required_env_vars` are missing, stop with `env_mismatch` or `registry_auth_missing`
   - if the current runner platform is not listed in `supported_platforms`, stop with `env_mismatch`
   - if `verification_workdir` is declared, run validation from that directory
12. Run required validation:
   - if the mapped target defines relevant verification commands, those commands must pass
   - otherwise, use focused rule-specific verification only when it proves the cleanup is syntactically safe
   - apply the profile's verification environment allowlist during validation commands
13. Run the review gate before any promotion decision.
14. Open or update a cleanup PR when deterministic cleanup succeeded and policy allows it. Record the incident triage state and any manual follow-up actions such as credential rotation or provider-side review in the PR body and the run report.
15. For alerts that require history rewrite, return `blocked` with reason `history_rewrite_required`.
16. For alerts that require human judgment, provider-side mutation, false-positive dismissal review, or non-deterministic edits, return `blocked` or `skipped` with reason `policy_blocked` and record the incident triage state explicitly.

## Execution Rules

- Treat the selected profile as the live source of truth.
- Never auto-merge secret-scanning PRs.
- Never rotate, revoke, or validate live credentials against external providers.
- Never dismiss GitHub secret-scanning alerts through the API.
- Query secret-scanning alerts once per repository entry, then map each alert to a target. Do not duplicate discovery per target.
- Keep cleanup diffs tightly scoped to secret removal or placeholder replacement.
- Do not prepare cleanup edits or ignore patterns that the selected profile forbids.
- Include manual follow-up actions whenever a credential may still need rotation or revocation after repository cleanup.
- Preserve the incident triage state in reporting even when the final workflow outcome is `blocked` or `skipped`.
- Use only the reason-code vocabulary from `../../docs/operating-model.md`.
