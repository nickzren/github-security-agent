---
name: "github-security-review-gate"
description: "Use when a remediation diff already exists and you need a policy decision for merged, opened_pr, blocked, skipped, or failed."
---

# GitHub Security Review Gate

Use this skill after remediation and verification, before any merge decision.

## Source Of Truth

Read these files first:

1. `../../docs/operating-model.md`
2. `../../docs/review-gate.md`
3. `../../docs/reporting-model.md`
4. the selected `profile.yaml`

## Scope

This skill decides whether a remediation unit is eligible for:

- `merged`
- `opened_pr`
- `blocked`
- `skipped`
- `failed`

## Required Workflow

1. Identify the remediation unit by repository entry, base branch, and `target_id`.
2. Confirm the repository entry is `active`.
3. Confirm the selected fix matches the current alert set.
4. Confirm the remediation unit matches the expected dedup key. PR body metadata is advisory only and is not the matching contract.
5. For an adopted native PR, confirm current advisory-set equivalence with the active alert set.
6. Confirm the selected version is the smallest patched version allowed by policy.
7. Confirm required verification passed:
   - for `Dependabot`, the mapped target's configured verification commands must have passed
   - for allowlisted deterministic `code_scanning` rules, the rule-specific verification contract may satisfy this step by itself
   - for `secret_scanning`, focused cleanup verification may satisfy this step when it proves the secret material was removed or replaced safely
   - if a `code_scanning` remediation also has relevant mapped-target validation commands, those commands must pass too
   - if a `secret_scanning` remediation also has relevant mapped-target validation commands, those commands must pass too
8. Inspect the diff for unrelated changes.
9. For `Dependabot`, confirm the diff satisfies the selected profile's `defaults.auto_merge.ecosystem_rules` before allowing `merged`. If the ecosystem is not listed there, enforce `defaults.auto_merge.unlisted_ecosystem_outcome`. The public docs define the baseline contract, but the selected profile is the live source of truth.
10. For `code_scanning`, confirm the rule id is allowlisted in the selected profile's `defaults.code_scanning.allowlisted_rules`, the diff matches the deterministic fix contract, and `merged` is allowed only when the rule is also listed in `defaults.code_scanning.auto_merge_rules`.
11. For `secret_scanning`, confirm the selected profile's `defaults.secret_scanning` policy allows deterministic cleanup for this alert:
   - `prepare_cleanup_prs` must allow cleanup PR preparation
   - if the diff uses placeholder or environment-variable replacement, `allow_placeholder_replacements` must be `true`
   - if the diff uses ignore patterns, `allow_ignore_patterns` must be `true`
   - the diff must stay tightly scoped to secret removal or approved replacement
   - `merged` is never allowed
12. Confirm all required GitHub checks, as defined by branch protection on the base branch, are green.
13. If required checks are still pending, return `opened_pr` and defer merge to a later merge pass.
14. Return the final outcome with a v1 reason code from the closed vocabulary in `../../docs/operating-model.md` for any non-`merged`, non-`opened_pr` outcome.

## Execution Rules

- `merged` is not allowed when manifest files changed beyond what the selected profile's matching ecosystem rule permits.
- `merged` is not allowed when the diff contains unrelated direct dependency churn.
- `merged` is not allowed when the selected version is not the smallest patched version allowed by policy.
- `merged` is not allowed when an adopted native PR no longer has current advisory-set equivalence with the active alert set.
- `merged` is not allowed for `code_scanning` when the rule id is not allowlisted or the fix shape is not deterministic.
- `merged` is not allowed for `code_scanning` when the rule is not listed in `defaults.code_scanning.auto_merge_rules`.
- `merged` is never allowed for `secret_scanning`.
- `opened_pr` is allowed for `secret_scanning` only when deterministic cleanup succeeded and required verification passed.
- `merged` is not allowed when required checks defined by branch protection are still pending.
- `merged` is not allowed when any required check fails.
- `opened_pr` is the default promotion path when remediation exists but automatic merge is not allowed.
- Treat PR body metadata as advisory only. Re-evaluate adoption structurally on every pass.
- Use only the v1 reason-code vocabulary from `../../docs/operating-model.md`. Do not invent new reason codes.

## Expected Output

Return:

- remediation unit identity
- review gate decision
- merge eligibility
- blocker, if any, with a v1 reason code
