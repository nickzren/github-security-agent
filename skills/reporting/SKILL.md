---
name: "github-security-reporting"
description: "Use when you need a consistent run summary across remediation units, outcomes, and remaining blockers."
---

# GitHub Security Reporting

Use this skill at the end of a run or when summarizing current remediation status.

## Source Of Truth

Read these files first:

1. `../../docs/operating-model.md`
2. `../../docs/reporting-model.md`
3. the selected `profile.yaml`

## Scope

This skill does not patch repositories. It summarizes what happened.

## Required Workflow

1. Collect all remediation units processed in the run.
2. Record one outcome for each remediation unit.
3. Record whether the PR was adopted from native Dependabot or opened by the agent.
4. Record PR links where applicable.
5. Record the rule id for every `code_scanning` remediation unit.
6. Record the alert number and secret type for every `secret_scanning` remediation unit.
7. Record the incident triage state for every `secret_scanning` remediation unit.
8. Record any manual follow-up actions for every `secret_scanning` remediation unit.
9. Record any relevant `platform_constraints` when they explain why a target is `manual_only`, review-required, or blocked by environment/runtime assumptions.
10. Record a reason code for every `blocked`, `skipped`, and `failed` outcome.
11. Separate unsupported scope from execution failure.
12. Distinguish remediation-pass results from merge-pass results.
13. Record any concurrency lock recovery events for the run.
14. Write the JSON Lines run report under `{clone_root}/.github-security-agent/runs/{profile_id}/{iso8601_utc}.jsonl` and overwrite the companion `latest.json` summary.
15. Summarize the remaining open-alert posture in operational terms, including code-scanning coverage gaps, secret-scanning follow-up actions, and surfaced platform constraints when they explain operator action.

## Execution Rules

- Use the fixed outcome model from the operating model.
- Use `target_id` in every per-unit summary.
- Include the remediation dedup key in every per-unit summary.
- Do not describe a remediation unit as `merged` unless the merge actually completed via the GitHub merge API.
- Use only the closed reason-code vocabulary defined in `../../docs/operating-model.md`. Do not invent new reason codes.
- Distinguish profile policy blocks from runtime contract failures.
- Never log secret values. Never write secrets into the run report.

## Expected Output

Return:

- total remediation units by outcome
- per-unit summary with repository name, base branch, and `target_id`
- remaining blockers
- relevant platform constraints, if any
- follow-up actions, if any
