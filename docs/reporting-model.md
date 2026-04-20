# Reporting Model

Every run should produce exactly one summary per remediation unit, reflecting the unit's final state for that run (not one entry per iteration of the exhaustive loop).

## Required Summary Fields

- profile name
- GitHub owner
- repository name
- base branch
- `target_id`
- remediation dedup key
- alert class
- rule id, when the alert class is `code_scanning`
- alert number and secret type, when the alert class is `secret_scanning`
- incident triage state, when the alert class is `secret_scanning`
- PR source: native_dependabot or agent_managed
- pass type: remediation or merge
- outcome
- pull request link, if any
- reason code, if any
- remaining blocker, if any
- platform constraints, when they explain operator action or review-required handling
- manual follow-up actions, if any

## Outcome Semantics

- `merged`: remediation completed and was merged
- `opened_pr`: remediation prepared and PR opened or updated
- `blocked`: remediation is prepared or known, but policy or environment prevents completion
- `skipped`: intentionally not processed
- `failed`: execution error or unrecoverable tooling problem

## Reporting Rules

- summarize all processed remediation units
- report all skipped repository entries with the reason
- report all blocked units with the specific blocker
- report any reason code using the closed reason-code vocabulary defined in `docs/operating-model.md`
- distinguish unsupported alert classes from execution failures
- do not mark a unit `merged` unless the actual merge completed
- report remaining open `Dependabot` alerts after the exhausted run and explain whether they are waiting on `opened_pr`, blocked by policy or environment, or outside current remediation scope
- report remaining open `code scanning` alerts by rule and explain whether they are unsupported, blocked by policy, disabled at the repository level, or missing analysis
- report remaining open `secret_scanning` alerts with their incident triage state and required manual follow-up actions, and explain whether they are awaiting cleanup PR review, blocked by policy, or disabled at the repository level
- surface relevant `platform_constraints` for manual-only, review-required, or env-mismatch cases when they explain the operator action needed
