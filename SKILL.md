---
name: "github-security-agent"
description: "Use when asked to reduce GitHub security alerts across all active repositories in one selected profile."
---

# GitHub Security Agent

Use this skill as the canonical entrypoint for one selected `profile`.

## Source Of Truth

Read these files before changing anything:

1. `docs/runtime-contract.md`
2. `docs/operating-model.md`
3. `docs/code-scanning-policy.md`
4. `docs/secret-scanning-policy.md`
5. `docs/review-gate.md`
6. `docs/reporting-model.md`
7. the selected `profile.yaml`

## Scope

- one selected `profile`
- all `active` repository entries in that profile
- `Dependabot` remediation first
- then selected `code scanning` remediation
- then `secret scanning` response for enabled targets

## Required Workflow

1. Run account discovery and validate the selected `profile`.
2. Acquire the profile lock before any mutation.
3. Run the `Dependabot` remediation pass and keep iterating until eligible `Dependabot` work converges.
4. Run the `code scanning` triage pass across active repositories.
5. For code-scanning findings:
   - if code scanning is disabled for the repository, report `skipped` with reason `code_scanning_disabled`
   - if GitHub reports no analysis, report `skipped` with reason `no_analysis_found`
   - if the rule is not allowlisted in the selected profile, report `skipped` with reason `unsupported_rule`
   - if the rule is allowlisted and deterministic, run the code-scanning remediator
6. Run the `secret scanning` response pass across active repositories.
7. For secret-scanning findings:
   - if secret scanning is disabled or unavailable for the repository, report `skipped` with reason `secret_scanning_disabled`
   - if deterministic repository cleanup is possible, run the secret-scanning response skill and open or update a review-required cleanup PR
   - if cleanup would require history rewrite or external provider mutation, report `blocked` with the correct reason code and manual follow-up actions
8. Run the review gate before any merge decision.
9. Reconcile stale or superseded agent-managed PRs that remain in scope. If a PR no longer matches the live alert state because it was superseded, the advisory was withdrawn, or the dependency was removed, close it with a comment that points to the replacement remediation unit when one exists, and record the result with the correct `skipped` reason code.
10. Write final reporting artifacts for all supported alert classes after reconcile is complete.
11. Release the profile lock.

## Execution Rules

- The selected profile is the live source of truth.
- `Dependabot`, `code scanning`, and `secret scanning` are separate passes with separate policies.
- Exhaust eligible `Dependabot` work before starting `code scanning` or `secret scanning`.
- For `code scanning`, only auto-remediate allowlisted deterministic rules from the selected profile's `defaults.code_scanning` policy.
- For `secret scanning`, use the selected profile's `defaults.secret_scanning` policy and never auto-merge cleanup PRs.
- Final reporting must reflect any reconcile actions taken in the same locked run.
