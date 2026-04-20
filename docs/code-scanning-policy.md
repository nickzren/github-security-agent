# Code Scanning Policy

## Scope

Code scanning remediation is narrower than `Dependabot`.

- query open code-scanning alerts in active repository entries
- remediate only rules that are explicitly allowlisted by the selected profile
- default all other rules to report-only behavior

The selected profile's `defaults.code_scanning` section is the live source of truth.

## Coverage States

For each repository entry:

- if GitHub returns `403` and code scanning is not enabled, record `skipped` with reason `code_scanning_disabled`
- if GitHub returns `404` and no analysis is present, record `skipped` with reason `no_analysis_found`
- if code scanning is enabled and alerts are open, triage them by rule, path, and repository entry

Coverage gaps are reportable conditions, not silent skips.

## Allowlist Model

Only rules listed in `defaults.code_scanning.allowlisted_rules` may enter remediation.

- rules outside the allowlist: `skipped` with reason `unsupported_rule`
- rules inside the allowlist but not listed in `defaults.code_scanning.auto_merge_rules`: `opened_pr` after remediation unless policy blocks them entirely

## Public Baseline Allowlist

The public baseline starts with one deterministic rule:

- `actions/missing-workflow-permissions`

## Rule Contract: `actions/missing-workflow-permissions`

This rule is eligible only when all of the following are true:

- the alert points to `.github/workflows/*.yml` or `.github/workflows/*.yaml`
- the workflow does not already declare an explicit `permissions:` block at the top level
- the workflow appears read-only and build/test oriented

The default safe fix is:

```yaml
permissions:
  contents: read
```

Do not auto-fix or auto-merge this rule when the workflow appears to need broader token scopes, for example:

- `id-token: write`
- release publishing
- package publishing
- deployment or Pages publishing
- issue or PR commenting bots
- status or checks writes
- `pull_request_target`
- explicit `gh` or `github-script` usage that mutates GitHub state

In those cases, open a PR for review or block with `policy_blocked`.

## Verification

For `actions/missing-workflow-permissions`, rule-specific verification is:

- parse every changed workflow file as YAML
- ensure the only semantic change is the explicit `permissions:` block

If the repository entry also has relevant local validation commands, run them too.

## Merge Policy

Code-scanning merge decisions still flow through the review gate.

`merged` is allowed only when:

- the rule is allowlisted
- the rule is listed in `defaults.code_scanning.auto_merge_rules`
- rule-specific verification passed
- required GitHub checks, as defined by branch protection, are green
- the diff is minimal and limited to the deterministic fix shape

Everything else should stop at `opened_pr` or `blocked`.

