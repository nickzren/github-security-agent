# Review Gate

Run this review gate after remediation and verification but before any merge decision.

## Required Checks

For all remediation units:

1. the repository entry is `active`
2. the selected fix matches the current alert set or a clearly necessary transitive update
3. the remediation unit matches the expected dedup key and PR metadata
4. required verification passed
5. all required GitHub checks, as defined by branch protection, are green
6. the diff contains no unrelated changes

For `Dependabot`, required verification means the mapped target's configured local verification commands passed.

For allowlisted deterministic `code scanning` rules, required verification may be satisfied by the rule-specific verification contract alone. If the repository entry also defines relevant local validation commands for the mapped target, those commands must pass too.

For `secret_scanning`, required verification may be satisfied by focused cleanup verification when it proves the secret material was removed or replaced safely. If the repository entry also defines relevant local validation commands for the mapped target, those commands must pass too.

Additional requirements for `Dependabot` automatic merge:

1. any adopted native PR still matches the current advisory set
2. the selected version is the smallest patched version allowed by policy
3. the diff satisfies the selected profile's `defaults.auto_merge.ecosystem_rules`, with `unlisted_ecosystem_outcome` applied when the ecosystem is not listed
4. no manifest files changed unless the matching profile rule explicitly allows them
5. no unrelated direct dependency churn appears

If a `Dependabot` remediation changes manifest files, the allowed outcome is `opened_pr` or `blocked`, not `merged`.

Additional requirements for `code scanning` promotion:

1. the rule id is allowlisted in the selected profile's `defaults.code_scanning.allowlisted_rules`
2. the diff matches the deterministic fix contract for that rule
3. rule-specific verification passed
4. `merged` is allowed only when the rule is also listed in `defaults.code_scanning.auto_merge_rules`

If a `code scanning` rule is allowlisted but not merge-allowed, the correct promotion path is `opened_pr`, not `merged`.

Additional requirements for `secret_scanning` promotion:

1. the alert is enabled for the mapped target and still matches the live alert state
2. the diff is tightly scoped to secret removal or placeholder replacement
3. focused cleanup verification passed, plus any relevant mapped-target validation commands
4. the selected profile's `defaults.secret_scanning.prepare_cleanup_prs` allows cleanup PR preparation
5. the selected cleanup shape is permitted by profile policy:
   - placeholder or environment-variable replacement requires `allow_placeholder_replacements: true`
   - ignore-pattern cleanup requires `allow_ignore_patterns: true`
6. the change does not require history rewrite or external provider mutation to be safe on the current branch
7. `merged` is never allowed; the promotion path is `opened_pr` or `blocked`

If required GitHub checks are still pending, the correct outcome is `opened_pr` until a later merge pass re-evaluates the PR.

## Outcomes

- `merged`: review gate passed and merge completed
- `opened_pr`: remediation is ready for human review or waiting on checks
- `blocked`: remediation cannot proceed because review gate or policy failed
- `skipped`: repository entry or target is intentionally not processed
- `failed`: remediation or verification could not complete
