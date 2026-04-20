# Secret Scanning Policy

Use this policy when the selected profile enables `secret_scanning`.

The selected profile's `defaults.secret_scanning` section is the live source of truth for:

- whether cleanup PRs may be prepared
- whether placeholder or environment-variable replacement is allowed
- whether ignore-pattern based cleanup is allowed

## Purpose

Secret scanning is not a dependency-update problem. It is a response workflow that may combine:

- alert discovery
- deterministic repository cleanup
- incident-style reporting
- manual follow-up actions such as rotation, revocation, or provider-side review

## Supported Behavior

The framework may:

- detect open secret-scanning alerts in active repository entries
- map alerts onto configured `target_id` values
- prepare minimal cleanup pull requests when the secret can be removed from tracked text files deterministically
- replace committed secret material with placeholders or environment-variable references when the replacement is straightforward and reviewable
- record manual follow-up actions in the run report and pull request body

## Never Done Automatically

The framework must not:

- rotate or revoke credentials
- dismiss secret-scanning alerts in GitHub
- rewrite git history
- auto-merge secret-scanning pull requests
- mutate production systems, provider settings, or secret managers

## Deterministic Cleanup Contract

A secret-scanning alert may enter remediation only when all of the following are true:

1. the alert maps to an `active` repository entry and enabled `target_id`
2. the secret appears in a tracked text file on the current branch
3. the cleanup can be expressed as a small, reviewable repository change
4. the replacement is a placeholder, dummy value, documented example, or environment-variable reference
5. the change does not require history rewrite to be effective on the current branch
6. relevant target validation commands can run, or a focused rule-specific cleanup check can prove the edit is syntactically safe

If any of these conditions fail, the correct outcome is `blocked` or `skipped`, not forced cleanup.

The live profile policy must also permit the selected cleanup shape:

- if `prepare_cleanup_prs` is `false`, deterministic cleanup candidates must stay `blocked` with `policy_blocked`
- if the cleanup requires placeholder or environment-variable replacement and `allow_placeholder_replacements` is `false`, the candidate must stay `blocked` with `policy_blocked`
- if the cleanup requires ignore patterns and `allow_ignore_patterns` is `false`, the candidate must stay `blocked` with `policy_blocked`

## Incident Triage States

Every secret-scanning alert should carry one incident triage state in reporting:

- `active`
- `revoked`
- `historical`
- `false_positive`

This triage state is separate from the workflow bucket and outcome. It preserves incident-response context even when the final workflow result is `opened_pr`, `blocked`, or `skipped`.

## Response Buckets

Use these buckets consistently:

- `opened_pr`: deterministic cleanup PR prepared, with manual follow-up actions recorded when rotation or revocation is still required
- `blocked` with `history_rewrite_required`: the alert survives only in git history or requires history surgery to remove
- `blocked` with `policy_blocked`: the alert needs human judgment, provider-side changes, dismissal review, or non-deterministic code edits
- `skipped` with `secret_scanning_disabled`: GitHub secret scanning is disabled or unavailable for the repository

## Verification

For secret scanning:

- relevant mapped-target validation commands should run when they exist
- otherwise, focused rule-specific verification may be enough if it proves the cleanup is syntactically safe
- lack of safe verification should block automatic cleanup PR preparation

## Pull Request Rules

Secret-scanning pull requests must:

- stay tightly scoped to secret removal or placeholder replacement
- avoid unrelated refactors
- include manual follow-up actions when credentials may still need rotation or revocation
- remain review-required even when all validation passes
