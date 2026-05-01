# Operating Model

## Vocabulary

Use these terms consistently:

- `profile`: one account-level configuration for a GitHub owner
- `repository entry`: one repository definition inside a profile
- `target_id`: one stable remediation target inside a repository entry
- `remediation unit`: one actionable work item derived from alerts and mapped onto one `target_id`
- `remediation dedup key`: the stable identity used for PR reuse, branch naming, and reporting

## Repository Modes

Each repository entry must declare one automation mode:

- `active`: the agent may patch, open pull requests, and merge when all gates pass
- `manual_only`: the agent may scan and report, but must not mutate the repository
- `ignored`: the agent must skip the repository entry and report the configured reason

`active` requires at least one real verification command for every enabled remediation target. If a repository entry cannot define real verification commands, it must remain `manual_only`.

## Mutation Modes

- `report_only`: read alerts and write local or public reports only; no branch creation, no pull request creation or update, no pushes, and no merges
- `pull_request`: create or update remediation branches and pull requests for `active` repositories after verification allows it; no direct default-branch pushes and no auto-merge

`manual_only` repository entries remain read/report-only under every mutation mode. Auto-merge requires a future explicit mutation mode; `pull_request` is not enough.

A real verification command must:

- exit non-zero on failure with no manual intervention
- exercise the dependency graph that the fix touches; install plus at least one test, type-check, or equivalent validation pass (a bare install is not sufficient)
- complete within a profile-configured timeout (default 15 minutes)
- require no interactive input

A target whose only available command is install without downstream verification must remain `manual_only`.

For allowlisted deterministic `code scanning` rules that operate on repository metadata such as GitHub Actions workflows, the rule contract may supply focused rule-specific verification in place of dependency-graph verification.

For `secret_scanning`, focused cleanup verification may be used when it proves that secret material was removed or replaced safely, but relevant mapped-target validation commands must still run when they exist.

The automation mode must be evaluated before any patching begins.

## Remediation Unit

For `Dependabot`, the remediation unit is:

- one repository entry
- one base branch
- one `target_id`

The normalized remediation key should include:

- `profile.owner/repo`
- alert class
- base branch
- `target_id`

For `code_scanning`, the normalized remediation key must also include the normalized rule id or rule family so different allowlisted rules in the same target do not compete for one branch or PR.

For `secret_scanning`, the normalized remediation key must also include the GitHub alert number so distinct secret alerts in the same target stay isolated.

When one remediation unit needs finer distinction because the underlying alert set changed materially, the framework may append a normalized alert-set hash. The base remediation key must remain stable across runs.

An alert-set change is material only when a new advisory enters scope and is not satisfied by the currently selected fix, or when the smallest patched version allowed by policy changes. CVSS rescoring, advisory text edits, or other metadata-only updates do not create a new remediation unit.

Do not combine unrelated targets into one pull request.

## Branch Naming

Agent-managed branches follow the template `security/{alert_class}/{target_id}/{remediation_key_short}`. `remediation_key_short` is the first 12 characters of a stable hash over the full remediation dedup key. This keeps branch names readable while remaining stable and collision-resistant across runs.

## Native PR Strategy

For `Dependabot`, the scaffold uses `adopt-first` behavior.

- native Dependabot PR matching is candidate discovery only: `owner/repo + base_branch + manifest_path + package_ecosystem + head_branch_prefix`, where `head_branch_prefix` comes from the selected profile and defaults to `dependabot/` in the public template
- native PR candidates are re-evaluated structurally on every pass; PR body metadata is advisory only
- adoption requires current advisory-set equivalence
- adoption also requires confirmation that the PR still represents the smallest patched fix allowed by policy
- re-stamp PR body metadata on every pass as a best-effort breadcrumb for human readers
- verification of an adopted native PR runs against a local checkout of that PR head ref without pushing commits
- merge of an adopted native PR means a GitHub merge API call after the review gate passes, not a push to the Dependabot branch
- agent-managed PR matching is by remediation dedup key carried in branch naming and PR body metadata
- optional static labels may be added for categorization, but labels are not part of the remediation dedup contract
- if no usable native PR exists, open or update one deduplicated agent-managed PR
- do not create parallel PRs for the same remediation unit

## Outcome States

Every processed remediation unit should end in exactly one outcome:

- `merged`: remediation completed and merged
- `opened_pr`: remediation prepared and pull request opened or updated
- `blocked`: remediation exists or was attempted but cannot proceed under current policy or environment
- `skipped`: intentionally not processed because of policy or unsupported scope
- `failed`: execution error or unrecoverable tooling failure

Reason codes use a closed reason-code vocabulary and must be reported consistently:

- `superseded`
- `advisory_withdrawn`
- `dependency_removed`
- `unsupported_alert_class`
- `unsupported_ecosystem`
- `verification_unavailable`
- `verification_failed`
- `checks_pending`
- `checks_red`
- `branch_protection_block`
- `manifest_change_required`
- `no_patch_available`
- `clone_missing`
- `rate_limited`
- `env_mismatch`
- `auth_insufficient`
- `registry_auth_missing`
- `lock_contended`
- `policy_blocked`
- `unsupported_rule`
- `code_scanning_disabled`
- `secret_scanning_disabled`
- `no_analysis_found`
- `history_rewrite_required`

## Merge Timing

The scaffold uses a two-pass merge model.

- remediation pass: discover alerts, adopt or open PRs, and apply the review gate using current status
- merge pass: re-evaluate existing PRs and merge only after checks are green

## Exhaustive Dependabot Runs

Within one locked profile run, the agent should exhaust eligible `Dependabot` work in `active` repository entries.

- repeat discovery, normalization, remediation, review, merge, and rediscovery until an iteration creates no new PR and performs no merge
- after every merge, re-query open `Dependabot` alerts before deciding the run is complete
- it is valid to end a run with `opened_pr` units still waiting on required checks, but only after all other eligible units in scope were processed
- after `Dependabot` convergence, the run may continue into the code-scanning and secret-scanning passes

## Code Scanning Runs

After `Dependabot` work converges, a locked run may process eligible `code scanning` work in `active` repository entries.

- query open `code scanning` alerts for each active repository entry
- if GitHub reports that code scanning is disabled, record `skipped` with reason `code_scanning_disabled`
- if GitHub reports that no analysis exists, record `skipped` with reason `no_analysis_found`
- only rule ids allowlisted in the selected profile's `defaults.code_scanning.allowlisted_rules` may enter remediation
- rules outside the allowlist are `skipped` with reason `unsupported_rule`
- merge decisions for allowlisted rules still flow through the review gate

## Secret Scanning Runs

After `code_scanning` work converges, a locked run may process eligible `secret_scanning` work in `active` repository entries.

- query open `secret_scanning` alerts for each active repository entry that enables the alert class
- if GitHub reports that secret scanning is disabled or unavailable, record `skipped` with reason `secret_scanning_disabled`
- map each alert to the nearest enabled `target_id` that owns the affected path, using the root target for repository-level alerts
- record one incident triage state per alert: `active`, `revoked`, `historical`, or `false_positive`
- deterministic cleanup may open or update a review-required pull request
- secret-scanning pull requests never auto-merge
- alerts that require history rewrite, external provider mutation, dismissal review, or non-deterministic edits should remain `blocked` or `skipped` with explicit follow-up actions

## Current Scope Boundary

The current scaffold supports:

- `Dependabot` remediation
- a very small allowlist of deterministic `code_scanning` remediation
- `secret_scanning` response with review-required cleanup PRs when deterministic cleanup is possible

The current scaffold still does not rotate credentials, dismiss alerts, rewrite history, or auto-merge `secret_scanning` pull requests.
