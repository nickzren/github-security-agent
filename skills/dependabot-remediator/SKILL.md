---
name: "github-security-dependabot-remediator"
description: "Use when asked to remediate GitHub Dependabot alerts across the repositories defined in one selected profile."
---

# GitHub Security Dependabot Remediator

Use this skill when the task is to reduce open `Dependabot` alerts for one selected `profile`.

## Source Of Truth

Read these files before changing anything:

1. `../../docs/runtime-contract.md`
2. `../../docs/operating-model.md`
3. `../../docs/review-gate.md`
4. `../../docs/reporting-model.md`
5. the selected `profile.yaml`

## Scope

- V1 covers `Dependabot` only.
- The remediation unit is one repository entry, one base branch, and one `target_id`.
- Use one deduplicated pull request per remediation unit.
- Within `active` repository entries, a locked run should exhaust eligible `Dependabot` work before it exits.

## Required Workflow

1. Validate the selected `profile` and runtime contract.
2. Acquire the profile-scoped concurrency lock at `{clone_root}/.github-security-agent.{profile_id}.lock` before any mutation. If the lock is held and not stale, stop the run with reason `lock_contended`.
3. Treat the run as exhaustive for eligible `Dependabot` work in the selected profile. Repeat discovery, normalization, remediation, review, merge, and rediscovery until an iteration creates no new PR and performs no merge.
4. Query open `Dependabot` alerts for the configured GitHub owner.
5. Group alerts by repository, manifest path, package ecosystem, and base branch.
6. Map each alert group to a configured `repository entry` and `target_id`.
7. Apply repository automation mode before any patching:
   - `active`: eligible for remediation
   - `manual_only`: scan and report only
   - `ignored`: skip and report the configured reason
8. Resolve the target base branch from profile data.
9. Compute the remediation dedup key from `owner/repo`, alert class, base branch, and `target_id`.
10. Decide whether the alert set has changed materially. In v1 a change is material only when a new advisory enters scope and is not satisfied by the currently selected fix, or when the smallest patched version allowed by policy changes. CVSS rescoring and other metadata-only updates do not create a new remediation unit.
11. Look for an existing native Dependabot PR that is a structural candidate for the remediation unit by `owner/repo + base_branch + manifest_path + package_ecosystem + head_branch_prefix`, where `head_branch_prefix` comes from the selected profile's `defaults.native_dependabot_head_branch_prefix`.
12. Re-evaluate every native PR candidate structurally on every pass. PR body metadata is advisory only and is not the adoption source of truth.
13. Adopt a native PR only when it has current advisory-set equivalence with the active alert set and still represents the smallest patched fix allowed by policy.
14. Verify an adopted native PR against a local checkout of its head ref. Never push commits to a Dependabot-authored branch.
15. Re-stamp PR body metadata after adoption as a best-effort breadcrumb for human readers, never as the matching contract.
16. If no usable native PR exists, work in the configured `local_path` for the mapped repository entry, create or reuse a branch that follows the profile branch template, and prepare the smallest patched fix.
17. Keep the diff minimal and within the selected profile's `defaults.auto_merge.ecosystem_rules`. If the ecosystem is not listed there, follow `defaults.auto_merge.unlisted_ecosystem_outcome` instead of inventing a new policy. The public docs define the baseline contract, but the selected profile is the live source of truth.
18. Before verification, enforce the mapped target's structured environment requirements:
   - if `required_env_vars` are missing, stop with `env_mismatch` or `registry_auth_missing`
   - if the current runner platform is not listed in `supported_platforms`, stop with `env_mismatch`
   - if `verification_workdir` is declared, run verification from that directory
19. Run the configured verification commands for the mapped `target_id` using the profile's verification environment allowlist. Never log secret values.
20. Run the review gate.
21. In the remediation pass, open or update the deduplicated PR. If required GitHub checks defined by branch protection are still pending, stop at `opened_pr` for that remediation unit and continue processing the rest of the profile.
22. In the merge pass, merge the PR through the GitHub merge API only when the review gate still allows `merged`. For an adopted native PR, merge the existing PR; never push to its branch.
23. After every merge, re-query open `Dependabot` alerts before deciding the run is complete.
24. End the run only when every remaining open `Dependabot` alert in active scope is represented by `opened_pr`, `blocked`, `skipped`, or `failed`, or is outside v1 remediation scope.
25. Release the concurrency lock when the run ends.

## Execution Rules

- Do not create new clones in v1.
- Do not mutate `manual_only` or `ignored` repository entries.
- Use `gh` plus PAT-style authentication only in v1.
- Do not auto-merge unless the diff satisfies the selected profile's `defaults.auto_merge.ecosystem_rules`, with `unlisted_ecosystem_outcome` applied for ecosystems the profile does not list.
- Do not broaden dependency updates when a smaller patched fix exists.
- Prefer adopting a usable native Dependabot PR over opening an agent-managed replacement.
- Use `target_id`, not raw path text alone, for branch naming, PR reuse, PR metadata, and reporting.
- Treat PR body metadata as advisory only. Never use it as the matching source of truth.
- Required GitHub checks are determined by branch protection on the base branch.
- Optional static labels may be applied for categorization, but they are not part of the remediation dedup contract.
- Do not wait indefinitely for GitHub checks in a single iteration. Revisit each `opened_pr` unit on later iterations of the same locked run and merge it when required checks turn green and the review gate still passes.
- Use the closed v1 reason-code vocabulary defined in `../../docs/operating-model.md` for every `blocked`, `skipped`, or `failed` outcome. Do not invent new reason codes.

## Expected Output

Summarize each remediation unit as one of:

- `merged`
- `opened_pr`
- `blocked`
- `skipped`
- `failed`

Attach a v1 reason code from the closed vocabulary to every non-`merged`, non-`opened_pr` outcome.
