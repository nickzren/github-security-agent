---
name: "github-security-account-discovery"
description: "Use when you need to validate a selected profile, inspect the runtime contract, and map repository entries to local clone paths before any remediation work starts."
---

# GitHub Security Account Discovery

Use this skill before any remediation run.

## Source Of Truth

Read these files first:

1. `../../docs/runtime-contract.md`
2. `../../docs/operating-model.md`
3. the selected `profile.yaml`

## Scope

This skill validates execution inputs. It does not patch repositories, open pull requests, or merge anything.

## Required Workflow

1. Identify the selected `profile`.
2. Validate the runtime contract defined by the profile.
3. Confirm the GitHub owner and account type.
4. Confirm the profile is using the supported `gh` plus PAT-style auth model for v1.
5. Confirm the authenticated GitHub identity satisfies the required capabilities declared in the profile.
6. Inspect `{clone_root}/.github-security-agent.{profile_id}.lock`. Report whether the lock is absent, active, or stale so a remediation run can decide whether to acquire it.
7. Enumerate `repository entry` values from the profile.
8. Validate each configured `local_path`.
9. Validate that each `repository entry` has stable `target_id` values.
10. Validate that branch naming and PR metadata can carry the remediation dedup key.
11. Detect missing local clones, stale paths, duplicate `target_id` values, or missing verification commands.
12. For every `active` target, confirm the verification commands declared in the profile look like real verification, not bare install commands.
13. For every `active` or `manual_only` target, surface any declared `platform_constraints` that operators should see before remediation runs.
14. For every `active` target, inspect structured environment requirements and report:
   - missing `required_env_vars`
   - unsupported `supported_platforms`
   - declared `verification_workdir` values that do not exist
15. If the profile supports `code_scanning`, inspect repository coverage state and distinguish:
   - code scanning enabled with analysis available
   - code scanning disabled
   - no analysis found
16. If the profile supports `secret_scanning`, inspect repository coverage state and distinguish:
   - secret scanning enabled or available
   - secret scanning disabled or unavailable
17. Summarize which repository entries are `active`, `manual_only`, or `ignored`.

## Execution Rules

- Do not create new clones in v1.
- Do not infer missing profile data from repository state.
- Treat the profile as the source of truth.
- Treat unsupported auth modes as contract failures.
- Treat insufficient GitHub capabilities as contract failures.
- Verify capabilities via direct endpoint probes (for example, a read of `/repos/{owner}/{repo}/dependabot/alerts`) rather than relying on `gh auth status` scope text, which may report stale cached scopes that do not reflect the active token's real capabilities.
- Report contract errors clearly before any remediation skill runs.
- Use the closed v1 reason-code vocabulary from `../../docs/operating-model.md` for any contract failure surfaced to reporting.

## Expected Output

Return a concise account inventory that includes:

- profile name
- GitHub owner
- runtime contract status
- auth model status
- GitHub capability check status
- concurrency lock status (absent, active, stale)
- repository entries by automation mode
- missing or invalid local paths
- invalid or duplicate `target_id` values
- targets with missing or weak verification commands
- targets with environment mismatches or missing required environment variables
- surfaced `platform_constraints` for `active` or `manual_only` targets when they explain readiness, review requirements, or known operator assumptions
- code-scanning coverage status by repository entry
- secret-scanning coverage status by repository entry
