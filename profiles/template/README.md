# Profile Template

Use this directory as the source of truth for profile field names and vocabulary.

## Vocabulary

- `profile`: one account-level configuration
- `owner_type`: allowed values are `user` or `org`
- `repository entry`: one repository definition inside the profile
- `target_id`: one stable remediation target inside a repository entry
- `remediation dedup key`: the stable identity carried through branch naming, PR metadata, and reporting

## Rules

- every repository entry must declare an automation mode
- every supported target must declare a stable `target_id`
- every active target must declare at least one real verification command; for dependency remediation this should exercise the dependency graph, and for metadata-only or secret-cleanup workflows it should provide relevant repository validation
- the runtime contract belongs to the profile, not to ad hoc agent state
- branch naming and PR metadata should support the remediation dedup key
- optional static labels may be used for categorization, but they are not part of the remediation dedup contract

The remediation dedup key is constructed by combining `profile.owner` with each repository entry's `repo` field, then adding alert class, base branch, and `target_id`. For `code_scanning`, the dedup key also includes the normalized rule id or rule family. For `secret_scanning`, the dedup key also includes the GitHub alert number.

## Profile-Level Sections

The template defines four profile-level sections that the agent must respect:

- `auth`: GitHub host, supported auth modes, and required capabilities
- `runtime`: clone root, clone-handling mode, execution mode, and required local tools
- `concurrency`: lock filename and stale-lock TTL, scoped to the profile
- `verification`: default timeout, environment variable allowlist, optional `.env` path, and secret redaction patterns

## Target-Level Environment Fields

Each target may also declare structured environment-handling fields:

- `verification_workdir`: working directory to use when running verification commands
- `required_env_vars`: environment variables that must exist before verification can run
- `supported_platforms`: allowed runner platforms for that target, such as `darwin` or `linux`
- `platform_constraints`: informational notes about known runtime or verification limits for that target

Missing required environment variables should resolve to `env_mismatch` or `registry_auth_missing`. Unsupported runner platforms should resolve to `env_mismatch`, not silent skip.

`platform_constraints` is descriptive metadata, not an execution gate by itself. Use it to explain why a target stays `manual_only`, why a repository is review-required, or what operator assumption a run should surface in reporting.

`defaults.auto_merge.ecosystem_rules` defines per-ecosystem diff constraints for automatic merge. Any ecosystem not listed in `ecosystem_rules` falls back to `unlisted_ecosystem_outcome` (default `opened_pr`). These profile fields are the live source of truth for remediation and review skills.

That fallback is how manifest-review-only ecosystems such as `maven` can still enter remediation while remaining review-required instead of silently unsupported.

`defaults.native_dependabot_head_branch_prefix` defines the expected native Dependabot branch prefix for candidate discovery. The public template default is `dependabot/`.

`defaults.code_scanning.allowlisted_rules` defines which code-scanning rules may enter remediation. `defaults.code_scanning.auto_merge_rules` is narrower: only those rules may merge automatically after the review gate passes. Rules outside the allowlist are report-only.

`defaults.secret_scanning` defines whether deterministic cleanup PRs may be prepared, whether placeholder or environment-variable replacement is allowed, whether ignore-pattern based cleanup is allowed, and the title template for review-required cleanup PRs. Secret-scanning pull requests are never auto-merged by this scaffold, and these fields are enforced by the secret-scanning response skill and review gate.

Reason codes returned by skills must come from the closed reason-code vocabulary documented in `docs/operating-model.md`.

Use the template file in this directory as the starting point for new adopters.
