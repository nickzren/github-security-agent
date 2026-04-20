# Runtime Contract

## Clone Handling

V1 assumes repositories are already cloned locally under the configured clone root.

- the framework may validate configured local paths
- the framework may fetch or refresh existing clones when policy allows
- the framework must not create new clones automatically in v1
- a missing local path should result in `blocked` or `skipped` with reason `clone_missing`, not an implicit clone step

## Execution Model

V1 is local-first and pre-cloned.

- the framework runs on a machine with direct access to the configured clone root
- unattended cron-style runs are compatible with this model
- GitHub Actions-first execution is not part of the v1 contract
- one locked run should exhaust eligible `Dependabot` work in `active` repository entries before it exits
- after `Dependabot` converges, the same locked run may triage and remediate allowlisted deterministic `code scanning` findings in `active` repository entries
- after `code scanning` converges, the same locked run may triage and respond to eligible `secret scanning` alerts in `active` repository entries
- after every merge, refresh alert state before deciding the run is complete
- pending required checks may defer a unit to a later merge pass, but should not prevent processing other eligible units in the same run
- repositories where code scanning is disabled or has no analysis should be reported, not treated as silent success
- repositories where secret scanning is disabled or unavailable should be reported, not treated as silent success

## Required Tools

The runner should provide:

- `git`
- `gh`
- required ecosystem tooling for each configured `target_id`

Examples of target-specific tooling:

- `npm`
- `pnpm`
- `uv`
- `pytest`

## Target Environment Handling

Targets may declare structured environment requirements in the selected profile:

- `verification_workdir`
- `required_env_vars`
- `supported_platforms`
- `platform_constraints`

The agent should evaluate these before running verification:

- if required environment variables are missing, return `env_mismatch` or `registry_auth_missing`
- if the current runner platform is not listed in `supported_platforms`, return `env_mismatch`
- if `verification_workdir` is declared, run verification from that directory instead of assuming the repository root
- `platform_constraints` is informational metadata only; it should be surfaced in discovery and reporting, but it does not block execution unless a separate enforced field such as `required_env_vars` or `supported_platforms` also fails

Do not silently skip verification because of environment mismatch. Report the blocker explicitly.

## GitHub Authentication

V1 supports `gh` with a PAT-style auth model only.

- supported: classic PAT exposed through `gh auth`
- supported: fine-grained PAT exposed through `gh auth`
- not supported in v1: GitHub App auth
- not supported in v1: `GITHUB_TOKEN`-only Actions execution

The authenticated GitHub identity must have enough capability to:

- read repository metadata
- read security alerts for repositories in scope
- push branches to repositories in scope
- open and update pull requests
- read workflow and check status
- merge pull requests where branch protection permits

Required checks are defined by branch protection on the base branch, not by the agent. If branch protection cannot be read, the correct outcome is `blocked` with reason `auth_insufficient` or `rate_limited`, not a silent skip.

The framework should not assume administrative access unless a specific profile says otherwise.

## Concurrency

V1 allows one active run per profile at a time.

- the lock file is `{clone_root}/.github-security-agent.{profile_id}.lock`
- the lock record captures at least the PID, start time, and stale-lock TTL
- if the lock is active and not stale, the next run must stop with reason `lock_contended` before mutating any repository state
- if the lock is stale, the next run may replace it and must record the recovery in the run report

Lock scope is the profile, not the repository, because GitHub API rate limits and remediation policy are both profile-level concerns.

Per remediation unit, use compare-and-set behavior before creating new work. If a branch or PR already exists for the same remediation dedup key, enter adopt or update flow instead of create flow. If branch creation or PR creation loses a race (for example GitHub returning `422 Unprocessable Entity`), re-enter adopt or update flow instead of failing.

## Rate Limits

If GitHub API limits prevent reliable alert discovery, PR inspection, or merge decisions, the run should stop promotion and return `failed` or `blocked` with reason `rate_limited` instead of continuing with partial state.

## Secret Handling During Verification

Secrets used by verification must come only from profile-declared environment variable names, read from the runner environment or from an explicit `.env` file path declared in the profile.

- never log secret values
- never write secret values into run reports or PR bodies
- never commit files that match profile-declared secret redaction patterns
- run verification commands with the profile's `verification.environment_allowlist` applied, not the full process environment
- when verification requires credentials the runner cannot provide, return `blocked` with reason `registry_auth_missing` or `env_mismatch` instead of a silent skip

## PR Body Metadata Schema

Agent-managed PRs, and adopted native Dependabot PRs after stamping, carry one HTML comment block with a JSON object describing the remediation unit. The required fields are:

- `schema_version`
- `remediation_key`
- `alert_class`
- `target_id`
- `base_branch`
- `advisory_ids`: sorted array of advisory identifiers (for `Dependabot` remediation units)
- `alert_number`: GitHub alert id (required for `code_scanning` and `secret_scanning` remediation units)
- `secret_type`: detected secret type (`secret_scanning` only)
- `agent_version`
- `last_pass_at`

This metadata is advisory only. It helps human readers and agent-managed PR reuse, but adopted native Dependabot PRs must still be re-evaluated structurally on every pass.

## Reason Codes

Every non-`merged`, non-`opened_pr` outcome must carry a reason code from the closed v1 vocabulary defined in `operating-model.md`. Do not invent new reason codes in v1.

## Failure Behavior

If the runtime contract is not satisfied, the run should fail fast with a clear contract error.

Do not degrade into partial remediation when the runner cannot reliably discover alerts, patch repositories, or verify the result.
