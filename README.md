# GitHub Security Agent

Agent framework for reducing GitHub security alerts across many repositories. Profile-driven, local-first, and scoped to remediation patterns that are mechanically verifiable.

## Scope

The current scaffold supports:

- GitHub `Dependabot` alerts — exhaustive remediation within one locked run
- Selected GitHub `code scanning` rules with deterministic fixes — allowlisted per profile
- GitHub `secret scanning` response — review-required cleanup PRs when deterministic repository cleanup is possible

Not supported for automatic merge:

- `code scanning` rules outside the selected profile allowlist
- `secret scanning` cleanup PRs (always review-required)
- any finding that requires infrastructure, product, or compliance decisions

The scaffold never rotates credentials, dismisses alerts, rewrites git history, or pushes commits to Dependabot-authored branches.

## Quick Start

1. Fork or clone this repository.
2. Create `profiles/local/<your-owner>/`, then copy `profiles/template/profile.yaml` to `profiles/local/<your-owner>/profile.yaml`. The `profiles/local/` directory is gitignored.
3. Fill in `profile_id`, `owner`, `owner_type`, `runtime.local_clone_root`, and per-repo `local_path` to match your environment.
4. For each repository entry, set `automation_mode: active` only when every enabled target has real verification commands. Otherwise use `manual_only`. See [docs/operating-model.md](docs/operating-model.md) for the verification command contract.
5. Authenticate `gh` with a PAT or fine-grained token that has the required capabilities (see [docs/runtime-contract.md](docs/runtime-contract.md)).
6. Invoke the root [SKILL.md](SKILL.md) with your selected profile.

## Operating Model

The framework is organized around a `profile` that describes one GitHub owner. Each profile contains `repository entry` definitions, each with stable `target_id` values for remediation targets (e.g. `root`, `ui`, `api-server`).

Every locked run acquires a profile-scoped lock under the clone root, then processes eligible work in this order: exhaustive `Dependabot` → allowlisted `code scanning` → `secret scanning` response → review gate → reconcile → report.

Each remediation unit has a stable dedup key (`owner/repo + alert_class + base_branch + target_id`, with normalized rule id or GitHub alert number appended for `code_scanning` and `secret_scanning` respectively) that flows through branch naming, PR body metadata, and run reporting.

## Contract Documents

Public contracts live in `docs/`:

- [docs/runtime-contract.md](docs/runtime-contract.md) — clone handling, authentication, concurrency, rate limits, target environment handling, secret handling, PR body metadata schema
- [docs/operating-model.md](docs/operating-model.md) — vocabulary, repository modes, remediation unit, branch naming, native PR strategy, outcome states, reason codes, exhaustive run model
- [docs/code-scanning-policy.md](docs/code-scanning-policy.md) — allowlist model, coverage states, rule contracts
- [docs/secret-scanning-policy.md](docs/secret-scanning-policy.md) — deterministic cleanup contract, response buckets, PR rules
- [docs/review-gate.md](docs/review-gate.md) — pre-merge verification per alert class
- [docs/reporting-model.md](docs/reporting-model.md) — summary fields, outcome semantics, reporting rules

## Reporting

Every locked run writes one JSON Lines record per remediation unit to `{clone_root}/.github-security-agent/runs/{profile_id}/{iso8601_utc}.jsonl`, plus a companion `latest.json` summary overwritten on each run. Blocked and skipped findings appear in the same report with their reason code and any relevant `platform_constraints` or manual follow-up actions. See [docs/reporting-model.md](docs/reporting-model.md) for the per-unit summary schema.

## Repository Layout

```text
SKILL.md
README.md
LICENSE
docs/
  code-scanning-policy.md
  secret-scanning-policy.md
  operating-model.md
  review-gate.md
  runtime-contract.md
  reporting-model.md
skills/
  account-discovery/
  code-scanning-triage/
  code-scanning-remediator/
  dependabot-remediator/
  secret-scanning-response/
  review-gate/
  reporting/
profiles/
  template/
  examples/
  local/          # gitignored account-specific overlays
```

## Skills

- [SKILL.md](SKILL.md) — canonical entrypoint for one selected profile
- [skills/account-discovery/SKILL.md](skills/account-discovery/SKILL.md) — profile and runtime validation
- [skills/dependabot-remediator/SKILL.md](skills/dependabot-remediator/SKILL.md) — `Dependabot` alert remediation
- [skills/code-scanning-triage/SKILL.md](skills/code-scanning-triage/SKILL.md) — classify `code scanning` alerts
- [skills/code-scanning-remediator/SKILL.md](skills/code-scanning-remediator/SKILL.md) — allowlisted deterministic remediation
- [skills/secret-scanning-response/SKILL.md](skills/secret-scanning-response/SKILL.md) — cleanup PRs with manual follow-up recording
- [skills/review-gate/SKILL.md](skills/review-gate/SKILL.md) — pre-merge policy decision
- [skills/reporting/SKILL.md](skills/reporting/SKILL.md) — run summary

## Profiles

- [profiles/template/profile.yaml](profiles/template/profile.yaml) — canonical schema
- [profiles/template/README.md](profiles/template/README.md) — profile vocabulary and rules
- [profiles/examples/acme-org/profile.yaml](profiles/examples/acme-org/profile.yaml) — organization profile example

Account-specific runnable overlays should live under `profiles/local/`, which is gitignored.

## License

MIT — see [LICENSE](LICENSE).
