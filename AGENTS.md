# GitHub Security Agent Instructions

Use [SKILL.md](SKILL.md) as the canonical entrypoint for this repository.

## Source Of Truth

Read these before changing anything:

1. [SKILL.md](SKILL.md)
2. [docs/runtime-contract.md](docs/runtime-contract.md)
3. [docs/operating-model.md](docs/operating-model.md)
4. [docs/code-scanning-policy.md](docs/code-scanning-policy.md)
5. [docs/secret-scanning-policy.md](docs/secret-scanning-policy.md)
6. [docs/review-gate.md](docs/review-gate.md)
7. [docs/reporting-model.md](docs/reporting-model.md)
8. the selected `profile.yaml`

## Execution Order

For one selected profile, run work in this order:

1. account discovery
2. profile lock
3. exhaustive `Dependabot`
4. allowlisted deterministic `code_scanning`
5. `secret_scanning` response
6. review gate
7. reconcile stale or superseded PRs
8. final reporting
9. lock release

## Rules

- The selected `profile.yaml` is the live source of truth.
- Do not invent policy beyond the selected profile and public docs.
- `secret_scanning` cleanup PRs are review-required and never auto-merge.
- Do not rotate credentials, dismiss alerts, or rewrite git history automatically.
- Treat `PLAN.md`, `profiles/local/`, and `.claude/` as local-only material, not part of the public contract.
