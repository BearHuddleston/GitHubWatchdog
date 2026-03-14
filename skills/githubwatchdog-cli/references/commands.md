# GitHubWatchdog Command Patterns

## Search

Use `search` for broad repository discovery.

Auth can come from `GITHUB_TOKEN`, `GH_TOKEN`, or a logged-in `gh` session.
For agent flows, derive `--since` and `--updated-before` from the user's prompt instead of inventing unrelated fixed dates.

```bash
go run ./cmd/app search --profile recent --only-flagged --format ndjson
go run ./cmd/app search --query 'stars:>20' --since 2026-03-01 --updated-before 2026-03-13
go run ./cmd/app search --profile backfill --checkpoint backlog
go run ./cmd/app search --checkpoint backlog --resume
```

Useful flags:

- `--only-flagged`
- `--include-skipped=false`
- `--fail-on-findings`
- `--format json|ndjson|text`
- `--profile recent|high-signal|backfill`
- `--checkpoint <name>`
- `--resume`
- `--since`
- `--updated-before`
- `--persist=false`

Output notes:

- `json` returns a single search report.
- `ndjson` streams per-result objects and ends with a summary object.
- `--fail-on-findings` returns exit code `10` when flagged results are present.
- Add the global `-quiet` flag when the caller wants clean stderr during machine-readable runs.

## Repository and User Scans

Use `repo` or `user` when the target type is known.

```bash
go run ./cmd/app repo owner/repo --summary --format json
go run ./cmd/app user octocat --summary --format json
```

Useful flags:

- `--summary`
- `--fail-on-findings`
- `--format json|ndjson|text`
- `--persist=false`

## Verdict

Use `verdict` when the target may be either a repo or a user, or when running mixed-target batches.

```bash
go run ./cmd/app verdict owner/repo --format json
go run ./cmd/app verdict octocat --format json
go run ./cmd/app verdict --input targets.txt --format ndjson --continue-on-error
```

Batch input rules:

- Pass newline-delimited targets with `--input <path>` or `--input -` for stdin.
- Use `--continue-on-error` if one bad target should not abort the whole run.
- In batch mode, `json` returns an array; `ndjson` returns one object per line.

## Checkpoints

Use `checkpoints` to manage saved search cursors.

```bash
go run ./cmd/app checkpoints list
go run ./cmd/app checkpoints show backlog
go run ./cmd/app checkpoints export backlog --format json
go run ./cmd/app checkpoints import --input backlog.json
go run ./cmd/app checkpoints delete backlog
```

## High-Signal Fields

When summarizing machine-readable output, preserve these fields when present:

- `entity_type`
- `repo_id`
- `username`
- `is_flagged`
- `is_malicious`
- `owner_suspicious`
- `is_suspicious`
- `repo_flags`
- `heuristics`
- `errors`
- `profile_name`
- `query`
- `checkpoint_name`
- `next_updated_before`
