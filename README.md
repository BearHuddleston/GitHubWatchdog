# GitHubWatchdog

GitHubWatchdog is an agent-first Go CLI for scanning GitHub repositories and users for suspicious or malicious patterns. It can run broad searches, targeted repo or user scans, and mixed-target verdict batches backed by SQLite.

The CLI is designed to be agent-friendly:

- JSON is the default output for scan commands.
- `ndjson` is available for streaming workflows.
- `capabilities` exposes a machine-readable command and flag catalog.
- `recommend` turns a natural-language task into a deterministic command suggestion.
- Exit code `10` signals findings when `--fail-on-findings` is used.
- Search checkpoints can be saved, resumed, exported, and imported.
- `-quiet` suppresses informational stderr logs for cleaner automation.

## Requirements

- Go 1.23.5 or newer
- GitHub auth via one of:
  - `GITHUB_TOKEN`
  - `GH_TOKEN`
  - an authenticated `gh` session

Example:

```bash
export GITHUB_TOKEN=your_token_here
```

Or authenticate once with GitHub CLI:

```bash
gh auth login
```

## Build

```bash
go build -o githubwatchdog ./cmd/app
```

## Quick Start

Run the default batch search:

```bash
./githubwatchdog
```

Scan a single repository:

```bash
./githubwatchdog repo BearHuddleston/GitHubWatchdog
```

Scan a single user:

```bash
./githubwatchdog user octocat
```

Emit a compact verdict instead of the full payload:

```bash
./githubwatchdog verdict BearHuddleston/GitHubWatchdog
./githubwatchdog verdict octocat
```

## Commands

```text
githubwatchdog [global flags] search [search flags]
githubwatchdog [global flags] repo <owner>/<repo> [scan flags]
githubwatchdog [global flags] user <username> [scan flags]
githubwatchdog [global flags] verdict <owner/repo|username> [verdict flags]
githubwatchdog [global flags] checkpoints <list|show|delete|export|import> [args]
githubwatchdog [global flags] capabilities [--format json|text]
githubwatchdog [global flags] recommend <task...>
```

Global flags:

- `-config`: path to config file, default `config.json`
- `-db`: path to SQLite database, default `github_watchdog.db`
- `-quiet`: suppress informational logs on stderr

Running the binary with no subcommand is equivalent to `search`.

## Search Workflows

Basic search:

```bash
./githubwatchdog search --query 'stars:>5' --since 2026-03-01 --max-pages 2
```

Only emit flagged results and fail the run if any are found:

```bash
./githubwatchdog search --only-flagged --fail-on-findings
```

Stream results as they are discovered:

```bash
./githubwatchdog search --format ndjson --only-flagged
```

Add validated updated-time filters without editing raw `updated:` qualifiers:

```bash
./githubwatchdog search --since 2026-03-01 --updated-before 2026-03-13
```

Search by repository creation time instead:

```bash
./githubwatchdog search --activity created --created-since 2026-03-01 --created-before 2026-03-13
```

Search for repositories that are new or recently updated:

```bash
./githubwatchdog search --activity either --created-since 2026-03-10 --since 2026-03-10
```

For agent workflows, derive the time window from the prompt. If the prompt implies "up to now", prefer lower-bound flags only and omit unnecessary upper bounds.

Use a built-in profile:

```bash
./githubwatchdog search --profile recent
./githubwatchdog search --profile high-signal --only-flagged
./githubwatchdog search --list-profiles
```

Built-in profiles:

- `recent`
- `high-signal`
- `backfill`

Search output includes scan metadata such as:

- `activity`
- `profile_name`
- `base_query`
- `query`
- `queries`
- `since`
- `created_since`
- `created_before`
- `updated_since`
- `updated_before`
- `checkpoint_name`
- `next_created_before`
- `next_updated_before`

## Checkpoints

Save and resume long-running searches:

```bash
./githubwatchdog search --profile backfill --checkpoint backlog
./githubwatchdog search --checkpoint backlog --resume
```

Manage stored checkpoints:

```bash
./githubwatchdog checkpoints list
./githubwatchdog checkpoints show backlog
./githubwatchdog checkpoints delete backlog
```

Move checkpoints between machines:

```bash
./githubwatchdog checkpoints export backlog --format json > backlog.json
./githubwatchdog checkpoints import --input backlog.json
```

## Verdict Workflows

Compact targeted verdicts:

```bash
./githubwatchdog repo BearHuddleston/GitHubWatchdog --summary
./githubwatchdog user octocat --summary --format json
./githubwatchdog verdict BearHuddleston/GitHubWatchdog
./githubwatchdog verdict octocat
```

Batch mixed-target verdicts from stdin or a file:

```bash
printf 'BearHuddleston/GitHubWatchdog\noctocat\n' | ./githubwatchdog verdict --input - --format ndjson
./githubwatchdog verdict --input targets.txt --format ndjson --fail-on-findings
./githubwatchdog verdict --input targets.txt --format ndjson --continue-on-error
```

`verdict --continue-on-error` emits per-target error objects in batch mode instead of aborting on the first failure.

## Agent Discovery

Use the binary itself as the authoritative command catalog:

```bash
./githubwatchdog capabilities --format json
```

Ask the CLI for a deterministic recommendation from a user prompt:

```bash
./githubwatchdog recommend --prompt 'find new or updated repos from the last 3 days' --format json
```

`recommend` does not execute scans. It returns the recommended command, resolved time window, assumptions, warnings, and ready-to-run invocations.

## Output and Exit Codes

Supported output formats:

- `json`
- `text`
- `ndjson`

Notes:

- `search` defaults to `json`, and `ndjson` streams one result per line plus a final summary line.
- `repo`, `user`, and `verdict` support compact summary output for automation.
- `capabilities` and `recommend` support `json` and `text`.
- `--fail-on-findings` returns exit code `10` when suspicious results are present.
- `-quiet` is useful for agent runs that want machine-readable output without informational stderr logs.

## Configuration

`config.json` is optional. The CLI can pick up auth from `GITHUB_TOKEN`, `GH_TOKEN`, or a logged-in `gh` session, and falls back to built-in defaults when no config file is present.

Example `config.json`:

```json
{
  "max_pages": 10,
  "per_page": 100,
  "github_query": "stars:>5",
  "max_concurrent": 50,
  "rate_limit_buffer": 500,
  "cache_ttl": 60,
  "verbose": false
}
```

## Development

Run the CLI help:

```bash
go run ./cmd/app help
```

Run tests:

```bash
go test ./...
go vet ./...
```
