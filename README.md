# GitHubWatchdog

GitHubWatchdog is a Go CLI for scanning GitHub repositories and users for suspicious or malicious patterns. It can run broad searches, targeted repo or user scans, mixed-target verdict batches, and a local web UI backed by SQLite.

The CLI is designed to be agent-friendly:

- JSON is the default output for scan commands.
- `ndjson` is available for streaming workflows.
- Exit code `10` signals findings when `--fail-on-findings` is used.
- Search checkpoints can be saved, resumed, exported, and imported.

## Requirements

- Go 1.23.5 or newer
- A GitHub token in `GITHUB_TOKEN`

Example:

```bash
export GITHUB_TOKEN=your_token_here
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

Start the local web UI:

```bash
./githubwatchdog serve
```

The web server listens on [http://127.0.0.1:8080](http://127.0.0.1:8080) by default.

## Commands

```text
githubwatchdog [global flags] search [search flags]
githubwatchdog [global flags] repo <owner>/<repo> [scan flags]
githubwatchdog [global flags] user <username> [scan flags]
githubwatchdog [global flags] verdict <owner/repo|username> [verdict flags]
githubwatchdog [global flags] checkpoints <list|show|delete|export|import> [args]
githubwatchdog [global flags] serve [serve flags]
```

Global flags:

- `-config`: path to config file, default `config.json`
- `-db`: path to SQLite database, default `github_watchdog.db`

Running the binary with no subcommand is equivalent to `search`.

## Search Workflows

Basic search:

```bash
./githubwatchdog search --query 'created:>2026-01-01 stars:>5' --max-pages 2
```

Only emit flagged results and fail the run if any are found:

```bash
./githubwatchdog search --only-flagged --fail-on-findings
```

Stream results as they are discovered:

```bash
./githubwatchdog search --format ndjson --only-flagged
```

Add validated time filters without editing raw `updated:` qualifiers:

```bash
./githubwatchdog search --since 2026-03-01 --updated-before 2026-03-13
```

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

- `profile_name`
- `base_query`
- `query`
- `since`
- `updated_before`
- `checkpoint_name`
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

## Output and Exit Codes

Supported output formats:

- `json`
- `text`
- `ndjson`

Notes:

- `search` defaults to `json`, and `ndjson` streams one result per line plus a final summary line.
- `repo`, `user`, and `verdict` support compact summary output for automation.
- `--fail-on-findings` returns exit code `10` when suspicious results are present.

## Configuration

`config.json` is optional. If loading it fails but `GITHUB_TOKEN` is set, the CLI falls back to built-in defaults plus the environment token.

Example `config.json`:

```json
{
  "max_pages": 10,
  "per_page": 100,
  "github_query": "created:>2025-02-25 stars:>5",
  "max_concurrent": 50,
  "rate_limit_buffer": 500,
  "cache_ttl": 60,
  "verbose": true
}
```

## Web UI

Start the UI:

```bash
./githubwatchdog serve
```

Custom address:

```bash
./githubwatchdog serve --addr :9090
```

The web server binds to loopback by default. The UI provides:

- dashboard views for repositories, users, and flags
- sortable tables and pagination
- repo and user detail pages
- manual status toggles
- README rendering for repository reports

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
