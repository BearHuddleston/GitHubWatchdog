---
name: githubwatchdog-cli
description: Use this skill when working in the GitHubWatchdog repository to scan GitHub repositories or users for suspicious or malicious patterns with the local `githubwatchdog` CLI. Trigger it for broad search runs, targeted repo or user checks, mixed target verdict batches, checkpoint resume/export workflows, or any task where an agent needs machine-readable findings from this repo's scanner.
---

# GitHubWatchdog CLI

## Overview

Use the local CLI instead of reimplementing scans or calling GitHub directly for normal detection tasks. Prefer JSON or NDJSON output so downstream agents can parse results without scraping text output.

Read [references/commands.md](references/commands.md) when you need exact command patterns or a reminder of key output fields.

## Quick Start

Before running scans:

- Ensure `GITHUB_TOKEN` is set, or confirm the requested config file contains a token.
- Run commands from the repo root.
- Prefer the existing SQLite database unless the user asks for an isolated run.
- Use `--persist=false` for one-off checks that should not mutate local scan state.

Build the binary only when that is materially helpful. `go run ./cmd/app ...` is usually sufficient for ad hoc runs.

## Choose the Right Command

- Use `search` for broad GitHub repository discovery.
- Use `repo <owner>/<repo>` when the target is definitely a repository and you want the full report or repo summary.
- Use `user <username>` when the target is definitely a user and you want the full report or user summary.
- Use `verdict <owner/repo|username>` when the target type may vary or you only need the compact verdict block.
- Use `verdict --input ...` for newline-delimited mixed repo/user target batches.
- Use `checkpoints` when a long-running `search` must be resumed, inspected, exported, imported, or pruned.

## Run Agent-Friendly Scans

Prefer these output modes:

- Use `--format json` for single-shot machine-readable output.
- Use `--format ndjson` for long-running or streaming workflows.
- Use `--format text` only when the user explicitly wants a human-oriented summary.

Prefer these control flags:

- Add `--fail-on-findings` when the calling workflow should exit non-zero on suspicious results. Exit code `10` means findings were present.
- Add `--only-flagged` on `search` when the caller only cares about suspicious repositories.
- Add `--continue-on-error` on batch `verdict --input ...` runs when partial results are better than aborting on the first bad target.
- Add `--summary` on `repo` or `user` when the caller only needs the compact verdict instead of the full report payload.

## Handle Incremental Search Work

Use built-in profiles before inventing raw queries:

- `recent`
- `high-signal`
- `backfill`

Use checkpoint workflows for resumable scans:

- Save a cursor with `search --checkpoint <name>`.
- Resume with `search --checkpoint <name> --resume`.
- Export or import state with `checkpoints export` and `checkpoints import`.
- Inspect with `checkpoints show <name>` before resuming when the scan window matters.

Do not manually rebuild `updated:` query fragments when `--since` or `--updated-before` can express the same intent. The CLI already validates and applies those qualifiers.

## Summarize Results Correctly

- Treat `repo`, `user`, and `verdict` summary output as the authoritative compact verdict block.
- For `search --format ndjson`, expect result events followed by a final summary event.
- Preserve scan metadata such as `profile_name`, `query`, `since`, `updated_before`, `checkpoint_name`, and `next_updated_before` when reporting what was executed.
- Call out whether findings came from repository heuristics, owner suspicion, or user heuristics when summarizing flagged results.

## Guardrails

- Do not describe removed web functionality or suggest `serve`; this repo is CLI-only now.
- Do not bypass the CLI with ad hoc GitHub API requests unless the user explicitly needs data the CLI cannot provide.
- Do not silently mutate scan state when the user asked for a dry run; use `--persist=false`.
- Do not assume a non-zero exit always means a runtime failure. Exit code `10` is an expected findings signal when `--fail-on-findings` is enabled.

## Examples

```bash
go run ./cmd/app search --profile recent --only-flagged --format ndjson --fail-on-findings
go run ./cmd/app repo owner/repo --summary --format json
go run ./cmd/app verdict --input targets.txt --format ndjson --continue-on-error
go run ./cmd/app checkpoints show backlog
```
