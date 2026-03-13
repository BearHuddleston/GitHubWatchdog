# GitHubWatchdog - GitHub Suspicious User Detector

GitHubWatchdog is a Go-based microservice that leverages the GitHub API to search for repositories and analyze their owners for suspicious activity. The tool scans repositories using a predefined search query and applies heuristics to flag users who may exhibit unusual patterns, such as newly created accounts or repositories with low disk usage yet high star counts.

I have personally reported **over 3000+ accounts** using this tool.

## Architecture & Project Structure

```
GitHubWatchdog/
├── cmd/
│   └── app/
│       └── main.go           # CLI entrypoint.
└── internal/
    ├── analyzer/
    │   ├── analyzer.go       # Contains user heuristics and analysis logic.
    │   └── heuristic.go      # Defines heuristic rules for suspicious activity detection.
    ├── cli/
    │   └── app.go            # Subcommand parsing and CLI output formatting.
    ├── config/
    │   └── config.go         # Reads environment variables and sets default configuration.
    ├── db/
    │   └── sqlite.go         # Implements SQLite-based storage for processed users and repositories.
    ├── github/
    │   ├── client.go         # Sets up the GitHub REST client.
    │   ├── cache.go          # Implements caching for GitHub API requests.
    │   └── rate_limiter.go   # Handles GitHub API rate limiting.
    ├── logger/
    │   └── logger.go         # Provides logging functionality.
    ├── models/
    │   └── models.go         # Defines data structures used throughout the application.
    ├── scan/
    │   └── service.go        # Reusable scan service for CLI and agent workflows.
    └── web/
        ├── server.go         # Implements HTTP server for web interface.
        ├── handlers.go       # HTTP request handlers for web interface.
        ├── data.go           # Database query functions for web interface.
        ├── api.go            # API endpoints for GitHub data integration.
        ├── template_funcs.go # Template functions for web interface.
        ├── templates/        # HTML templates for web interface.
        └── static/           # Static assets (CSS, JavaScript) for web interface.
```

## Overview

GitHubWatchdog performs the following tasks:

-   **GitHub Client Initialization:**  
    Creates an authenticated GitHub client using a personal access token (see `internal/github/client.go`).

-   **Repository Search & Processing:**  
    Uses GitHub's REST API to search for repositories matching a specific query (e.g., repositories created after a certain date with more than 5 stars). Results are processed concurrently through the reusable scan service (`internal/scan/service.go`).

-   **Processed Repository Tracking:**  
    The service tracks processed repositories and users in an SQLite database (`github_watchdog.db`) to avoid duplicate analysis. Database interactions are handled by `internal/db/sqlite.go`.

-   **User Analysis:**  
    For repositories with low disk usage, the tool further analyzes the associated user’s account using various heuristics (such as account age, total stars across repositories, and contribution counts). The analysis logic is encapsulated in the `internal/analyzer` package.

-   **Heuristic-Based Suspicious Detection:**  
    The system applies predefined heuristics (see `internal/analyzer/heuristic.go`) to flag accounts with suspicious behavior, such as new accounts with high stars or repositories with empty content but significant stargazer activity.

-   **Suspicious User & Repository Recording:**  
    If a user or repository is flagged as suspicious, the relevant details are logged and stored in the SQLite database.

-   **Agent-Friendly CLI:**  
    The binary exposes explicit `search`, `repo`, `user`, and `serve` commands, with JSON output by default for scan commands.

## Requirements

-   **Go Environment:**  
    Make sure you have Go installed (version 1.16 or later is recommended).

-   **GitHub Personal Access Token:**  
    Export a GitHub token as an environment variable:

    ```bash
    export GITHUB_TOKEN=your_github_token_here
    ```

-   **Dependencies:**  
    The project uses several Go packages including:

    -   `github.com/mattn/go-sqlite3`

    Dependencies are managed via Go modules. Use `go mod tidy` to ensure all dependencies are fetched.

## Running the Application

Build and run the application from the project root:

```bash
go build -o githubwatchdog ./cmd/app
```

### Batch Search

Running the binary with no subcommand still performs the default search:

```bash
./githubwatchdog
```

You can also call the search command explicitly:

```bash
./githubwatchdog search --query 'created:>2026-01-01 stars:>5' --max-pages 2
```

For agent workflows, these flags are the important ones:

```bash
./githubwatchdog search --only-flagged --fail-on-findings
```

That keeps the JSON payload focused on suspicious results and exits with code `10` when findings are present.

For long-running scans, use streaming output:

```bash
./githubwatchdog search --format ndjson --only-flagged
```

That emits one result per line as the scan progresses, followed by a final summary line.

For incremental polling, use the validated time filters instead of hand-building `updated:` query fragments:

```bash
./githubwatchdog search --since 2026-03-01 --updated-before 2026-03-13
```

For stable canned searches, use a built-in profile:

```bash
./githubwatchdog search --profile recent
./githubwatchdog search --profile high-signal --only-flagged
./githubwatchdog search --list-profiles
```

Profiles set a default query window and page budget, but any explicit flag still wins.

### Direct Repository Scan

```bash
./githubwatchdog repo BearHuddleston/GitHubWatchdog
```

### Direct User Scan

```bash
./githubwatchdog user octocat
```

### Web Interface

To run the application with the web interface for viewing the database:

```bash
./githubwatchdog serve
```

The web server listens on `127.0.0.1:8080` by default. You can access it at http://127.0.0.1:8080

The web interface includes the following features:

-   **Dashboard**: Overview of processed repositories, users, and detected flags
-   **Repository View**: List of analyzed repositories with status indicators
-   **User View**: List of analyzed GitHub users with suspicion status
-   **Flags View**: List of detected heuristic flags
-   **Sortable Tables**: Click on column headers to sort data
-   **Pagination**: Adjustable page size with navigation controls
-   **Status Toggle**: One-click toggle between clean/malicious or clean/suspicious states
-   **Detailed Reports**: Real-time reports using GitHub API for repositories and users
-   **Markdown Rendering**: Properly formatted README display in repository reports

Options:

-   `search`: Batch-scan repositories using the configured or supplied query
-   `repo <owner>/<repo>`: Scan a single repository and its owner
-   `user <username>`: Scan a single GitHub user
-   `serve`: Run the web interface
-   `-config`: Specify the configuration file path
-   `-db`: Specify the SQLite database path
-   `--only-flagged`: Limit `search` output to repositories with findings
-   `--include-skipped=false`: Exclude already-processed repositories from `search` output
-   `--fail-on-findings`: Exit with code `10` when suspicious results are found
-   `--format ndjson`: Stream one JSON object per line during `search`
-   `--since`: Add an `updated:>=...` qualifier without editing the raw query
-   `--updated-before`: Add an `updated:<=...` qualifier without editing the raw query
-   `--profile`: Apply a built-in `search` preset such as `recent`, `high-signal`, or `backfill`
-   `--list-profiles`: Print the built-in `search` presets and exit

Example with custom port:

```bash
./githubwatchdog serve --addr=":9090"
```

**Note**: Scan commands default to JSON output so they can be consumed directly by agents or scripts. Use `--format text` for a human-oriented summary. A valid GitHub token is required, which can be provided through the `GITHUB_TOKEN` environment variable or in the `config.json` file.

## TO-DO List

### Unit Testing

-   Develop comprehensive unit tests for:
    -   GitHub client initialization.
    -   Contribution counting logic.
    -   User analysis with various edge cases.
    -   Database persistence and retrieval.

### Error Handling Improvements

-   ✅ Enhance error handling throughout the code, especially for network/API errors and database operations.

### Configuration Enhancements

-   ✅ Introduce a configuration file (`config.json`) or command-line flags to allow dynamic setting of thresholds (e.g., repository size, stars threshold, page limits).

### Logging Enhancements

-   ✅ Integrate a more robust logging framework that supports log levels and log file rotation.

### Rate Limiting Handling

-   ✅ Improve handling for GitHub API rate limits, including automatic retries and exponential backoff.

### Enhanced Query Parameters

-   Allow customization of the GitHub search query via environment variables or command-line arguments.

### Performance Optimization

-   ✅ Investigate opportunities for further parallel processing when analyzing multiple repositories or users concurrently.

### Web UI Integration

-   ✅ Develop and integrate a web UI for viewing database content
-   ✅ Add sortable tables with column headers
-   ✅ Implement pagination and customizable page size
-   ✅ Add status toggle for repository and user classification
-   ✅ Integrate detailed reports with GitHub API data
-   ✅ Implement Markdown rendering for repository READMEs
-   Enhance web UI with real-time monitoring and scanning process management

### CI/CD Integration

-   Set up continuous integration to run tests on each commit and pull request.
