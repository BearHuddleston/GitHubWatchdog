# GitHubWatchdog - GitHub Suspicious User Detector

GitHubWatchdog is a Go-based microservice that leverages the GitHub API to search for repositories and analyze their owners for suspicious activity. The tool scans repositories using a predefined search query and applies heuristics to flag users who may exhibit unusual patterns, such as newly created accounts or repositories with low disk usage yet high star counts.

I have personally reported **over 3000+ accounts** using this tool.

## Architecture & Project Structure

The new structure improves modularity, maintainability, and data persistence. An example directory layout is:

```
GitHubWatchdog/
├── cmd/
│   └── app/
│       └── main.go           # Bootstraps the application, initializes dependencies, and starts the search loop.
└── internal/
    ├── analyzer/
    │   ├── analyzer.go       # Contains user heuristics and analysis logic.
    │   └── heuristic.go      # Defines heuristic rules for suspicious activity detection.
    ├── config/
    │   └── config.go         # Reads environment variables and sets default configuration.
    ├── db/
    │   └── sqlite.go         # Implements SQLite-based storage for processed users and repositories.
    ├── github/
    │   └── client.go         # Sets up the GitHub GraphQL client.
    └── processor/
        └── processor.go      # Coordinates repository search, worker pool, and processing.
```

This structure allows each package to have a single responsibility, keeping the codebase simple and aligned with Go best practices.

## Overview

GitHubWatchdog performs the following tasks:

-   **GitHub Client Initialization:**  
    Creates an authenticated GitHub client using a personal access token (see `internal/github/client.go`).

-   **Repository Search & Processing:**  
    Uses GitHub's GraphQL API to search for repositories matching a specific query (e.g., repositories created after a certain date with more than 5 stars). Results are dispatched to a worker pool for concurrent processing (see `internal/processor/processor.go`).

-   **Processed Repository Tracking:**  
    The service tracks processed repositories and users in an SQLite database (`github_watchdog.db`) to avoid duplicate analysis. Database interactions are handled by `internal/db/sqlite.go`.

-   **User Analysis:**  
    For repositories with low disk usage, the tool further analyzes the associated user’s account using various heuristics (such as account age, total stars across repositories, and contribution counts). The analysis logic is encapsulated in the `internal/analyzer` package.

-   **Heuristic-Based Suspicious Detection:**  
    The system applies predefined heuristics (see `internal/analyzer/heuristic.go`) to flag accounts with suspicious behavior, such as new accounts with high stars or repositories with empty content but significant stargazer activity.

-   **Suspicious User & Repository Recording:**  
    If a user or repository is flagged as suspicious, the relevant details are logged and stored in the SQLite database.

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

    -   `golang.org/x/oauth2`
    -   `github.com/shurcooL/githubv4`
    -   `github.com/mattn/go-sqlite3`

    Dependencies are managed via Go modules. Use `go mod tidy` to ensure all dependencies are fetched.

## Running the Application

Build and run the application from the project root:

```bash
go build -o githubwatchdog ./cmd/app
githubwatchdog
```

## TO-DO List

### Unit Testing

-   Develop comprehensive unit tests for:
    -   GitHub client initialization.
    -   Contribution counting logic.
    -   User analysis with various edge cases.
    -   Database persistence and retrieval.

### Error Handling Improvements

-   Enhance error handling throughout the code, especially for network/API errors and database operations.

### Configuration Enhancements

-   Introduce a configuration file (`config.json`) or command-line flags to allow dynamic setting of thresholds (e.g., repository size, stars threshold, page limits).

### Logging Enhancements

-   Integrate a more robust logging framework that supports log levels and log file rotation.

### Rate Limiting Handling

-   Improve handling for GitHub API rate limits, including automatic retries and exponential backoff.

### Enhanced Query Parameters

-   Allow customization of the GitHub search query via environment variables or command-line arguments.

### Performance Optimization

-   Investigate opportunities for further parallel processing when analyzing multiple repositories or users concurrently.

### Web UI Integration

-   Develop and integrate a web UI for real-time monitoring and management of the scanning process.

### CI/CD Integration

-   Set up continuous integration to run tests on each commit and pull request.
