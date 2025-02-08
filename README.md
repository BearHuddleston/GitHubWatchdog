# GitHubWatchdog - GitHub Suspicious User Detector

GitHubWatchdog is a Go-based microservice that leverages the GitHub API to search for repositories and analyze their owners for suspicious activity. The tool scans repositories using a predefined search query and applies heuristics to flag users who may exhibit unusual patterns, such as newly created accounts or repositories with low disk usage yet high star counts.

## Update

The project has been restructured into a microservice architecture with a web UI (coming soon) and follows modern Go idioms. Core functionalities have been split into clear, focused packages under the `internal/` directory. The main executable is now located in the `cmd/app/` folder.

## Architecture & Project Structure

The new structure improves modularity and maintainability. An example directory layout is:

```
GitHubWatchdog/
├── cmd/
│   └── app/
│       └── main.go           # Bootstraps the application, initializes dependencies, and starts the search loop.
└── internal/
    ├── analyzer/
    │   └── analyzer.go       # Contains user heuristics and analysis logic.
    ├── config/
    │   └── config.go         # Reads environment variables and sets default configuration.
    ├── fileutil/
    │   └── fileutil.go       # Handles file I/O operations (loading and appending records).
    ├── github/
    │   └── client.go         # Sets up the GitHub GraphQL client.
    ├── processor/
    │   └── processor.go      # Coordinates repository search, worker pool, and processing.
    └── repo/
        └── repo.go           # Contains repository-specific analysis (e.g., README scanning).
```

This structure allows each package to have a single responsibility, keeping the codebase simple and aligned with Go best practices.

## Overview

GitHubWatchdog performs the following tasks:

-   **GitHub Client Initialization:**  
    Creates an authenticated GitHub client using a personal access token (see `internal/github/client.go`).

-   **Repository Search & Processing:**  
    Uses GitHub's GraphQL API to search for repositories matching a specific query (e.g., repositories created after a certain date with more than 5 stars). Results are dispatched to a worker pool for concurrent processing (see `internal/processor/processor.go`).

-   **Processed Repository Tracking:**  
    The service reads and appends repository IDs (in the format `owner/repo`) to a file (`processed_repos.txt`) to avoid duplicate processing. File operations are handled by the `internal/fileutil` package.

-   **User Analysis:**  
    For repositories with low disk usage, the tool further analyzes the associated user’s account using various heuristics (such as account age, total stars across repositories, and contribution counts). The analysis logic is encapsulated in the `internal/analyzer` package.

-   **Suspicious User & Repository Recording:**  
    If a user or repository is flagged as suspicious, the relevant details are logged and appended to designated files (e.g., `suspicious_users.txt`, `malicious_repos.txt`).

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

    Dependencies are managed via Go modules. Use `go mod tidy` to ensure all dependencies are fetched.

## Running the Microservice

Build and run the service from the project root:

```bash
go build -o githubwatchdog ./cmd/app
./githubwatchdog
```

## TO-DO List

### Unit Testing

-   Develop comprehensive unit tests for:
    -   GitHub client initialization.
    -   Contribution counting logic.
    -   User analysis with various edge cases.

### Error Handling Improvements

-   Enhance error handling throughout the code, especially for network/API errors and file I/O operations.

### Configuration Enhancements

-   Introduce a configuration file or command-line flags to allow dynamic setting of thresholds (e.g., repository size, stars threshold, page limits).

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

---
