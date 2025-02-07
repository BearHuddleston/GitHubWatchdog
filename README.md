# GitHubWatchdog - GitHub Suspicious User Detector

This project is a Go-based tool that leverages the GitHub API to search for repositories and analyze their owners for suspicious activity. It specifically targets users with newly created accounts or those with repositories that match certain "empty" criteria. The tool gathers information such as repository stars, repository size, and user contributions, then flags users based on predefined criteria.

## Watchdogs Barking: Calling Out Suspicious Users!

[bark-2025-02-06-2058CT](bark-2025-02-06-2058CT)

## Overview

The tool performs the following tasks:

-   **GitHub Client Initialization:**  
    Creates an authenticated GitHub client using a personal access token.

-   **Repository Search:**  
    Searches GitHub for repositories matching a specific query (e.g., repositories created after a certain date with more than 5 stars).

-   **Processed Repository Tracking:**  
    Reads and appends repository IDs (in the format `owner/repo`) to a file (`processed_repos.txt`) to avoid duplicate processing.

-   **User Analysis:**  
    For repositories considered "empty" (based on a size threshold), the tool analyzes the associated user's account. The analysis includes:

    -   Checking account age.
    -   Summing up the stars across all repositories.
    -   Counting "empty" repositories.
    -   Counting recent contributions (using public event counts as a proxy).

    The user is flagged as suspicious if they meet any of these criteria:

    -   **suspiciousOriginal:** Indicates original content exhibiting unusual patterns.
    -   **suspiciousNew:** Flags new or emerging patterns that require attention.
    -   **suspiciousRecent:** Marks recent activities as potentially suspicious.

-   **Suspicious User Recording:**  
    If a user is flagged as suspicious, their username is appended to a file (`suspicious_users.txt`).

## Requirements

-   **Go Environment:**  
    Make sure you have Go installed (version 1.16 or later is recommended).

-   **GitHub Personal Access Token:**  
    Export a GitHub token as an environment variable:
    ```bash
    export GITHUB_TOKEN=your_github_token_here
    ```
-   **Dependencies:**

The tool uses the following Go packages:

-   `github.com/google/go-github/v68/github`
-   `golang.org/x/oauth2`

These can be installed via `go get` or managed using Go modules.

## Code Structure

### GitHub Client Initialization

-   **Function:** `initializeGitHubClient(token string) *github.Client`  
    Sets up an OAuth2-enabled GitHub client.

### Contribution Count

-   **Function:** `getContributionsLastYear(ctx, client, username)`  
    Counts a user's public events in the last year.

### User Analysis

-   **Function:** `analyzeUser(ctx, client, username)`  
    Fetches the user profile and repositories, calculates metrics, and determines if the user is suspicious.

### Processed Repositories Management

-   **Functions:**
    -   `loadProcessedRepos(filename string) (map[string]bool, error)`
    -   `appendProcessedRepo(filename, repoID string) error`

### Suspicious User Recording

-   **Function:** `appendSuspiciousUser(filename, username string) error`

### Main Routine

-   **Function:** `main()`  
    Orchestrates the repository search, user analysis, and file recording.

## TO-DO List

### Unit Testing

Develop comprehensive unit tests for:

-   GitHub client initialization.
-   Contribution counting logic.
-   User analysis with various edge cases.

### Error Handling Improvements

Enhance error handling throughout the code, especially for network/API errors and file I/O operations.

### Configuration File

Introduce a configuration file or command-line flags to allow dynamic setting of thresholds (e.g., repository size threshold, stars threshold, page limits).

### Logging Enhancements

Consider integrating a more robust logging framework that supports log levels and log file rotation.

### Rate Limiting Handling

Implement better handling for GitHub API rate limits, including automatic retries and exponential backoff.

### Enhanced Query Parameters

Allow customization of the GitHub search query via environment variables or command-line arguments.

### Performance Optimization

Investigate opportunities for parallel processing when analyzing multiple repositories or users concurrently.

### Documentation

Expand the README and in-code comments to provide deeper insights into the logic and decision criteria.

### CI/CD Integration

Set up continuous integration to run tests on each commit and pull request.
