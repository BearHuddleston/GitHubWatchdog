# GitHubWatchdog - GitHub Suspicious User Detector

GitHubWatchdog is a Go-based microservice that leverages the GitHub API to search for repositories and analyze their owners for suspicious activity. The tool scans repositories using a predefined search query and applies heuristics to flag users who may exhibit unusual patterns, such as newly created accounts or repositories with low disk usage yet high star counts.

I have personally reported **over 3000+ accounts** using this tool.

## Malicious Repositories

All has been reported and has be dealt with.

| id  | repo_id                                                                         | owner               | name                                                          | updated_at                | disk_usage | stargazer_count | is_malicious | processed_at        |
| --- | ------------------------------------------------------------------------------- | ------------------- | ------------------------------------------------------------- | ------------------------- | ---------- | --------------- | ------------ | ------------------- |
| 34  | VastSupp/Ex1tlag-Free-2024                                                      | VastSupp            | Ex1tlag-Free-2024                                             | 2025-02-17 22:15:31+00:00 | 93         | 65              | 1            | 2025-02-18 20:01:46 |
| 36  | TavsancikArthur/FL-Studio                                                       | TavsancikArthur     | FL-Studio                                                     | 2025-02-17 22:15:31+00:00 | 92         | 65              | 1            | 2025-02-18 20:01:46 |
| 38  | TwistedTheIETDriver/Dayz-Cheat-H4ck-A1mbot                                      | TwistedTheIETDriver | Dayz-Cheat-H4ck-A1mbot                                        | 2025-02-17 22:15:31+00:00 | 46         | 65              | 1            | 2025-02-18 20:01:46 |
| 39  | DiegoX12T/League-0f-Legends-h4ck                                                | DiegoX12T           | League-0f-Legends-h4ck                                        | 2025-02-17 22:15:31+00:00 | 93         | 64              | 1            | 2025-02-18 20:01:46 |
| 40  | 15-038-Stevanus/Roblox-Blox-Fruits-Script-2024                                  | 15-038-Stevanus     | Roblox-Blox-Fruits-Script-2024                                | 2025-02-17 22:15:32+00:00 | 103        | 63              | 1            | 2025-02-18 20:01:46 |
| 41  | CoolRocksyer120/N1tr0Dreams-2024                                                | CoolRocksyer120     | N1tr0Dreams-2024                                              | 2025-02-17 22:15:31+00:00 | 91         | 64              | 1            | 2025-02-18 20:01:46 |
| 42  | janek1343/Nexus-Rob1ox                                                          | janek1343           | Nexus-Rob1ox                                                  | 2025-02-17 22:15:32+00:00 | 27         | 63              | 1            | 2025-02-18 20:01:46 |
| 43  | twistedscripting/Rainbow-S1x-Siege-Cheat                                        | twistedscripting    | Rainbow-S1x-Siege-Cheat                                       | 2025-02-17 22:15:31+00:00 | 50         | 63              | 1            | 2025-02-18 20:01:46 |
| 44  | hi654321/Spotify-Premium-for-free-2024                                          | hi654321            | Spotify-Premium-for-free-2024                                 | 2025-02-17 22:15:32+00:00 | 26         | 62              | 1            | 2025-02-18 20:01:46 |
| 45  | Yusufid056/rust-hack-fre3                                                       | Yusufid056          | rust-hack-fre3                                                | 2025-02-17 22:15:32+00:00 | 97         | 62              | 1            | 2025-02-18 20:01:46 |
| 47  | reudyp2006/SonyVegas-2024                                                       | reudyp2006          | SonyVegas-2024                                                | 2025-02-17 22:15:32+00:00 | 46         | 62              | 1            | 2025-02-18 20:01:46 |
| 48  | SBlennytoxicgod/r0b10x-synapse-x-free                                           | SBlennytoxicgod     | r0b10x-synapse-x-free                                         | 2025-02-17 22:15:32+00:00 | 84         | 62              | 1            | 2025-02-18 20:01:46 |
| 56  | tarosgrippen-1992/ReiBoot-Pro-11.1.1-Crack-With-Registration-Code-Download-2025 | tarosgrippen-1992   | ReiBoot-Pro-11.1.1-Crack-With-Registration-Code-Download-2025 | 2025-02-17 03:52:20+00:00 | 2          | 41              | 1            | 2025-02-18 20:01:47 |
| 63  | knightannymars0/Codex-Roblox                                                    | knightannymars0     | Codex-Roblox                                                  | 2025-02-18 17:40:13+00:00 | 2          | 39              | 1            | 2025-02-18 20:01:47 |
| 64  | bafymronterry8/JJsploit                                                         | bafymronterry8      | JJsploit                                                      | 2025-02-18 16:49:36+00:00 | 3          | 39              | 1            | 2025-02-18 20:01:47 |
| 65  | hotpantsbronze5/Evon-Executor                                                   | hotpantsbronze5     | Evon-Executor                                                 | 2025-02-18 16:49:36+00:00 | 2          | 39              | 1            | 2025-02-18 20:01:47 |
| 69  | tagal-nervok/FiveM-External-Cheat                                               | tagal-nervok        | FiveM-External-Cheat                                          | 2025-02-17 04:13:28+00:00 | 3          | 36              | 1            | 2025-02-18 20:01:47 |
| 71  | optimistvova146/Shrimp                                                          | optimistvova146     | Shrimp                                                        | 2025-02-18 17:23:53+00:00 | 3          | 36              | 1            | 2025-02-18 20:01:47 |
| 78  | griderempark1992/Blade                                                          | griderempark1992    | Blade                                                         | 2025-02-18 17:23:53+00:00 | 3          | 31              | 1            | 2025-02-18 20:01:48 |
| 83  | wring4/Cubase-Pro-No-Crack                                                      | wring4              | Cubase-Pro-No-Crack                                           | 2025-02-17 04:17:22+00:00 | 2          | 29              | 1            | 2025-02-18 20:01:48 |
| 197 | mowhampton83/autscript                                                          | mowhampton83        | autscript                                                     | 2025-02-18 17:23:52+00:00 | 3          | 15              | 1            | 2025-02-18 20:01:54 |
| 216 | rondablackguard681/Blox-scr                                                     | rondablackguard681  | Blox-scr                                                      | 2025-02-18 17:23:52+00:00 | 3          | 14              | 1            | 2025-02-18 20:01:56 |
| 224 | elthinshordekeep/Roblox-Incognito                                               | elthinshordekeep    | Roblox-Incognito                                              | 2025-02-18 16:55:06+00:00 | 2          | 12              | 1            | 2025-02-18 20:01:57 |
| 243 | optimistvova146/Arceus-Executor                                                 | optimistvova146     | Arceus-Executor                                               | 2025-02-18 16:17:21+00:00 | 2          | 10              | 1            | 2025-02-18 20:01:58 |
| 251 | bossannymars1992/BedWars                                                        | bossannymars1992    | BedWars                                                       | 2025-02-18 16:55:06+00:00 | 3          | 10              | 1            | 2025-02-18 20:01:58 |
| 261 | simpotniikristmas2/Nexus-Roblox                                                 | simpotniikristmas2  | Nexus-Roblox                                                  | 2025-02-18 16:17:21+00:00 | 2          | 10              | 1            | 2025-02-18 20:01:58 |
| 354 | chaz91madk/HorseLife                                                            | chaz91madk          | HorseLife                                                     | 2025-02-18 16:38:51+00:00 | 3          | 6               | 1            | 2025-02-18 20:02:05 |

## Architecture & Project Structure

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
