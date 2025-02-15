# GitHubWatchdog - GitHub Suspicious User Detector

GitHubWatchdog is a Go-based microservice that leverages the GitHub API to search for repositories and analyze their owners for suspicious activity. The tool scans repositories using a predefined search query and applies heuristics to flag users who may exhibit unusual patterns, such as newly created accounts or repositories with low disk usage yet high star counts.

I have personally reported **over 3000+ accounts** using this tool.

## Malicious Repositories Examples

| id  | repo_id                                                                      | owner              | name                                                                   | updated_at                | disk_usage | stargazer_count | is_malicious | processed_at        |
| --- | ---------------------------------------------------------------------------- | ------------------ | ---------------------------------------------------------------------- | ------------------------- | ---------- | --------------- | ------------ | ------------------- |
| 954 | dejavufreshmeat708/Cheat-CS2                                                 | dejavufreshmeat708 | Cheat-CS2                                                              | 2025-02-14 01:51:37+00:00 | 2          | 17              | 1            | 2025-02-15 19:23:57 |
| 1   | SUKSTA/counter-str1ke-2-h4ck                                                 | SUKSTA             | counter-str1ke-2-h4ck                                                  | 2025-02-15 08:02:00+00:00 | 2896       | 336             | 1            | 2025-02-15 19:22:23 |
| 2   | Castravel/cheat-escape-from-tarkov                                           | Castravel          | cheat-escape-from-tarkov                                               | 2025-02-15 08:03:20+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 3   | Tezixx12/synapse-x-roblox-free                                               | Tezixx12           | synapse-x-roblox-free                                                  | 2025-02-15 08:09:57+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 4   | wildrax/Solara-Executor                                                      | wildrax            | Solara-Executor                                                        | 2025-02-15 08:09:21+00:00 | 2896       | 335             | 1            | 2025-02-15 19:22:23 |
| 5   | CrisMilan/Dead1ock-h4ck                                                      | CrisMilan          | Dead1ock-h4ck                                                          | 2025-02-15 08:02:46+00:00 | 2896       | 335             | 1            | 2025-02-15 19:22:23 |
| 6   | albertkd7/f0rtnite-h4ck                                                      | albertkd7          | f0rtnite-h4ck                                                          | 2025-02-15 08:04:45+00:00 | 2896       | 335             | 1            | 2025-02-15 19:22:23 |
| 7   | saro668/GTA-5-Mod-Menu-2024                                                  | saro668            | GTA-5-Mod-Menu-2024                                                    | 2025-02-15 08:05:49+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 8   | ega1994/IObit-Driver-Booster-Pro-2024-free-Serial-Key                        | ega1994            | IObit-Driver-Booster-Pro-2024-free-Serial-Key                          | 2025-02-15 08:05:29+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 9   | Louis1189/IDM-Activation-Script-2024                                         | Louis1189          | IDM-Activation-Script-2024                                             | 2025-02-15 08:05:17+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 10  | pelicula6565/NitroDreams-2024                                                | pelicula6565       | NitroDreams-2024                                                       | 2025-02-15 08:06:22+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 11  | slank3111/SketchUp-Pro-free-2024                                             | slank3111          | SketchUp-Pro-free-2024                                                 | 2025-02-15 08:08:46+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 12  | Leonightlee/Spotify-Premium-for-free-2024                                    | Leonightlee        | Spotify-Premium-for-free-2024                                          | 2025-02-15 08:09:38+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 13  | Ujjwal6u/Roblox-Luna-Executor                                                | Ujjwal6u           | Roblox-Luna-Executor                                                   | 2025-02-15 08:10:49+00:00 | 2897       | 335             | 1            | 2025-02-15 19:22:23 |
| 14  | Konnix-th/ESET-KeyGen-2024                                                   | Konnix-th          | ESET-KeyGen-2024                                                       | 2025-02-15 08:03:35+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 15  | lumiLuna/IDA-Pro-Keygen-2024                                                 | lumiLuna           | IDA-Pro-Keygen-2024                                                    | 2025-02-15 08:04:57+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 16  | pirate9900/Delta-Executor                                                    | pirate9900         | Delta-Executor                                                         | 2025-02-15 08:10:11+00:00 | 2896       | 335             | 1            | 2025-02-15 19:22:23 |
| 17  | fendygg/SoLBF                                                                | fendygg            | SoLBF                                                                  | 2025-02-15 08:09:05+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 18  | N1ketpr0/Fl-Studio-2024                                                      | N1ketpr0           | Fl-Studio-2024                                                         | 2025-02-15 08:04:28+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 19  | 123pk321/ShadowTool                                                          | 123pk321           | ShadowTool                                                             | 2025-02-15 08:08:18+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 20  | MrLeeHub2006/OpenSea-Bidding-Bot-2024                                        | MrLeeHub2006       | OpenSea-Bidding-Bot-2024                                               | 2025-02-15 08:06:34+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 21  | Jle1596/Roblox-Beaming-Tool                                                  | Jle1596            | Roblox-Beaming-Tool                                                    | 2025-02-15 08:10:30+00:00 | 2896       | 335             | 1            | 2025-02-15 19:22:23 |
| 22  | rafi-bitc/Exitlag-Free-2024                                                  | rafi-bitc          | Exitlag-Free-2024                                                      | 2025-02-15 08:04:08+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 23  | zuriodev/SeedTool                                                            | zuriodev           | SeedTool                                                               | 2025-02-15 08:07:59+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 24  | Raoufra47/SilenceGen                                                         | Raoufra47          | SilenceGen                                                             | 2025-02-15 08:08:30+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 25  | gargankur1/Eth-Miner                                                         | gargankur1         | Eth-Miner                                                              | 2025-02-15 08:03:54+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 26  | thegoodweekends/Discord-AllinOne-Tool                                        | thegoodweekends    | Discord-AllinOne-Tool                                                  | 2025-02-15 08:02:59+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 27  | KrishanthMSK/N3xus-Scr1pt-R0bl0x                                             | KrishanthMSK       | N3xus-Scr1pt-R0bl0x                                                    | 2025-02-15 08:06:08+00:00 | 2895       | 335             | 1            | 2025-02-15 19:22:23 |
| 28  | Korpai-ii/Rainbow-S1x-Siege-Cheat                                            | Korpai-ii          | Rainbow-S1x-Siege-Cheat                                                | 2025-02-15 08:07:12+00:00 | 2897       | 335             | 1            | 2025-02-15 19:22:23 |
| 37  | Yurmakara96/Dayz-Cheat-H4ck-A1mb0t                                           | Yurmakara96        | Dayz-Cheat-H4ck-A1mb0t                                                 | 2025-02-15 08:02:30+00:00 | 2896       | 335             | 1            | 2025-02-15 19:22:23 |
| 51  | satwikpsp9/Canva-Pro-2024                                                    | satwikpsp9         | Canva-Pro-2024                                                         | 2025-02-15 08:01:29+00:00 | 2896       | 336             | 1            | 2025-02-15 19:22:23 |
| 69  | Ujjwal6u/Al-Photoshop-2024                                                   | Ujjwal6u           | Al-Photoshop-2024                                                      | 2025-02-15 07:59:45+00:00 | 2895       | 336             | 1            | 2025-02-15 19:22:23 |
| 74  | rajendramca18/apex-legends-cheat-download                                    | rajendramca18      | apex-legends-cheat-download                                            | 2025-02-15 08:00:07+00:00 | 2897       | 336             | 1            | 2025-02-15 19:22:23 |
| 76  | pirate9900/Adobe-Acrobat-Pro-2024                                            | pirate9900         | Adobe-Acrobat-Pro-2024                                                 | 2025-02-15 07:59:16+00:00 | 2895       | 336             | 1            | 2025-02-15 19:22:23 |
| 78  | MINHTB/rust-hack-fr33                                                        | MINHTB             | rust-hack-fr33                                                         | 2025-02-15 08:07:26+00:00 | 2896       | 335             | 1            | 2025-02-15 19:22:23 |
| 79  | Alaxkhan/CosmicStar                                                          | Alaxkhan           | CosmicStar                                                             | 2025-02-15 08:01:45+00:00 | 2895       | 336             | 1            | 2025-02-15 19:22:23 |
| 94  | DmonZZ31/AquaDiscord                                                         | DmonZZ31           | AquaDiscord                                                            | 2025-02-15 08:00:20+00:00 | 2896       | 336             | 1            | 2025-02-15 19:22:23 |
| 95  | Jle1596/Adobe-Express-2024                                                   | Jle1596            | Adobe-Express-2024                                                     | 2025-02-15 07:59:29+00:00 | 2895       | 336             | 1            | 2025-02-15 19:22:23 |
| 108 | luciferburn1992/Carbon-Executor                                              | luciferburn1992    | Carbon-Executor                                                        | 2025-02-14 16:15:23+00:00 | 2          | 35              | 1            | 2025-02-15 19:22:31 |
| 109 | diggerbupyc/Nexus-Roblox                                                     | diggerbupyc        | Nexus-Roblox                                                           | 2025-02-14 16:15:23+00:00 | 2          | 36              | 1            | 2025-02-15 19:22:31 |
| 111 | beck12lade/Rust-Hack-FR33---Ethical-Hacking-for-Rust-Game                    | beck12lade         | Rust-Hack-FR33---Ethical-Hacking-for-Rust-Game                         | 2025-02-15 18:05:36+00:00 | 3          | 38              | 1            | 2025-02-15 19:22:31 |
| 112 | beck12lade/dayz-radar-h4ck                                                   | beck12lade         | dayz-radar-h4ck                                                        | 2025-02-15 18:05:27+00:00 | 2          | 38              | 1            | 2025-02-15 19:22:31 |
| 117 | beck12lade/f0rtnite-h4ck-2025-4imbot-wa11hack-skin-changer                   | beck12lade         | f0rtnite-h4ck-2025-4imbot-wa11hack-skin-changer                        | 2025-02-15 18:05:48+00:00 | 3          | 38              | 1            | 2025-02-15 19:22:31 |
| 118 | beck12lade/Roblox-Synapse                                                    | beck12lade         | Roblox-Synapse                                                         | 2025-02-15 18:05:43+00:00 | 3          | 38              | 1            | 2025-02-15 19:22:31 |
| 120 | wings-bloodfire/Codex-Roblox                                                 | wings-bloodfire    | Codex-Roblox                                                           | 2025-02-14 16:15:23+00:00 | 2          | 35              | 1            | 2025-02-15 19:22:31 |
| 125 | linkertburgh259/Roblox-Oxygen                                                | linkertburgh259    | Roblox-Oxygen                                                          | 2025-02-14 16:15:23+00:00 | 2          | 35              | 1            | 2025-02-15 19:22:31 |
| 137 | raydenjester5/DX9WARE-Roblox                                                 | raydenjester5      | DX9WARE-Roblox                                                         | 2025-02-14 01:27:20+00:00 | 2          | 31              | 1            | 2025-02-15 19:22:31 |
| 138 | fireboygayelite430/Nevermiss                                                 | fireboygayelite430 | Nevermiss                                                              | 2025-02-14 01:38:36+00:00 | 2          | 32              | 1            | 2025-02-15 19:22:31 |
| 146 | skechqwenty274/Evon-Executor                                                 | skechqwenty274     | Evon-Executor                                                          | 2025-02-14 01:27:24+00:00 | 2          | 31              | 1            | 2025-02-15 19:22:31 |
| 149 | exomi206/JJsploit                                                            | exomi206           | JJsploit                                                               | 2025-02-14 01:27:32+00:00 | 2          | 31              | 1            | 2025-02-15 19:22:31 |
| 153 | screwtape-white/Scriptware-Executer                                          | screwtape-white    | Scriptware-Executer                                                    | 2025-02-14 01:38:44+00:00 | 2          | 30              | 1            | 2025-02-15 19:22:31 |
| 164 | dominatoresquire3/Roblox-Oxygen                                              | dominatoresquire3  | Roblox-Oxygen                                                          | 2025-02-14 01:38:41+00:00 | 2          | 30              | 1            | 2025-02-15 19:22:31 |
| 165 | charterdanyysamp4/Codex-Roblox                                               | charterdanyysamp4  | Codex-Roblox                                                           | 2025-02-14 01:27:36+00:00 | 2          | 30              | 1            | 2025-02-15 19:22:32 |
| 168 | dejavufreshmeat708/JJsploit                                                  | dejavufreshmeat708 | JJsploit                                                               | 2025-02-14 01:38:39+00:00 | 2          | 30              | 1            | 2025-02-15 19:22:32 |
| 178 | bottes8/m0dmenu-gta5-free                                                    | bottes8            | m0dmenu-gta5-free                                                      | 2025-02-14 01:38:46+00:00 | 3          | 28              | 1            | 2025-02-15 19:22:32 |
| 183 | regeneronius527/Roblox-Celery                                                | regeneronius527    | Roblox-Celery                                                          | 2025-02-14 07:04:36+00:00 | 3          | 26              | 1            | 2025-02-15 19:22:32 |
| 186 | jesusdog60/Arceus-Executor                                                   | jesusdog60         | Arceus-Executor                                                        | 2025-02-14 07:04:36+00:00 | 2          | 26              | 1            | 2025-02-15 19:22:32 |
| 191 | solomon15yammee/Codex-Roblox                                                 | solomon15yammee    | Codex-Roblox                                                           | 2025-02-14 01:34:00+00:00 | 2          | 24              | 1            | 2025-02-15 19:22:32 |
| 194 | eddy-bonkers/Roblox-Synapse                                                  | eddy-bonkers       | Roblox-Synapse                                                         | 2025-02-14 07:04:36+00:00 | 3          | 24              | 1            | 2025-02-15 19:22:32 |
| 195 | barsikbenladen15/Roblox-Oxygen                                               | barsikbenladen15   | Roblox-Oxygen                                                          | 2025-02-14 01:05:55+00:00 | 3          | 24              | 1            | 2025-02-15 19:22:32 |
| 196 | tigercub-mattdamon/Seliware-Executor                                         | tigercub-mattdamon | Seliware-Executor                                                      | 2025-02-14 01:05:58+00:00 | 3          | 24              | 1            | 2025-02-15 19:22:32 |
| 211 | igorgarik354/Evon-Executor                                                   | igorgarik354       | Evon-Executor                                                          | 2025-02-14 01:33:51+00:00 | 2          | 23              | 1            | 2025-02-15 19:22:40 |
| 213 | lellmanmictikfid3/Roblox-Incognito                                           | lellmanmictikfid3  | Roblox-Incognito                                                       | 2025-02-14 01:33:47+00:00 | 2          | 23              | 1            | 2025-02-15 19:22:40 |
| 215 | soldierzekeplays/Roblox-Synapse                                              | soldierzekeplays   | Roblox-Synapse                                                         | 2025-02-14 01:33:55+00:00 | 2          | 23              | 1            | 2025-02-15 19:22:40 |
| 233 | razor-gayman/Roblox-Krampus                                                  | razor-gayman       | Roblox-Krampus                                                         | 2025-02-14 01:06:02+00:00 | 2          | 22              | 1            | 2025-02-15 19:22:40 |
| 654 | flad0/Forgotten-Runiverse-Crypto-Bot-Crypto-Game-Auto-Farm-Clicker-Cheat-Api | flad0              | Forgotten-Runiverse-Crypto-Bot-Crypto-Game-Auto-Farm-Clicker-Cheat-Api | 2025-02-12 23:51:21+00:00 | 4          | 19              | 1            | 2025-02-15 19:23:17 |
| 738 | dominatoresquire3/Fortnite-Cheat-Ethify                                      | dominatoresquire3  | Fortnite-Cheat-Ethify                                                  | 2025-02-14 01:51:46+00:00 | 2          | 17              | 1            | 2025-02-15 19:23:29 |
| 788 | youritch-bloodfire/FiveM-External-Cheat                                      | youritch-bloodfire | FiveM-External-Cheat                                                   | 2025-02-15 05:45:49+00:00 | 3          | 17              | 1            | 2025-02-15 19:23:30 |
| 938 | skechqwenty274/1aq-CounterStrike2q                                           | skechqwenty274     | 1aq-CounterStrike2q                                                    | 2025-02-14 01:51:41+00:00 | 2          | 17              | 1            | 2025-02-15 19:23:57 |

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
