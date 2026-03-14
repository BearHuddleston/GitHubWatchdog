package cli

import (
	"fmt"
	"io"
	"strings"
	"time"
)

type capabilityCatalog struct {
	Tool              string               `json:"tool"`
	Version           string               `json:"version,omitempty"`
	GlobalFlags       []capabilityFlag     `json:"global_flags"`
	Commands          []capabilityCommand  `json:"commands"`
	OutputFormats     []string             `json:"output_formats"`
	CheckpointFormats []string             `json:"checkpoint_formats"`
	ExitCodes         []capabilityExitCode `json:"exit_codes"`
	Profiles          []capabilityProfile  `json:"profiles"`
	SearchTime        capabilitySearchTime `json:"search_time"`
	AgentNotes        []string             `json:"agent_notes"`
}

type capabilityCommand struct {
	Name        string              `json:"name"`
	Summary     string              `json:"summary"`
	Usage       string              `json:"usage"`
	Positional  []capabilityArg     `json:"positional_args,omitempty"`
	Flags       []capabilityFlag    `json:"flags,omitempty"`
	Subcommands []capabilityCommand `json:"subcommands,omitempty"`
}

type capabilityArg struct {
	Name        string `json:"name"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

type capabilityFlag struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	Default       string   `json:"default,omitempty"`
	Description   string   `json:"description"`
	Enum          []string `json:"enum,omitempty"`
	Requires      []string `json:"requires,omitempty"`
	ConflictsWith []string `json:"conflicts_with,omitempty"`
}

type capabilityExitCode struct {
	Code        int    `json:"code"`
	Description string `json:"description"`
}

type capabilityProfile struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	Query         string `json:"query"`
	Activity      string `json:"activity"`
	CreatedSince  string `json:"created_since,omitempty"`
	CreatedBefore string `json:"created_before,omitempty"`
	UpdatedSince  string `json:"updated_since,omitempty"`
	UpdatedBefore string `json:"updated_before,omitempty"`
	MaxPages      int    `json:"max_pages,omitempty"`
	PerPage       int    `json:"per_page,omitempty"`
}

type capabilitySearchTime struct {
	DefaultActivity string   `json:"default_activity"`
	Activities      []string `json:"activities"`
	Notes           []string `json:"notes"`
}

func buildCapabilityCatalog(now time.Time) capabilityCatalog {
	return capabilityCatalog{
		Tool:    "githubwatchdog",
		Version: versionString(),
		GlobalFlags: []capabilityFlag{
			{Name: "-config", Type: "string", Default: "config.json", Description: "Path to the configuration file"},
			{Name: "-db", Type: "string", Default: "github_watchdog.db", Description: "Path to the SQLite database"},
			{Name: "-quiet", Type: "bool", Default: "false", Description: "Suppress informational logs on stderr"},
		},
		Commands: []capabilityCommand{
			{
				Name:    "search",
				Summary: "Search GitHub repositories and analyze suspicious findings.",
				Usage:   "githubwatchdog [global flags] search [search flags]",
				Flags: []capabilityFlag{
					{Name: "--query", Type: "string", Default: "stars:>5", Description: "Base GitHub repository search query"},
					{Name: "--profile", Type: "string", Description: "Built-in search profile", Enum: []string{"recent", "high-signal", "backfill"}},
					{Name: "--list-profiles", Type: "bool", Default: "false", Description: "List built-in search profiles and exit"},
					{Name: "--checkpoint", Type: "string", Description: "Save search progress under this checkpoint name"},
					{Name: "--resume", Type: "bool", Default: "false", Description: "Resume search defaults from the named checkpoint", Requires: []string{"--checkpoint"}},
					{Name: "--activity", Type: "string", Default: "updated", Description: "Search activity source", Enum: []string{"updated", "created", "either"}},
					{Name: "--since", Type: "string", Description: "Alias for --updated-since for backward-compatible updated-time searches"},
					{Name: "--updated-before", Type: "string", Description: "Upper bound for updated-time searches"},
					{Name: "--created-since", Type: "string", Description: "Lower bound for created-time searches"},
					{Name: "--created-before", Type: "string", Description: "Upper bound for created-time searches"},
					{Name: "--max-pages", Type: "int", Default: "10", Description: "Maximum number of result pages to scan"},
					{Name: "--per-page", Type: "int", Default: "100", Description: "Repositories to request per page"},
					{Name: "--max-concurrent", Type: "int", Default: "10", Description: "Maximum concurrent repository analyses"},
					{Name: "--timeout", Type: "duration", Default: "1h0m0s", Description: "Overall command timeout"},
					{Name: "--persist", Type: "bool", Default: "true", Description: "Persist results to the SQLite database"},
					{Name: "--format", Type: "string", Default: "json", Description: "Output format", Enum: []string{"json", "ndjson", "text"}},
					{Name: "--only-flagged", Type: "bool", Default: "false", Description: "Only include flagged repositories in output"},
					{Name: "--include-skipped", Type: "bool", Default: "true", Description: "Include skipped repositories in output"},
					{Name: "--fail-on-findings", Type: "bool", Default: "false", Description: "Exit with code 10 when findings are present"},
				},
			},
			{
				Name:    "repo",
				Summary: "Analyze a single repository by owner/name.",
				Usage:   "githubwatchdog [global flags] repo <owner>/<repo> [scan flags]",
				Positional: []capabilityArg{
					{Name: "<owner>/<repo>", Required: true, Description: "Repository reference"},
				},
				Flags: []capabilityFlag{
					{Name: "--timeout", Type: "duration", Default: "5m0s", Description: "Overall command timeout"},
					{Name: "--persist", Type: "bool", Default: "true", Description: "Persist results to the SQLite database"},
					{Name: "--format", Type: "string", Default: "json", Description: "Output format", Enum: []string{"json", "ndjson", "text"}},
					{Name: "--summary", Type: "bool", Default: "false", Description: "Emit a compact verdict summary instead of the full report"},
					{Name: "--fail-on-findings", Type: "bool", Default: "false", Description: "Exit with code 10 when findings are present"},
				},
			},
			{
				Name:    "user",
				Summary: "Analyze a single GitHub user.",
				Usage:   "githubwatchdog [global flags] user <username> [scan flags]",
				Positional: []capabilityArg{
					{Name: "<username>", Required: true, Description: "GitHub username"},
				},
				Flags: []capabilityFlag{
					{Name: "--timeout", Type: "duration", Default: "5m0s", Description: "Overall command timeout"},
					{Name: "--persist", Type: "bool", Default: "true", Description: "Persist results to the SQLite database"},
					{Name: "--format", Type: "string", Default: "json", Description: "Output format", Enum: []string{"json", "ndjson", "text"}},
					{Name: "--summary", Type: "bool", Default: "false", Description: "Emit a compact verdict summary instead of the full report"},
					{Name: "--fail-on-findings", Type: "bool", Default: "false", Description: "Exit with code 10 when findings are present"},
				},
			},
			{
				Name:    "verdict",
				Summary: "Auto-detect a target type and emit a compact verdict.",
				Usage:   "githubwatchdog [global flags] verdict <owner/repo|username> [verdict flags]",
				Positional: []capabilityArg{
					{Name: "<owner/repo|username>", Required: false, Description: "Single target when not using --input"},
				},
				Flags: []capabilityFlag{
					{Name: "--timeout", Type: "duration", Default: "5m0s", Description: "Overall command timeout"},
					{Name: "--persist", Type: "bool", Default: "true", Description: "Persist results to the SQLite database"},
					{Name: "--format", Type: "string", Default: "json", Description: "Output format", Enum: []string{"json", "ndjson", "text"}},
					{Name: "--input", Type: "string", Description: "Read newline-delimited targets from this path or - for stdin"},
					{Name: "--continue-on-error", Type: "bool", Default: "false", Description: "Emit structured per-target errors in batch mode and continue", Requires: []string{"--input"}},
					{Name: "--fail-on-findings", Type: "bool", Default: "false", Description: "Exit with code 10 when findings are present"},
				},
			},
			{
				Name:    "checkpoints",
				Summary: "Manage saved search checkpoints.",
				Usage:   "githubwatchdog [global flags] checkpoints <list|show|delete|export|import> [args]",
				Subcommands: []capabilityCommand{
					{Name: "list", Summary: "List stored checkpoints.", Usage: "githubwatchdog checkpoints list", Flags: []capabilityFlag{{Name: "--format", Type: "string", Default: "text", Description: "Output format", Enum: []string{"json", "text"}}}},
					{Name: "show", Summary: "Show one checkpoint.", Usage: "githubwatchdog checkpoints show <name>", Positional: []capabilityArg{{Name: "<name>", Required: true, Description: "Checkpoint name"}}, Flags: []capabilityFlag{{Name: "--format", Type: "string", Default: "text", Description: "Output format", Enum: []string{"json", "text"}}}},
					{Name: "delete", Summary: "Delete one checkpoint.", Usage: "githubwatchdog checkpoints delete <name>", Positional: []capabilityArg{{Name: "<name>", Required: true, Description: "Checkpoint name"}}},
					{Name: "export", Summary: "Export one or all checkpoints.", Usage: "githubwatchdog checkpoints export [name]", Positional: []capabilityArg{{Name: "[name]", Required: false, Description: "Checkpoint name"}}, Flags: []capabilityFlag{{Name: "--format", Type: "string", Default: "text", Description: "Output format", Enum: []string{"json", "text"}}}},
					{Name: "import", Summary: "Import checkpoint JSON.", Usage: "githubwatchdog checkpoints import --input <path|->", Flags: []capabilityFlag{{Name: "--format", Type: "string", Default: "text", Description: "Output format", Enum: []string{"json", "text"}}, {Name: "--input", Type: "string", Default: "-", Description: "Import input path or - for stdin"}}},
				},
			},
			{
				Name:    "capabilities",
				Summary: "Emit the authoritative command and flag catalog for agents.",
				Usage:   "githubwatchdog [global flags] capabilities [--format json|text]",
				Flags: []capabilityFlag{
					{Name: "--format", Type: "string", Default: "json", Description: "Output format", Enum: []string{"json", "text"}},
				},
			},
			{
				Name:    "recommend",
				Summary: "Recommend a deterministic command shape for a natural-language task.",
				Usage:   "githubwatchdog [global flags] recommend <task...>",
				Flags: []capabilityFlag{
					{Name: "--prompt", Type: "string", Description: "Task prompt to interpret"},
					{Name: "--format", Type: "string", Default: "json", Description: "Output format", Enum: []string{"json", "text"}},
					{Name: "--now", Type: "string", Description: "Reference time for deterministic planning (RFC3339)"},
				},
			},
		},
		OutputFormats:     []string{"json", "ndjson", "text"},
		CheckpointFormats: []string{"json", "text"},
		ExitCodes: []capabilityExitCode{
			{Code: 0, Description: "Success with no blocking CLI error"},
			{Code: 10, Description: "Findings present when --fail-on-findings is enabled"},
		},
		Profiles: []capabilityProfile{
			profileCapability("recent", now),
			profileCapability("high-signal", now),
			profileCapability("backfill", now),
		},
		SearchTime: capabilitySearchTime{
			DefaultActivity: "updated",
			Activities:      []string{"updated", "created", "either"},
			Notes: []string{
				"--since is an alias for updated-time lower bounds.",
				"--updated-before is an updated-time upper bound.",
				"--created-since and --created-before add created-time bounds.",
				"--activity either unions created-time and updated-time searches, then deduplicates by repository ID.",
				"Raw created: or updated: query qualifiers should not be combined with equivalent structured flags.",
			},
		},
		AgentNotes: []string{
			"Prefer -quiet for machine-readable runs.",
			"Prefer --persist=false for ad hoc scans that should not mutate local state.",
			"Prefer --format json for one-shot runs and --format ndjson for streaming or large batches.",
			"Use --fail-on-findings only when non-zero findings should gate automation.",
		},
	}
}

func profileCapability(name string, now time.Time) capabilityProfile {
	profile, _ := resolveSearchProfileAt(name, now)
	return capabilityProfile{
		Name:          profile.Name,
		Description:   profile.Description,
		Query:         profile.Query,
		Activity:      profile.Activity,
		CreatedSince:  profile.CreatedSince,
		CreatedBefore: profile.CreatedBefore,
		UpdatedSince:  profile.UpdatedSince,
		UpdatedBefore: profile.UpdatedBefore,
		MaxPages:      profile.MaxPages,
		PerPage:       profile.PerPage,
	}
}

func writeUsage(w io.Writer) {
	caps := buildCapabilityCatalog(time.Now().UTC())
	fmt.Fprintln(w, "GitHubWatchdog")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	for _, command := range caps.Commands {
		if command.Name == "help" {
			continue
		}
		fmt.Fprintf(w, "  %s\n", command.Usage)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Global flags:")
	for _, flag := range caps.GlobalFlags {
		fmt.Fprintf(w, "  %-15s %s", flag.Name+" "+flag.Type, flag.Description)
		if flag.Default != "" {
			fmt.Fprintf(w, " (default: %s)", flag.Default)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  - Scan commands default to JSON output for agent-friendly consumption.")
	fmt.Fprintln(w, "  - Use -quiet for automation that wants clean stderr.")
	fmt.Fprintln(w, "  - search --format ndjson streams result lines plus a final summary line.")
	fmt.Fprintln(w, "  - search supports updated-time, created-time, or either-activity windows.")
	fmt.Fprintln(w, "  - capabilities emits a machine-readable command catalog for agents.")
	fmt.Fprintln(w, "  - recommend suggests a deterministic command without executing it.")
	fmt.Fprintln(w, "  - Running with no subcommand defaults to the batch search command.")
	fmt.Fprintln(w, "  - Exit code 10 indicates findings when --fail-on-findings is used.")
}

func versionString() string {
	return ""
}

func writeCapabilityCatalogText(w io.Writer, caps capabilityCatalog) error {
	fmt.Fprintf(w, "Tool: %s\n", caps.Tool)
	if caps.Version != "" {
		fmt.Fprintf(w, "Version: %s\n", caps.Version)
	}
	fmt.Fprintf(w, "Output formats: %s\n", strings.Join(caps.OutputFormats, ", "))
	fmt.Fprintf(w, "Checkpoint formats: %s\n", strings.Join(caps.CheckpointFormats, ", "))
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, command := range caps.Commands {
		fmt.Fprintf(w, "- %s: %s\n", command.Name, command.Summary)
		fmt.Fprintf(w, "  usage=%s\n", command.Usage)
		for _, arg := range command.Positional {
			required := "optional"
			if arg.Required {
				required = "required"
			}
			fmt.Fprintf(w, "  arg %s (%s): %s\n", arg.Name, required, arg.Description)
		}
		for _, flag := range command.Flags {
			line := fmt.Sprintf("  flag %s (%s): %s", flag.Name, flag.Type, flag.Description)
			if flag.Default != "" {
				line += fmt.Sprintf(" default=%s", flag.Default)
			}
			if len(flag.Enum) > 0 {
				line += fmt.Sprintf(" enum=%s", strings.Join(flag.Enum, "|"))
			}
			fmt.Fprintln(w, line)
		}
		for _, subcommand := range command.Subcommands {
			fmt.Fprintf(w, "  subcommand %s: %s\n", subcommand.Name, subcommand.Summary)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Profiles:")
	for _, profile := range caps.Profiles {
		fmt.Fprintf(w, "- %s: %s\n", profile.Name, profile.Description)
		fmt.Fprintf(w, "  query=%q activity=%s", profile.Query, profile.Activity)
		if profile.CreatedSince != "" {
			fmt.Fprintf(w, " created-since=%s", profile.CreatedSince)
		}
		if profile.CreatedBefore != "" {
			fmt.Fprintf(w, " created-before=%s", profile.CreatedBefore)
		}
		if profile.UpdatedSince != "" {
			fmt.Fprintf(w, " updated-since=%s", profile.UpdatedSince)
		}
		if profile.UpdatedBefore != "" {
			fmt.Fprintf(w, " updated-before=%s", profile.UpdatedBefore)
		}
		fmt.Fprintln(w)
	}
	return nil
}
