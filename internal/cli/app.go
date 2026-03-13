package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/arkouda/github/GitHubWatchdog/internal/config"
	"github.com/arkouda/github/GitHubWatchdog/internal/db"
	"github.com/arkouda/github/GitHubWatchdog/internal/github"
	"github.com/arkouda/github/GitHubWatchdog/internal/logger"
	"github.com/arkouda/github/GitHubWatchdog/internal/scan"
	"github.com/arkouda/github/GitHubWatchdog/internal/web"
)

const exitCodeFindings = 10

type searchNDJSONEvent struct {
	Type    string           `json:"type"`
	Result  *scan.RepoReport `json:"result,omitempty"`
	Summary *searchSummary   `json:"summary,omitempty"`
}

type searchSummary struct {
	Query           string    `json:"query"`
	StartedAt       time.Time `json:"started_at"`
	CompletedAt     time.Time `json:"completed_at"`
	OldestUpdatedAt time.Time `json:"oldest_updated_at,omitempty"`
	TotalCount      int       `json:"total_count"`
	AnalyzedCount   int       `json:"analyzed_count"`
	FlaggedCount    int       `json:"flagged_count"`
	EmittedCount    int       `json:"emitted_count"`
}

type exitError struct {
	code    int
	message string
}

func (e exitError) Error() string {
	return e.message
}

func (e exitError) ExitCode() int {
	return e.code
}

// Run executes the GitHubWatchdog CLI.
func Run(args []string, stdout, stderr io.Writer) error {
	root := flag.NewFlagSet("githubwatchdog", flag.ContinueOnError)
	root.SetOutput(stderr)

	configPath := root.String("config", "config.json", "Path to the configuration file")
	dbPath := root.String("db", "github_watchdog.db", "Path to the SQLite database")
	legacyWeb := root.Bool("web", false, "Run the web server")
	legacyAddr := root.String("addr", "127.0.0.1:8080", "Address for the web server")
	root.Usage = func() {
		writeUsage(stderr)
	}

	if err := root.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if *legacyWeb {
		cfg, err := loadConfig(*configPath)
		if err != nil {
			return err
		}
		appLogger := logger.New(cfg.Verbose != nil && *cfg.Verbose)
		database, err := db.New(*dbPath)
		if err != nil {
			return fmt.Errorf("opening database: %w", err)
		}
		defer database.Close()
		return runServeCommand(cfg, database, appLogger, *legacyAddr)
	}

	command := "search"
	commandArgs := root.Args()
	if len(commandArgs) > 0 {
		command = commandArgs[0]
		commandArgs = commandArgs[1:]
	}

	switch command {
	case "search":
		if helpRequested(commandArgs) {
			return runSearchCommand(commandArgs, stdout, stderr, defaultConfig(), nil, logger.New(false))
		}
		cfg, database, appLogger, err := openRuntime(*configPath, *dbPath)
		if err != nil {
			return err
		}
		defer database.Close()
		return runSearchCommand(commandArgs, stdout, stderr, cfg, database, appLogger)
	case "repo":
		if helpRequested(commandArgs) {
			return runRepoCommand(commandArgs, stdout, stderr, defaultConfig(), nil, logger.New(false))
		}
		cfg, database, appLogger, err := openRuntime(*configPath, *dbPath)
		if err != nil {
			return err
		}
		defer database.Close()
		return runRepoCommand(commandArgs, stdout, stderr, cfg, database, appLogger)
	case "user":
		if helpRequested(commandArgs) {
			return runUserCommand(commandArgs, stdout, stderr, defaultConfig(), nil, logger.New(false))
		}
		cfg, database, appLogger, err := openRuntime(*configPath, *dbPath)
		if err != nil {
			return err
		}
		defer database.Close()
		return runUserCommand(commandArgs, stdout, stderr, cfg, database, appLogger)
	case "serve":
		if helpRequested(commandArgs) {
			return runServeSubcommand(commandArgs, stderr, defaultConfig(), nil, logger.New(false))
		}
		cfg, database, appLogger, err := openRuntime(*configPath, *dbPath)
		if err != nil {
			return err
		}
		defer database.Close()
		return runServeSubcommand(commandArgs, stderr, cfg, database, appLogger)
	case "help":
		writeUsage(stdout)
		return nil
	default:
		writeUsage(stderr)
		return fmt.Errorf("unknown command %q", command)
	}
}

func runSearchCommand(args []string, stdout, stderr io.Writer, cfg *config.Config, database *db.Database, appLogger *logger.Logger) error {
	fs := flag.NewFlagSet("search", flag.ContinueOnError)
	fs.SetOutput(stderr)

	query := fs.String("query", cfg.GitHubQuery, "GitHub search query")
	since := fs.String("since", "", "Only include repositories updated on or after this date (YYYY-MM-DD or RFC3339)")
	updatedBefore := fs.String("updated-before", "", "Only include repositories updated on or before this date (YYYY-MM-DD or RFC3339)")
	maxPages := fs.Int("max-pages", intValue(cfg.MaxPages, 10), "Maximum number of result pages to scan")
	perPage := fs.Int("per-page", intValue(cfg.PerPage, 100), "Repositories to request per page")
	maxConcurrent := fs.Int("max-concurrent", intValue(cfg.MaxConcurrent, 10), "Maximum concurrent repository analyses")
	timeout := fs.Duration("timeout", 60*time.Minute, "Overall command timeout")
	persist := fs.Bool("persist", true, "Persist results to the SQLite database")
	format := fs.String("format", "json", "Output format: json, ndjson, or text")
	onlyFlagged := fs.Bool("only-flagged", false, "Only include flagged repositories in output")
	includeSkipped := fs.Bool("include-skipped", true, "Include skipped repositories in output")
	failOnFindings := fs.Bool("fail-on-findings", false, "Exit with code 10 when findings are present")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := validateFormat(*format); err != nil {
		return err
	}

	effectiveQuery, err := buildSearchQuery(*query, *since, *updatedBefore)
	if err != nil {
		return err
	}

	service := newScanService(cfg, database, appLogger)
	ctx, cancel := interruptibleContext(*timeout)
	defer cancel()

	var report scan.SearchReport
	var reportErr error
	if *format == "ndjson" {
		report, reportErr = writeSearchNDJSON(stdout, service, ctx, scan.SearchOptions{
			Query:         effectiveQuery,
			MaxPages:      *maxPages,
			PerPage:       *perPage,
			MaxConcurrent: *maxConcurrent,
			Persist:       *persist,
		}, *onlyFlagged, *includeSkipped)
		if reportErr != nil {
			return reportErr
		}
	} else {
		report, reportErr = service.Search(ctx, scan.SearchOptions{
			Query:         effectiveQuery,
			MaxPages:      *maxPages,
			PerPage:       *perPage,
			MaxConcurrent: *maxConcurrent,
			Persist:       *persist,
		})
		if reportErr != nil {
			return reportErr
		}
		if err := writeSearchReport(stdout, *format, report.Filter(*onlyFlagged, *includeSkipped)); err != nil {
			return err
		}
	}
	if *failOnFindings && report.FlaggedCount() > 0 {
		return exitError{code: exitCodeFindings}
	}
	return nil
}

func runRepoCommand(args []string, stdout, stderr io.Writer, cfg *config.Config, database *db.Database, appLogger *logger.Logger) error {
	fs := flag.NewFlagSet("repo", flag.ContinueOnError)
	fs.SetOutput(stderr)

	timeout := fs.Duration("timeout", 5*time.Minute, "Overall command timeout")
	persist := fs.Bool("persist", true, "Persist results to the SQLite database")
	format := fs.String("format", "json", "Output format: json, ndjson, or text")
	failOnFindings := fs.Bool("fail-on-findings", false, "Exit with code 10 when findings are present")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("repo command requires a single <owner>/<repo> argument")
	}
	if err := validateFormat(*format); err != nil {
		return err
	}

	owner, repo, err := parseRepoRef(fs.Arg(0))
	if err != nil {
		return err
	}

	service := newScanService(cfg, database, appLogger)
	ctx, cancel := interruptibleContext(*timeout)
	defer cancel()

	report, err := service.ScanRepository(ctx, owner, repo, scan.RepoOptions{
		Persist:         *persist,
		SkipIfUnchanged: false,
		AnalyzeOwner:    true,
	})
	if err != nil {
		return err
	}

	if err := writeRepoReport(stdout, *format, report); err != nil {
		return err
	}
	if *failOnFindings && report.IsFlagged() {
		return exitError{code: exitCodeFindings}
	}
	return nil
}

func runUserCommand(args []string, stdout, stderr io.Writer, cfg *config.Config, database *db.Database, appLogger *logger.Logger) error {
	fs := flag.NewFlagSet("user", flag.ContinueOnError)
	fs.SetOutput(stderr)

	timeout := fs.Duration("timeout", 5*time.Minute, "Overall command timeout")
	persist := fs.Bool("persist", true, "Persist results to the SQLite database")
	format := fs.String("format", "json", "Output format: json, ndjson, or text")
	failOnFindings := fs.Bool("fail-on-findings", false, "Exit with code 10 when findings are present")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("user command requires a single <username> argument")
	}
	if err := validateFormat(*format); err != nil {
		return err
	}

	service := newScanService(cfg, database, appLogger)
	ctx, cancel := interruptibleContext(*timeout)
	defer cancel()

	report, err := service.ScanUser(ctx, fs.Arg(0), scan.UserOptions{Persist: *persist})
	if err != nil {
		return err
	}

	if err := writeUserReport(stdout, *format, report); err != nil {
		return err
	}
	if *failOnFindings && report.Suspicious {
		return exitError{code: exitCodeFindings}
	}
	return nil
}

func runServeSubcommand(args []string, stderr io.Writer, cfg *config.Config, database *db.Database, appLogger *logger.Logger) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)

	addr := fs.String("addr", "127.0.0.1:8080", "Address to run web server on")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	return runServeCommand(cfg, database, appLogger, *addr)
}

func runServeCommand(cfg *config.Config, database *db.Database, appLogger *logger.Logger, addr string) error {
	server := web.NewServer(database, addr, appLogger, &web.ServerConfig{
		GitHubToken: cfg.Token,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Start()
	}()

	appLogger.Info("Web server running at %s", addr)
	appLogger.Info("Press Ctrl+C to stop")

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutting down server: %w", err)
		}
		return nil
	case err := <-errCh:
		return err
	}
}

func newScanService(cfg *config.Config, database *db.Database, appLogger *logger.Logger) *scan.Service {
	client := github.NewClient(
		cfg.Token,
		intValue(cfg.RateLimitBuffer, 500),
		intValue(cfg.CacheTTL, 60),
		appLogger.IsVerbose(),
	)
	return scan.NewService(client, database)
}

func loadConfig(configPath string) (*config.Config, error) {
	cfg, err := config.New(configPath)
	if err == nil {
		return cfg, nil
	}

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return nil, err
	}

	cfg = defaultConfig()
	cfg.Token = token
	return cfg, nil
}

func defaultConfig() *config.Config {
	maxPages := 10
	perPage := 100
	maxConcurrent := 10
	rateLimitBuffer := 500
	cacheTTL := 60
	verbose := true

	return &config.Config{
		MaxPages:        &maxPages,
		PerPage:         &perPage,
		GitHubQuery:     "created:>2025-02-23 stars:>5",
		Token:           "",
		MaxConcurrent:   &maxConcurrent,
		RateLimitBuffer: &rateLimitBuffer,
		CacheTTL:        &cacheTTL,
		Verbose:         &verbose,
	}
}

func openRuntime(configPath, dbPath string) (*config.Config, *db.Database, *logger.Logger, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, nil, nil, err
	}

	appLogger := logger.New(cfg.Verbose != nil && *cfg.Verbose)
	database, err := db.New(dbPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("opening database: %w", err)
	}

	return cfg, database, appLogger, nil
}

func writeUsage(w io.Writer) {
	fmt.Fprintln(w, "GitHubWatchdog")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  githubwatchdog [global flags] search [search flags]")
	fmt.Fprintln(w, "  githubwatchdog [global flags] repo <owner>/<repo> [scan flags]")
	fmt.Fprintln(w, "  githubwatchdog [global flags] user <username> [scan flags]")
	fmt.Fprintln(w, "  githubwatchdog [global flags] serve [serve flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Global flags:")
	fmt.Fprintln(w, "  -config string   Path to config file (default: config.json)")
	fmt.Fprintln(w, "  -db string       Path to SQLite database (default: github_watchdog.db)")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  - Scan commands default to JSON output for agent-friendly consumption.")
	fmt.Fprintln(w, "  - search --format ndjson streams result lines plus a final summary line.")
	fmt.Fprintln(w, "  - search --since and --updated-before add validated updated: qualifiers to the GitHub query.")
	fmt.Fprintln(w, "  - Running with no subcommand defaults to the batch search command.")
	fmt.Fprintln(w, "  - Legacy web mode is still available via -web and -addr.")
	fmt.Fprintln(w, "  - Exit code 10 indicates findings when --fail-on-findings is used.")
}

func writeSearchReport(w io.Writer, format string, report scan.SearchReport) error {
	switch format {
	case "json":
		return writeJSON(w, report)
	case "ndjson":
		return writeCompactJSON(w, report)
	case "text":
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Query: %s\n", report.Query))
		sb.WriteString(fmt.Sprintf("Started: %s\n", report.StartedAt.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("Completed: %s\n", report.CompletedAt.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("Repositories: %d total, %d analyzed, %d flagged\n",
			len(report.Results), report.AnalyzedCount(), report.FlaggedCount()))
		if !report.OldestUpdatedAt.IsZero() {
			sb.WriteString(fmt.Sprintf("Oldest updated_at: %s\n", report.OldestUpdatedAt.Format(time.RFC3339)))
		}
		for _, result := range report.Results {
			status := "clean"
			if result.Skipped {
				status = "skipped"
			} else if result.IsFlagged() {
				status = "flagged"
			}
			sb.WriteString(fmt.Sprintf("\n- %s [%s]\n", result.RepoID, status))
			if result.SkipReason != "" {
				sb.WriteString(fmt.Sprintf("  skip: %s\n", result.SkipReason))
			}
			if len(result.RepoFlags) > 0 {
				sb.WriteString(fmt.Sprintf("  repo flags: %d\n", len(result.RepoFlags)))
			}
			if result.OwnerAnalysis != nil {
				sb.WriteString(fmt.Sprintf("  owner suspicious: %t\n", result.OwnerAnalysis.Suspicious))
			}
			for _, err := range result.Errors {
				sb.WriteString(fmt.Sprintf("  error: %s\n", err))
			}
		}
		_, err := io.WriteString(w, sb.String())
		return err
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeRepoReport(w io.Writer, format string, report scan.RepoReport) error {
	switch format {
	case "json":
		return writeJSON(w, report)
	case "ndjson":
		return writeCompactJSON(w, report)
	case "text":
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Repository: %s\n", report.RepoID))
		sb.WriteString(fmt.Sprintf("Updated: %s\n", report.UpdatedAt.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("Disk usage: %d KB\n", report.DiskUsage))
		sb.WriteString(fmt.Sprintf("Stargazers: %d\n", report.Stargazers))
		sb.WriteString(fmt.Sprintf("Malicious: %t\n", report.IsMalicious))
		sb.WriteString(fmt.Sprintf("Repo flags: %d\n", len(report.RepoFlags)))
		if report.OwnerAnalysis != nil {
			sb.WriteString(fmt.Sprintf("Owner suspicious: %t\n", report.OwnerAnalysis.Suspicious))
		}
		if report.Skipped {
			sb.WriteString(fmt.Sprintf("Skipped: %s\n", report.SkipReason))
		}
		for _, err := range report.Errors {
			sb.WriteString(fmt.Sprintf("Error: %s\n", err))
		}
		_, err := io.WriteString(w, sb.String())
		return err
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeUserReport(w io.Writer, format string, report scan.UserReport) error {
	switch format {
	case "json":
		return writeJSON(w, report)
	case "text":
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("User: %s\n", report.Username))
		sb.WriteString(fmt.Sprintf("Created: %s\n", report.CreatedAt.Format(time.RFC3339)))
		sb.WriteString(fmt.Sprintf("Suspicious: %t\n", report.Suspicious))
		sb.WriteString(fmt.Sprintf("Contributions: %d\n", report.Contributions))
		sb.WriteString(fmt.Sprintf("Total stars: %d\n", report.TotalStars))
		sb.WriteString(fmt.Sprintf("Empty repos: %d\n", report.EmptyCount))
		sb.WriteString(fmt.Sprintf("Suspicious empty repos: %d\n", report.SuspiciousEmptyCount))
		for _, heuristic := range report.Heuristics {
			if heuristic.Flag {
				sb.WriteString(fmt.Sprintf("Flag: [%s] %s - %s\n", heuristic.Category, heuristic.Name, heuristic.Description))
			}
		}
		for _, err := range report.Errors {
			sb.WriteString(fmt.Sprintf("Error: %s\n", err))
		}
		_, err := io.WriteString(w, sb.String())
		return err
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeJSON(w io.Writer, value interface{}) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func writeCompactJSON(w io.Writer, value interface{}) error {
	return json.NewEncoder(w).Encode(value)
}

func validateFormat(format string) error {
	switch format {
	case "json", "text", "ndjson":
		return nil
	default:
		return fmt.Errorf("invalid format %q: expected json, ndjson, or text", format)
	}
}

func buildSearchQuery(baseQuery, since, updatedBefore string) (string, error) {
	query := strings.TrimSpace(baseQuery)
	if (since != "" || updatedBefore != "") && strings.Contains(strings.ToLower(query), "updated:") {
		return "", errors.New("cannot combine --since/--updated-before with a query that already includes updated:")
	}

	if since != "" {
		normalized, err := normalizeSearchDate(since)
		if err != nil {
			return "", fmt.Errorf("invalid --since value: %w", err)
		}
		query = strings.TrimSpace(query + " updated:>=" + normalized)
	}
	if updatedBefore != "" {
		normalized, err := normalizeSearchDate(updatedBefore)
		if err != nil {
			return "", fmt.Errorf("invalid --updated-before value: %w", err)
		}
		query = strings.TrimSpace(query + " updated:<=" + normalized)
	}

	return query, nil
}

func normalizeSearchDate(value string) (string, error) {
	value = strings.TrimSpace(value)
	for _, layout := range []string{time.DateOnly, time.RFC3339} {
		if parsed, err := time.Parse(layout, value); err == nil {
			if layout == time.DateOnly {
				return parsed.Format(time.DateOnly), nil
			}
			return parsed.UTC().Format(time.RFC3339), nil
		}
	}
	return "", fmt.Errorf("expected YYYY-MM-DD or RFC3339, got %q", value)
}

func parseRepoRef(value string) (string, string, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid repository %q: expected <owner>/<repo>", value)
	}
	return parts[0], parts[1], nil
}

func intValue(value *int, fallback int) int {
	if value == nil {
		return fallback
	}
	return *value
}

func interruptibleContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	base, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	ctx, cancel := context.WithTimeout(base, timeout)
	return ctx, func() {
		cancel()
		stop()
	}
}

func helpRequested(args []string) bool {
	for _, arg := range args {
		if arg == "-h" || arg == "--help" {
			return true
		}
	}
	return false
}

func writeSearchNDJSON(
	w io.Writer,
	service *scan.Service,
	ctx context.Context,
	opts scan.SearchOptions,
	onlyFlagged bool,
	includeSkipped bool,
) (scan.SearchReport, error) {
	emittedCount := 0
	report, err := service.SearchStream(ctx, opts, func(result scan.RepoReport) error {
		if !shouldEmitSearchResult(result, onlyFlagged, includeSkipped) {
			return nil
		}
		emittedCount++
		return writeCompactJSON(w, searchNDJSONEvent{
			Type:   "result",
			Result: &result,
		})
	})
	if err != nil {
		return report, err
	}

	return report, writeCompactJSON(w, searchNDJSONEvent{
		Type: "summary",
		Summary: &searchSummary{
			Query:           report.Query,
			StartedAt:       report.StartedAt,
			CompletedAt:     report.CompletedAt,
			OldestUpdatedAt: report.OldestUpdatedAt,
			TotalCount:      len(report.Results),
			AnalyzedCount:   report.AnalyzedCount(),
			FlaggedCount:    report.FlaggedCount(),
			EmittedCount:    emittedCount,
		},
	})
}

func shouldEmitSearchResult(result scan.RepoReport, onlyFlagged, includeSkipped bool) bool {
	if !includeSkipped && result.Skipped {
		return false
	}
	if onlyFlagged && !result.IsFlagged() {
		return false
	}
	return true
}
