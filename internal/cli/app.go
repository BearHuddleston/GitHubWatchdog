package cli

import (
	"bytes"
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

type searchProfile struct {
	Name          string
	Description   string
	Query         string
	Since         string
	UpdatedBefore string
	MaxPages      int
	PerPage       int
}

type searchNDJSONEvent struct {
	Type    string           `json:"type"`
	Result  *scan.RepoReport `json:"result,omitempty"`
	Summary *searchSummary   `json:"summary,omitempty"`
}

type searchSummary struct {
	CheckpointName    string    `json:"checkpoint_name,omitempty"`
	ProfileName       string    `json:"profile_name,omitempty"`
	BaseQuery         string    `json:"base_query,omitempty"`
	Query             string    `json:"query"`
	Since             string    `json:"since,omitempty"`
	UpdatedBefore     string    `json:"updated_before,omitempty"`
	NextUpdatedBefore string    `json:"next_updated_before,omitempty"`
	StartedAt         time.Time `json:"started_at"`
	CompletedAt       time.Time `json:"completed_at"`
	OldestUpdatedAt   time.Time `json:"oldest_updated_at,omitempty"`
	TotalCount        int       `json:"total_count"`
	AnalyzedCount     int       `json:"analyzed_count"`
	FlaggedCount      int       `json:"flagged_count"`
	EmittedCount      int       `json:"emitted_count"`
}

type repoSummary struct {
	EntityType      string   `json:"entity_type"`
	RepoID          string   `json:"repo_id"`
	IsFlagged       bool     `json:"is_flagged"`
	IsMalicious     bool     `json:"is_malicious"`
	OwnerSuspicious bool     `json:"owner_suspicious"`
	RepoFlagCount   int      `json:"repo_flag_count"`
	RepoFlags       []string `json:"repo_flags,omitempty"`
	Errors          []string `json:"errors,omitempty"`
}

type userSummary struct {
	EntityType     string   `json:"entity_type"`
	Username       string   `json:"username"`
	IsSuspicious   bool     `json:"is_suspicious"`
	HeuristicCount int      `json:"heuristic_count"`
	Heuristics     []string `json:"heuristics,omitempty"`
	Contributions  int      `json:"contributions"`
	TotalStars     int      `json:"total_stars"`
	Errors         []string `json:"errors,omitempty"`
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
		if helpRequested(commandArgs) || listProfilesRequested(commandArgs) {
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
	case "verdict":
		if helpRequested(commandArgs) {
			return runVerdictCommand(commandArgs, stdout, stderr, defaultConfig(), nil, logger.New(false))
		}
		cfg, database, appLogger, err := openRuntime(*configPath, *dbPath)
		if err != nil {
			return err
		}
		defer database.Close()
		return runVerdictCommand(commandArgs, stdout, stderr, cfg, database, appLogger)
	case "checkpoints":
		database, err := db.New(*dbPath)
		if err != nil {
			return fmt.Errorf("opening database: %w", err)
		}
		defer database.Close()
		return runCheckpointCommand(commandArgs, stdout, stderr, database)
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
	profileName := fs.String("profile", "", "Built-in search profile: recent, high-signal, or backfill")
	listProfiles := fs.Bool("list-profiles", false, "List built-in search profiles and exit")
	checkpointName := fs.String("checkpoint", "", "Save search progress under this checkpoint name")
	resume := fs.Bool("resume", false, "Resume search defaults from the named checkpoint")
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
	if *listProfiles {
		writeSearchProfiles(stdout)
		return nil
	}
	if *resume && strings.TrimSpace(*checkpointName) == "" {
		return errors.New("--resume requires --checkpoint")
	}

	var checkpoint db.SearchCheckpoint
	if *resume {
		if database == nil {
			return errors.New("checkpoint resume requires a database")
		}
		var err error
		checkpoint, err = database.GetSearchCheckpoint(*checkpointName)
		if err != nil {
			return err
		}
	}

	profile, err := resolveSearchProfile(*profileName)
	if err != nil {
		return err
	}
	profileValue := profile.Name
	if profileValue == "" {
		profileValue = checkpoint.ProfileName
	}
	queryValue := cfg.GitHubQuery
	if flagPassed(fs, "query") {
		queryValue = *query
	} else {
		queryValue = firstNonEmpty(checkpoint.BaseQuery, profile.Query, cfg.GitHubQuery)
	}
	sinceValue := *since
	if !flagPassed(fs, "since") {
		sinceValue = firstNonEmpty(checkpoint.Since, profile.Since)
	}
	updatedBeforeValue := *updatedBefore
	if !flagPassed(fs, "updated-before") {
		updatedBeforeValue = firstNonEmpty(checkpoint.NextUpdatedBefore, checkpoint.UpdatedBefore, profile.UpdatedBefore)
	}
	maxPagesValue := *maxPages
	if !flagPassed(fs, "max-pages") && profile.MaxPages > 0 {
		maxPagesValue = profile.MaxPages
	}
	perPageValue := *perPage
	if !flagPassed(fs, "per-page") && profile.PerPage > 0 {
		perPageValue = profile.PerPage
	}

	effectiveQuery, err := buildSearchQuery(queryValue, sinceValue, updatedBeforeValue)
	if err != nil {
		return err
	}
	searchOpts := scan.SearchOptions{
		CheckpointName: *checkpointName,
		ProfileName:    profileValue,
		BaseQuery:      queryValue,
		Query:          effectiveQuery,
		Since:          sinceValue,
		UpdatedBefore:  updatedBeforeValue,
		MaxPages:       maxPagesValue,
		PerPage:        perPageValue,
		MaxConcurrent:  *maxConcurrent,
		Persist:        *persist,
	}

	service := newScanService(cfg, database, appLogger)
	ctx, cancel := interruptibleContext(*timeout)
	defer cancel()

	var report scan.SearchReport
	var reportErr error
	if *format == "ndjson" {
		report, reportErr = writeSearchNDJSON(stdout, service, ctx, searchOpts, *onlyFlagged, *includeSkipped)
		if reportErr != nil {
			return reportErr
		}
	} else {
		report, reportErr = service.Search(ctx, searchOpts)
		if reportErr != nil {
			return reportErr
		}
		report.NextUpdatedBefore = nextUpdatedBefore(report.OldestUpdatedAt)
		if err := writeSearchReport(stdout, *format, report.Filter(*onlyFlagged, *includeSkipped)); err != nil {
			return err
		}
	}
	if *format == "ndjson" && report.NextUpdatedBefore == "" {
		report.NextUpdatedBefore = nextUpdatedBefore(report.OldestUpdatedAt)
	}
	if *checkpointName != "" {
		if err := saveSearchCheckpoint(database, report); err != nil {
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
	summary := fs.Bool("summary", false, "Emit a compact verdict summary instead of the full report")
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

	if *summary {
		if err := writeRepoSummary(stdout, *format, summarizeRepoReport(report)); err != nil {
			return err
		}
	} else if err := writeRepoReport(stdout, *format, report); err != nil {
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
	summary := fs.Bool("summary", false, "Emit a compact verdict summary instead of the full report")
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

	if *summary {
		if err := writeUserSummary(stdout, *format, summarizeUserReport(report)); err != nil {
			return err
		}
	} else if err := writeUserReport(stdout, *format, report); err != nil {
		return err
	}
	if *failOnFindings && report.Suspicious {
		return exitError{code: exitCodeFindings}
	}
	return nil
}

func runVerdictCommand(args []string, stdout, stderr io.Writer, cfg *config.Config, database *db.Database, appLogger *logger.Logger) error {
	fs := flag.NewFlagSet("verdict", flag.ContinueOnError)
	fs.SetOutput(stderr)

	timeout := fs.Duration("timeout", 5*time.Minute, "Overall command timeout")
	persist := fs.Bool("persist", true, "Persist results to the SQLite database")
	format := fs.String("format", "json", "Output format: json, ndjson, or text")
	input := fs.String("input", "", "Read newline-delimited verdict targets from this path; use - for stdin")
	failOnFindings := fs.Bool("fail-on-findings", false, "Exit with code 10 when findings are present")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("verdict command requires a single <owner>/<repo> or <username> argument")
	}
	if err := validateFormat(*format); err != nil {
		return err
	}
	if strings.TrimSpace(*input) != "" && fs.NArg() > 0 {
		return errors.New("verdict command accepts either a single target argument or --input, not both")
	}
	if strings.TrimSpace(*input) == "" && fs.NArg() != 1 {
		return errors.New("verdict command requires a single <owner>/<repo> or <username> argument, or --input for batch mode")
	}

	service := newScanService(cfg, database, appLogger)
	ctx, cancel := interruptibleContext(*timeout)
	defer cancel()

	if strings.TrimSpace(*input) != "" {
		targets, err := readVerdictTargets(*input)
		if err != nil {
			return err
		}
		anyFindings, err := runVerdictBatch(ctx, stdout, *format, service, targets, *persist)
		if err != nil {
			return err
		}
		if *failOnFindings && anyFindings {
			return exitError{code: exitCodeFindings}
		}
		return nil
	}

	summary, err := scanVerdictTarget(ctx, service, fs.Arg(0), *persist)
	if err != nil {
		return err
	}
	if err := writeVerdictSummary(stdout, *format, summary); err != nil {
		return err
	}
	if *failOnFindings && verdictHasFindings(summary) {
		return exitError{code: exitCodeFindings}
	}
	return nil
}

func runCheckpointCommand(args []string, stdout, stderr io.Writer, database *db.Database) error {
	fs := flag.NewFlagSet("checkpoints", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "Output format: json or text")
	input := fs.String("input", "-", "Import input path for checkpoints import; use - for stdin")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := validateCheckpointFormat(*format); err != nil {
		return err
	}

	subcommand := "list"
	if fs.NArg() > 0 {
		subcommand = fs.Arg(0)
	}

	switch subcommand {
	case "list":
		checkpoints, err := database.ListSearchCheckpoints()
		if err != nil {
			return err
		}
		return writeCheckpointList(stdout, *format, checkpoints)
	case "show":
		if fs.NArg() != 2 {
			return errors.New("checkpoints show requires a checkpoint name")
		}
		checkpoint, err := database.GetSearchCheckpoint(fs.Arg(1))
		if err != nil {
			return err
		}
		return writeCheckpoint(stdout, *format, checkpoint)
	case "delete":
		if fs.NArg() != 2 {
			return errors.New("checkpoints delete requires a checkpoint name")
		}
		return database.DeleteSearchCheckpoint(fs.Arg(1))
	case "export":
		return runCheckpointExport(stdout, *format, database, fs.Args()[1:])
	case "import":
		return runCheckpointImport(stdout, *format, database, *input)
	default:
		return fmt.Errorf("unknown checkpoints subcommand %q", subcommand)
	}
}

func runCheckpointExport(stdout io.Writer, format string, database *db.Database, args []string) error {
	switch len(args) {
	case 0:
		checkpoints, err := database.ListSearchCheckpoints()
		if err != nil {
			return err
		}
		return writeCheckpointList(stdout, format, checkpoints)
	case 1:
		checkpoint, err := database.GetSearchCheckpoint(args[0])
		if err != nil {
			return err
		}
		return writeCheckpoint(stdout, format, checkpoint)
	default:
		return errors.New("checkpoints export accepts at most one checkpoint name")
	}
}

func runCheckpointImport(stdout io.Writer, format string, database *db.Database, inputPath string) error {
	data, err := readCheckpointImportInput(inputPath)
	if err != nil {
		return err
	}
	checkpoints, err := decodeCheckpointImport(data)
	if err != nil {
		return err
	}
	for _, checkpoint := range checkpoints {
		if err := database.UpsertSearchCheckpoint(checkpoint); err != nil {
			return err
		}
	}
	return writeCheckpointImportResult(stdout, format, len(checkpoints))
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
	fmt.Fprintln(w, "  githubwatchdog [global flags] verdict <owner/repo|username> [verdict flags]")
	fmt.Fprintln(w, "  githubwatchdog [global flags] checkpoints <list|show|delete|export|import> [args]")
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
	fmt.Fprintln(w, "  - search --profile applies a built-in preset; explicit flags override the preset.")
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

func writeRepoSummary(w io.Writer, format string, summary repoSummary) error {
	switch format {
	case "json":
		return writeJSON(w, summary)
	case "ndjson":
		return writeCompactJSON(w, summary)
	case "text":
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Repository: %s\n", summary.RepoID))
		sb.WriteString(fmt.Sprintf("Flagged: %t\n", summary.IsFlagged))
		sb.WriteString(fmt.Sprintf("Malicious: %t\n", summary.IsMalicious))
		sb.WriteString(fmt.Sprintf("Owner suspicious: %t\n", summary.OwnerSuspicious))
		sb.WriteString(fmt.Sprintf("Repo flag count: %d\n", summary.RepoFlagCount))
		for _, flag := range summary.RepoFlags {
			sb.WriteString(fmt.Sprintf("Flag: %s\n", flag))
		}
		for _, err := range summary.Errors {
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

func writeUserSummary(w io.Writer, format string, summary userSummary) error {
	switch format {
	case "json":
		return writeJSON(w, summary)
	case "ndjson":
		return writeCompactJSON(w, summary)
	case "text":
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("User: %s\n", summary.Username))
		sb.WriteString(fmt.Sprintf("Suspicious: %t\n", summary.IsSuspicious))
		sb.WriteString(fmt.Sprintf("Heuristic count: %d\n", summary.HeuristicCount))
		sb.WriteString(fmt.Sprintf("Contributions: %d\n", summary.Contributions))
		sb.WriteString(fmt.Sprintf("Total stars: %d\n", summary.TotalStars))
		for _, heuristic := range summary.Heuristics {
			sb.WriteString(fmt.Sprintf("Heuristic: %s\n", heuristic))
		}
		for _, err := range summary.Errors {
			sb.WriteString(fmt.Sprintf("Error: %s\n", err))
		}
		_, err := io.WriteString(w, sb.String())
		return err
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeVerdictSummary(w io.Writer, format string, summary interface{}) error {
	switch typed := summary.(type) {
	case repoSummary:
		return writeRepoSummary(w, format, typed)
	case userSummary:
		return writeUserSummary(w, format, typed)
	default:
		return fmt.Errorf("unsupported verdict summary type %T", summary)
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

func validateCheckpointFormat(format string) error {
	switch format {
	case "json", "text":
		return nil
	default:
		return fmt.Errorf("invalid format %q: expected json or text", format)
	}
}

type checkpointImportResult struct {
	Imported int `json:"imported"`
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

func listProfilesRequested(args []string) bool {
	for _, arg := range args {
		if arg == "-list-profiles" || arg == "--list-profiles" {
			return true
		}
	}
	return false
}

func nextUpdatedBefore(oldest time.Time) string {
	if oldest.IsZero() {
		return ""
	}
	return oldest.Add(-1 * time.Second).UTC().Format(time.RFC3339)
}

func resolveSearchProfile(name string) (searchProfile, error) {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return searchProfile{}, nil
	}

	now := time.Now().UTC()
	profiles := map[string]searchProfile{
		"recent": {
			Name:        "recent",
			Description: "Fresh activity sweep over the last 7 days with a shallow page budget.",
			Query:       "stars:>5",
			Since:       now.Add(-7 * 24 * time.Hour).Format(time.DateOnly),
			MaxPages:    3,
			PerPage:     100,
		},
		"high-signal": {
			Name:        "high-signal",
			Description: "Higher-star recent sweep for likely-visible suspicious repos.",
			Query:       "stars:>20",
			Since:       now.Add(-30 * 24 * time.Hour).Format(time.DateOnly),
			MaxPages:    5,
			PerPage:     100,
		},
		"backfill": {
			Name:          "backfill",
			Description:   "Historical sweep older than the recent window for broader backlog coverage.",
			Query:         "stars:>5",
			UpdatedBefore: now.Add(-7 * 24 * time.Hour).Format(time.DateOnly),
			MaxPages:      20,
			PerPage:       100,
		},
	}

	profile, ok := profiles[name]
	if !ok {
		return searchProfile{}, fmt.Errorf("unknown search profile %q", name)
	}
	return profile, nil
}

func writeSearchProfiles(w io.Writer) {
	now := time.Now().UTC()
	_, _ = fmt.Fprintf(w, "Built-in search profiles (generated %s)\n", now.Format(time.RFC3339))
	for _, name := range []string{"recent", "high-signal", "backfill"} {
		profile, _ := resolveSearchProfile(name)
		_, _ = fmt.Fprintf(w, "\n- %s\n", profile.Name)
		_, _ = fmt.Fprintf(w, "  %s\n", profile.Description)
		_, _ = fmt.Fprintf(w, "  query=%q", profile.Query)
		if profile.Since != "" {
			_, _ = fmt.Fprintf(w, " since=%s", profile.Since)
		}
		if profile.UpdatedBefore != "" {
			_, _ = fmt.Fprintf(w, " updated-before=%s", profile.UpdatedBefore)
		}
		if profile.MaxPages > 0 {
			_, _ = fmt.Fprintf(w, " max-pages=%d", profile.MaxPages)
		}
		if profile.PerPage > 0 {
			_, _ = fmt.Fprintf(w, " per-page=%d", profile.PerPage)
		}
		_, _ = fmt.Fprintln(w)
	}
}

func writeCheckpointList(w io.Writer, format string, checkpoints []db.SearchCheckpoint) error {
	switch format {
	case "json":
		return writeJSON(w, checkpoints)
	case "text":
		if len(checkpoints) == 0 {
			_, err := io.WriteString(w, "No checkpoints.\n")
			return err
		}
		var sb strings.Builder
		for _, checkpoint := range checkpoints {
			sb.WriteString(fmt.Sprintf("- %s", checkpoint.Name))
			if checkpoint.ProfileName != "" {
				sb.WriteString(fmt.Sprintf(" profile=%s", checkpoint.ProfileName))
			}
			if checkpoint.NextUpdatedBefore != "" {
				sb.WriteString(fmt.Sprintf(" next-updated-before=%s", checkpoint.NextUpdatedBefore))
			}
			if !checkpoint.CompletedAt.IsZero() {
				sb.WriteString(fmt.Sprintf(" completed=%s", checkpoint.CompletedAt.Format(time.RFC3339)))
			}
			sb.WriteString("\n")
		}
		_, err := io.WriteString(w, sb.String())
		return err
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeCheckpoint(w io.Writer, format string, checkpoint db.SearchCheckpoint) error {
	switch format {
	case "json":
		return writeJSON(w, checkpoint)
	case "text":
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("Name: %s\n", checkpoint.Name))
		sb.WriteString(fmt.Sprintf("Profile: %s\n", checkpoint.ProfileName))
		sb.WriteString(fmt.Sprintf("Base query: %s\n", checkpoint.BaseQuery))
		sb.WriteString(fmt.Sprintf("Effective query: %s\n", checkpoint.EffectiveQuery))
		if checkpoint.Since != "" {
			sb.WriteString(fmt.Sprintf("Since: %s\n", checkpoint.Since))
		}
		if checkpoint.UpdatedBefore != "" {
			sb.WriteString(fmt.Sprintf("Updated before: %s\n", checkpoint.UpdatedBefore))
		}
		if checkpoint.NextUpdatedBefore != "" {
			sb.WriteString(fmt.Sprintf("Next updated before: %s\n", checkpoint.NextUpdatedBefore))
		}
		if !checkpoint.OldestUpdatedAt.IsZero() {
			sb.WriteString(fmt.Sprintf("Oldest updated at: %s\n", checkpoint.OldestUpdatedAt.Format(time.RFC3339)))
		}
		if !checkpoint.CompletedAt.IsZero() {
			sb.WriteString(fmt.Sprintf("Completed at: %s\n", checkpoint.CompletedAt.Format(time.RFC3339)))
		}
		_, err := io.WriteString(w, sb.String())
		return err
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func writeCheckpointImportResult(w io.Writer, format string, imported int) error {
	result := checkpointImportResult{Imported: imported}
	switch format {
	case "json":
		return writeJSON(w, result)
	case "text":
		_, err := fmt.Fprintf(w, "Imported %d checkpoint(s).\n", imported)
		return err
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func saveSearchCheckpoint(database *db.Database, report scan.SearchReport) error {
	if database == nil || report.CheckpointName == "" {
		return nil
	}
	return database.UpsertSearchCheckpoint(db.SearchCheckpoint{
		Name:              report.CheckpointName,
		ProfileName:       report.ProfileName,
		BaseQuery:         report.BaseQuery,
		EffectiveQuery:    report.Query,
		Since:             report.Since,
		UpdatedBefore:     report.UpdatedBefore,
		NextUpdatedBefore: report.NextUpdatedBefore,
		OldestUpdatedAt:   report.OldestUpdatedAt,
		CompletedAt:       report.CompletedAt,
	})
}

func summarizeRepoReport(report scan.RepoReport) repoSummary {
	summary := repoSummary{
		EntityType:      "repo",
		RepoID:          report.RepoID,
		IsFlagged:       report.IsFlagged(),
		IsMalicious:     report.IsMalicious,
		OwnerSuspicious: report.OwnerAnalysis != nil && report.OwnerAnalysis.Suspicious,
		RepoFlagCount:   len(report.RepoFlags),
		Errors:          append([]string(nil), report.Errors...),
	}
	for _, flag := range report.RepoFlags {
		summary.RepoFlags = append(summary.RepoFlags, fmt.Sprintf("%s:%s", flag.Category, flag.Name))
	}
	return summary
}

func summarizeUserReport(report scan.UserReport) userSummary {
	summary := userSummary{
		EntityType:    "user",
		Username:      report.Username,
		IsSuspicious:  report.Suspicious,
		Contributions: report.Contributions,
		TotalStars:    report.TotalStars,
		Errors:        append([]string(nil), report.Errors...),
	}
	for _, heuristic := range report.Heuristics {
		if heuristic.Flag {
			summary.HeuristicCount++
			summary.Heuristics = append(summary.Heuristics, fmt.Sprintf("%s:%s", heuristic.Category, heuristic.Name))
		}
	}
	return summary
}

func readVerdictTargets(path string) ([]string, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading verdict targets from stdin: %w", err)
		}
	} else {
		data, err = os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading verdict targets file: %w", err)
		}
	}
	return parseVerdictTargets(data)
}

func parseVerdictTargets(data []byte) ([]string, error) {
	var targets []string
	for _, line := range strings.Split(string(data), "\n") {
		target := strings.TrimSpace(line)
		if target == "" {
			continue
		}
		targets = append(targets, target)
	}
	if len(targets) == 0 {
		return nil, errors.New("verdict input is empty")
	}
	return targets, nil
}

func runVerdictBatch(ctx context.Context, stdout io.Writer, format string, service *scan.Service, targets []string, persist bool) (bool, error) {
	anyFindings := false
	summaries := make([]interface{}, 0, len(targets))
	for _, target := range targets {
		summary, err := scanVerdictTarget(ctx, service, target, persist)
		if err != nil {
			return false, err
		}
		if verdictHasFindings(summary) {
			anyFindings = true
		}
		summaries = append(summaries, summary)
	}
	if err := writeVerdictBatch(stdout, format, summaries); err != nil {
		return false, err
	}
	return anyFindings, nil
}

func scanVerdictTarget(ctx context.Context, service *scan.Service, target string, persist bool) (interface{}, error) {
	switch strings.Count(target, "/") {
	case 0:
		report, err := service.ScanUser(ctx, target, scan.UserOptions{Persist: persist})
		if err != nil {
			return nil, err
		}
		return summarizeUserReport(report), nil
	case 1:
		owner, repo, err := parseRepoRef(target)
		if err != nil {
			return nil, err
		}
		report, err := service.ScanRepository(ctx, owner, repo, scan.RepoOptions{
			Persist:         persist,
			SkipIfUnchanged: false,
			AnalyzeOwner:    true,
		})
		if err != nil {
			return nil, err
		}
		return summarizeRepoReport(report), nil
	default:
		return nil, fmt.Errorf("invalid verdict target %q: expected <owner>/<repo> or <username>", target)
	}
}

func verdictHasFindings(summary interface{}) bool {
	switch typed := summary.(type) {
	case repoSummary:
		return typed.IsFlagged
	case userSummary:
		return typed.IsSuspicious
	default:
		return false
	}
}

func writeVerdictBatch(w io.Writer, format string, summaries []interface{}) error {
	switch format {
	case "json":
		return writeJSON(w, summaries)
	case "ndjson":
		for _, summary := range summaries {
			if err := writeVerdictSummary(w, format, summary); err != nil {
				return err
			}
		}
		return nil
	case "text":
		for i, summary := range summaries {
			if i > 0 {
				if _, err := io.WriteString(w, "\n"); err != nil {
					return err
				}
			}
			if err := writeVerdictSummary(w, format, summary); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func readCheckpointImportInput(path string) ([]byte, error) {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading checkpoint import from stdin: %w", err)
		}
		return data, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading checkpoint import file: %w", err)
	}
	return data, nil
}

func decodeCheckpointImport(data []byte) ([]db.SearchCheckpoint, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("checkpoint import is empty")
	}

	if data[0] == '[' {
		var checkpoints []db.SearchCheckpoint
		if err := json.Unmarshal(data, &checkpoints); err != nil {
			return nil, fmt.Errorf("decoding checkpoint import array: %w", err)
		}
		return checkpoints, nil
	}

	var checkpoint db.SearchCheckpoint
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		return nil, fmt.Errorf("decoding checkpoint import object: %w", err)
	}
	return []db.SearchCheckpoint{checkpoint}, nil
}

func flagPassed(fs *flag.FlagSet, name string) bool {
	passed := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			passed = true
		}
	})
	return passed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
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
	report.NextUpdatedBefore = nextUpdatedBefore(report.OldestUpdatedAt)

	return report, writeCompactJSON(w, searchNDJSONEvent{
		Type: "summary",
		Summary: &searchSummary{
			CheckpointName:    report.CheckpointName,
			ProfileName:       report.ProfileName,
			BaseQuery:         report.BaseQuery,
			Query:             report.Query,
			Since:             report.Since,
			UpdatedBefore:     report.UpdatedBefore,
			NextUpdatedBefore: report.NextUpdatedBefore,
			StartedAt:         report.StartedAt,
			CompletedAt:       report.CompletedAt,
			OldestUpdatedAt:   report.OldestUpdatedAt,
			TotalCount:        len(report.Results),
			AnalyzedCount:     report.AnalyzedCount(),
			FlaggedCount:      report.FlaggedCount(),
			EmittedCount:      emittedCount,
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
