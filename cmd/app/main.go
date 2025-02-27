// Main entry point for GitHub Watchdog application
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/arkouda/github/GitHubWatchdog/internal/analyzer"
	"github.com/arkouda/github/GitHubWatchdog/internal/config"
	"github.com/arkouda/github/GitHubWatchdog/internal/db"
	"github.com/arkouda/github/GitHubWatchdog/internal/github"
	"github.com/arkouda/github/GitHubWatchdog/internal/logger"
	"github.com/arkouda/github/GitHubWatchdog/internal/models"
	"github.com/arkouda/github/GitHubWatchdog/internal/web"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Parse command line flags
	webMode := flag.Bool("web", false, "Run in web mode instead of search mode")
	webAddr := flag.String("addr", ":8080", "Address to run web server on")
	flag.Parse()

	// Load configuration
	cfg, err := config.New("config.json")
	if err != nil {
		// Try with environment variable only if loading from file failed
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			// Create config manually
			maxPages := 10
			perPage := 100
			maxConcurrent := 10
			rateLimitBuffer := 500
			cacheTTL := 60
			verbose := true
			cfg = &config.Config{
				MaxPages:        &maxPages,
				PerPage:         &perPage,
				GitHubQuery:     "created:>2025-02-23 stars:>5",
				Token:           token,
				MaxConcurrent:   &maxConcurrent,
				RateLimitBuffer: &rateLimitBuffer,
				CacheTTL:        &cacheTTL,
				Verbose:         &verbose,
			}
		} else {
			log.Fatalf("Loading configuration: %v", err)
		}
	}

	// Initialize logger
	verbose := false
	if cfg.Verbose != nil {
		verbose = *cfg.Verbose
	}
	appLogger := logger.New(verbose)
	appLogger.Info("Initializing GitHubWatchdog with verbose=%v", verbose)

	// Initialize database
	database, err := db.New("github_watchdog.db")
	if err != nil {
		appLogger.Fatal("Initializing database: %v", err)
	}
	defer func() {
		if err := database.Close(); err != nil {
			appLogger.Error("Closing database: %v", err)
		}
	}()

	if *webMode {
		// Run in web mode
		runWebServer(database, *webAddr, appLogger)
	} else {
		// Run in search mode (original functionality)
		runSearchMode(database, cfg, appLogger)
	}
}

// runWebServer starts the web server
func runWebServer(database *db.Database, addr string, appLogger *logger.Logger) {
	// Get GitHub token from environment variable or config
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		// Try loading from config
		cfg, err := config.New("config.json")
		if err == nil && cfg.Token != "" {
			token = cfg.Token
		} else {
			appLogger.Fatal("GitHub token not found in environment variable or config")
		}
	}
	
	server := web.NewServer(database, addr, appLogger, token)

	// Set up signal handling for graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := server.Start(); err != nil {
			appLogger.Fatal("Web server error: %v", err)
		}
	}()

	appLogger.Info("Web server running at %s", addr)
	appLogger.Info("Press Ctrl+C to stop")

	// Wait for interrupt signal
	<-done
	appLogger.Info("Shutting down server...")

	// Create a deadline for server shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		appLogger.Error("Server shutdown error: %v", err)
	}

	appLogger.Info("Server stopped")
}

// runSearchMode runs the original repository search functionality
func runSearchMode(database *db.Database, cfg *config.Config, appLogger *logger.Logger) {
	// Load processed users from database
	processedUsers, err := database.GetProcessedUsers()
	if err != nil {
		appLogger.Fatal("Loading processed users: %v", err)
	}
	appLogger.Info("Loaded %d processed users", len(processedUsers))

	// Initialize GitHub client
	bufferSize := 500
	if cfg.RateLimitBuffer != nil {
		bufferSize = *cfg.RateLimitBuffer
	}

	cacheTTL := 60
	if cfg.CacheTTL != nil {
		cacheTTL = *cfg.CacheTTL
	}

	githubClient := github.NewClient(cfg.Token, bufferSize, cacheTTL, appLogger.IsVerbose())

	// Initialize analyzer
	repoAnalyzer := analyzer.New(githubClient)
	repoAnalyzer.PreloadUsers(processedUsers)

	// Check rate limits before starting
	appLogger.Info("GitHub token loaded. Starting repository search.")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	if err := githubClient.FetchRateLimits(ctx); err != nil {
		appLogger.Error("Warning: Unable to fetch rate limits: %v", err)
	}

	// Main search loop
	currentQuery := cfg.GitHubQuery
	for {
		appLogger.Info("Searching with query: %s", currentQuery)

		// Run search and process repositories
		oldest, err := searchAndProcessRepositories(ctx, githubClient, currentQuery, cfg, repoAnalyzer, database)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				appLogger.Info("Operation cancelled.")
				break
			}
			appLogger.Error("Search error: %v", err)
			// Wait a bit before retrying on errors (could be rate limit related)
			time.Sleep(30 * time.Second)
			// Re-check rate limits explicitly
			if err := githubClient.FetchRateLimits(ctx); err != nil {
				appLogger.Error("Warning: Unable to fetch rate limits: %v", err)
			}
			// Continue instead of breaking on errors
			continue
		}

		if oldest.IsZero() {
			appLogger.Info("No more repositories found; ending search.")
			break
		}

		newQuery := fmt.Sprintf("created:<%s stars:>5", oldest.Format(time.RFC3339))
		if newQuery == currentQuery {
			appLogger.Info("Query unchanged. Ending to prevent infinite loop.")
			break
		}

		currentQuery = newQuery
		appLogger.Info("Continuing with updated query: %s", currentQuery)

		// Sleep briefly between pages to be nice to the API
		time.Sleep(2 * time.Second)
	}
	appLogger.Info("Search completed.")
}

// searchAndProcessRepositories searches for repositories and processes the results
func searchAndProcessRepositories(
	ctx context.Context,
	client *github.Client,
	queryStr string,
	cfg *config.Config,
	analyzer *analyzer.Analyzer,
	database *db.Database,
) (time.Time, error) {
	appLogger := client.GetLogger()
	var oldest time.Time

	maxPages := 10
	if cfg.MaxPages != nil {
		maxPages = *cfg.MaxPages
	}

	perPage := 100
	if cfg.PerPage != nil {
		perPage = *cfg.PerPage
	}

	maxConcurrent := 10
	if cfg.MaxConcurrent != nil {
		maxConcurrent = *cfg.MaxConcurrent
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	errCh := make(chan error, maxConcurrent)

	// Loop over pages
	for page := 1; page <= maxPages; page++ {
		// Search for repositories
		result, err := client.SearchRepositories(ctx, queryStr, page, perPage)
		if err != nil {
			return oldest, err
		}

		appLogger.Info("Page %d: Found %d repositories", page, len(result.Items))
		if len(result.Items) == 0 {
			break
		}

		// Process repositories with limited concurrency
		sem := make(chan struct{}, maxConcurrent)
		for _, item := range result.Items {
			item := item
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				oldestItem, err := processRepository(ctx, analyzer, database, item)
				if err != nil {
					select {
					case errCh <- err:
					default:
					}
					return
				}

				mu.Lock()
				if oldest.IsZero() || oldestItem.Before(oldest) {
					oldest = oldestItem
				}
				mu.Unlock()
			}()
		}

		wg.Wait()

		select {
		case err := <-errCh:
			return oldest, fmt.Errorf("processing error: %w", err)
		default:
		}

		if len(result.Items) < perPage {
			break
		}
	}

	return oldest, nil
}

// processRepository processes a single repository
func processRepository(
	ctx context.Context,
	analyzer *analyzer.Analyzer,
	database *db.Database,
	item models.RepoItem,
) (time.Time, error) {
	log := analyzer.GetLogger()

	repo := models.Repo{
		Owner:          item.Owner.Login,
		Name:           item.Name,
		UpdatedAt:      item.UpdatedAt,
		DiskUsage:      item.Size,
		StargazerCount: item.StargazersCount,
	}

	repoID := fmt.Sprintf("%s/%s", repo.Owner, repo.Name)

	// Check if repo was already processed
	already, err := database.WasRepoProcessed(repoID, repo.UpdatedAt)
	if err != nil {
		log.Error("Checking repo %s: %v", repoID, err)
		return time.Time{}, err
	}

	if already {
		log.Debug("Repo %s already processed, skipping.", repoID)
		return repo.UpdatedAt, nil
	}

	// For small repos, analyze the user
	if repo.DiskUsage < 10 {
		analysis, err := analyzer.AnalyzeUser(ctx, repo.Owner)
		if err != nil {
			log.Error("Analyzing user %s: %v", repo.Owner, err)
		} else {
			// Check if the user has already been flagged
			if !analyzer.IsUserFlagged(repo.Owner) {
				// Insert flags only once per user
				for _, hr := range analysis.HeuristicResults {
					if hr.Flag {
						flagMsg := fmt.Sprintf("%s: %s", hr.Name, hr.Description)
						if err := database.InsertHeuristicFlag("user", repo.Owner, flagMsg); err != nil {
							log.Error("Recording flag for user %s via %s: %v", repo.Owner, hr.Name, err)
						} else {
							log.Info("User %s flagged via %s.", repo.Owner, hr.Name)
						}
					}
				}

				if err := database.InsertProcessedUser(repo.Owner, time.Now(), analysis.TotalStars,
					analysis.EmptyCount, analysis.SuspiciousEmptyCount, analysis.Contributions, analysis.Suspicious); err != nil {
					log.Error("Recording user %s: %v", repo.Owner, err)
				}

				analyzer.MarkUserFlagged(repo.Owner)
			} else {
				log.Debug("User %s already flagged; skipping flag insertion.", repo.Owner)
			}
		}
	}

	// Check repository contents for malicious indicators
	var isMalicious bool
	if repo.DiskUsage > 0 {
		_, malicious, err := analyzer.CheckRepoFiles(ctx, repo.Owner, repo.Name, item.DefaultBranch)
		if err != nil {
			log.Error("Checking repo files for %s: %v", repoID, err)
		}
		isMalicious = malicious
		if isMalicious {
			log.Info("Repo %s/%s flagged as malicious", repo.Owner, repo.Name)
		}
	} else {
		log.Debug("Skipping file analysis for %s due to low disk usage.", repoID)
	}

	// Record the repository in the database
	if err := database.InsertProcessedRepo(repoID, repo.Owner, repo.Name, repo.UpdatedAt, repo.DiskUsage, repo.StargazerCount, isMalicious); err != nil {
		log.Error("Recording repo %s: %v", repoID, err)
		return time.Time{}, err
	}

	return repo.UpdatedAt, nil
}
