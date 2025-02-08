package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"log/slog"

	"githubwatchdog.bearhuddleston/internal/analyzer"
	"githubwatchdog.bearhuddleston/internal/config"
	"githubwatchdog.bearhuddleston/internal/fileutil"
	"githubwatchdog.bearhuddleston/internal/github"
	"githubwatchdog.bearhuddleston/internal/processor"
)

func main() {
	// Load configuration.
	cfg, err := config.New()
	if err != nil {
		log.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	logger.Info("GitHub token loaded. Starting repository search.")

	// Create a GitHub client.
	client := github.NewClient(cfg.Token)

	// Set up context with a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	// Load previously processed repositories.
	processedRepos, err := fileutil.LoadProcessedRepos(cfg.RecordFile)
	if err != nil {
		logger.Error(err.Error())
		processedRepos = make(map[string]bool)
	}

	// Initialize application state and analyzer.
	state := processor.NewState(processedRepos)
	anlz := analyzer.NewAnalyzer()

	// Start with the base query.
	currentQuery := cfg.GitHubQuery

	// Main processing loop.
	for {
		logger.Info("Searching for repositories", slog.String("query", currentQuery))
		oldest, err := processor.SearchAndProcessRepositories(ctx, client, currentQuery, cfg, state, anlz)
		if err != nil {
			// If a rate limit error is encountered (e.g. a 403), handle appropriately.
			if err.Error() == "403" { // (or inspect the error details)
				logger.Error("403 Forbidden encountered due to rate limit. Ending application.")
				os.Exit(1)
			}
			logger.Error(err.Error())
			os.Exit(1)
		}
		if oldest.IsZero() {
			logger.Info("No more repositories found, ending search.")
			break
		}

		// Update the query to search for older repositories.
		newQuery := fmt.Sprintf("created:<%s stars:>5", oldest.Format(time.RFC3339))
		if newQuery == currentQuery {
			break
		}
		currentQuery = newQuery
		logger.Info("Continuing search with updated query", slog.String("query", currentQuery))
	}

	logger.Info("Search completed.")
}
