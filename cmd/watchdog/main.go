package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"githubwatchdog.bearhuddleston/internal/analyzer"
	"githubwatchdog.bearhuddleston/internal/config"
	"githubwatchdog.bearhuddleston/internal/db"
	"githubwatchdog.bearhuddleston/internal/github"
	"githubwatchdog.bearhuddleston/internal/processor"
)

func main() {
	// Load configuration.
	cfg, err := config.New()
	if err != nil {
		log.Fatal(err)
	}

	// Initialize the database (creates file if needed).
	database, err := db.NewDatabase("github_watchdog.db")
	if err != nil {
		log.Fatal(err)
	}
	defer database.Close()

	// Load all processed users into memory.
	processedUsers, err := database.GetProcessedUsers()
	if err != nil {
		log.Fatalf("Could not load processed users: %v", err)
	}
	log.Printf("Loaded %d processed users", len(processedUsers))

	log.Println("GitHub token loaded. Starting repository search.")

	// Create a GitHub client.
	client := github.NewClient(cfg.Token)

	// Set up context with a timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	anlz := analyzer.NewAnalyzer()

	currentQuery := cfg.GitHubQuery

	// Main processing loop.
	for {
		log.Printf("Searching for repositories: query=%s", currentQuery)
		// Pass the processedUsers map to the processing routine.
		oldest, err := processor.SearchAndProcessRepositories(ctx, client, currentQuery, cfg, anlz, database, processedUsers)
		if err != nil {
			if strings.Contains(err.Error(), "403") {
				log.Println("403 Forbidden encountered due to rate limit. Ending application.")
				os.Exit(1)
			}
			log.Fatal(err)
		}
		if oldest.IsZero() {
			log.Println("No more repositories found, ending search.")
			break
		}
		newQuery := fmt.Sprintf("created:<%s stars:>5", oldest.Format(time.RFC3339))
		if newQuery == currentQuery {
			break
		}
		currentQuery = newQuery
		log.Printf("Continuing search with updated query: %s", currentQuery)
	}

	log.Println("Search completed.")
}
