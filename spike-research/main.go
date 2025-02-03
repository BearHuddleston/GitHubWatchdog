package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/go-github/v68/github"
	"golang.org/x/oauth2"
)

// initializeGitHubClient creates a GitHub client using a personal access token.
func initializeGitHubClient(token string) *github.Client {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}

// getContributionsLastYear returns an approximate count of the user's public events
// (used as a proxy for contributions) in the last year.
func getContributionsLastYear(ctx context.Context, client *github.Client, username string) int {
	perPage := 100
	opts := &github.ListOptions{PerPage: perPage}
	count := 0
	oneYearAgo := time.Now().Add(-365 * 24 * time.Hour)
	for {
		events, resp, err := client.Activity.ListEventsPerformedByUser(ctx, username, false, opts)
		if err != nil {
			log.Printf("Error fetching events for user %s: %v", username, err)
			break
		}
		if len(events) == 0 {
			break
		}
		// The events are in reverse chronological order.
		for _, event := range events {
			if event.CreatedAt != nil && event.CreatedAt.Time.After(oneYearAgo) {
				count++
			} else {
				// Once we see an event older than one year, we can stop counting.
				return count
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return count
}

// analyzeUser fetches the user profile and repositories, then returns true if the
// account (which must be new—created within the last 7 days) meets any of the following:
//   - Original criteria: totalStars >= 10 and emptyCount >= 20,
//   - New criteria: at least 5 empty repos with >= 5 stars each and contributions <= 5,
//   - Additional criteria: account is less than 24 hours old and totalStars >= 10.
func analyzeUser(ctx context.Context, client *github.Client, username string) bool {
	user, _, err := client.Users.Get(ctx, username)
	if err != nil {
		log.Printf("Error fetching user %s: %v", username, err)
		return false
	}
	if user.CreatedAt == nil {
		return false
	}
	accountAge := time.Since(user.GetCreatedAt().Time)

	// List all repositories owned by the user.
	opts := &github.RepositoryListOptions{
		Type: "owner",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}
	var allRepos []*github.Repository
	for {
		repos, resp, err := client.Repositories.List(ctx, username, opts)
		if err != nil {
			log.Printf("Error listing repos for user %s: %v", username, err)
			break
		}
		allRepos = append(allRepos, repos...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	if len(allRepos) == 0 {
		log.Printf("User %s has no repositories.", username)
		return false
	}

	totalStars := 0
	emptyCount := 0
	suspiciousReposCount := 0 // Count of repos that are "empty" and have >= 5 stars.
	// Use a threshold for emptiness; sometimes a repo isn't exactly size 0 but is effectively empty.
	const emptyThreshold = 10 // Adjust this threshold as needed.
	for _, repo := range allRepos {
		stars := repo.GetStargazersCount()
		totalStars += stars
		// Consider a repository "empty" if its size is below the threshold.
		if repo.GetSize() < emptyThreshold {
			emptyCount++
			if stars >= 5 {
				suspiciousReposCount++
			}
		}
	}

	contributions := getContributionsLastYear(ctx, client, username)

	// Debug logging for intermediate values.
	log.Printf("User %s details: account age %v, totalStars %d, emptyCount %d, suspiciousEmptyRepos %d, contributions in last year %d",
		username, accountAge, totalStars, emptyCount, suspiciousReposCount, contributions)

	// Original criteria: totalStars >= 10 and emptyCount >= 20.
	suspiciousOriginal := (totalStars >= 10 && emptyCount >= 20)
	// New criteria: at least 5 empty repos with >= 5 stars each and contributions <= 5.
	suspiciousNew := (suspiciousReposCount >= 5 && contributions <= 5)
	// Additional criteria: account is less than 24 hours old and has at least 10 stars.
	suspiciousRecent := (accountAge < 24*time.Hour && totalStars >= 10)

	if suspiciousOriginal || suspiciousNew || suspiciousRecent {
		log.Printf("User %s is flagged as suspicious (suspiciousOriginal=%v, suspiciousNew=%v, suspiciousRecent=%v).", username, suspiciousOriginal, suspiciousNew, suspiciousRecent)
		return true
	}

	return false
}

// loadProcessedRepos reads a file of processed repository IDs and returns a map.
func loadProcessedRepos(filename string) (map[string]bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		// If the file does not exist, return an empty map.
		if os.IsNotExist(err) {
			return make(map[string]bool), nil
		}
		return nil, err
	}
	defer file.Close()

	processed := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != "" {
			processed[line] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return processed, nil
}

// appendProcessedRepo appends a repository ID (owner/repo) to the processed record file.
func appendProcessedRepo(filename, repoID string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(repoID + "\n"); err != nil {
		return err
	}
	return nil
}

// appendSuspiciousUser appends a suspicious username to a record file.
func appendSuspiciousUser(filename, username string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(username + "\n"); err != nil {
		return err
	}
	return nil
}

func main() {
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Fatal("Please set the GITHUB_TOKEN environment variable")
	}
	log.SetFlags(0)
	log.SetOutput(os.Stdout)
	log.Println("GitHub token loaded successfully. Starting repository search.")

	const recordFile = "processed_repos.txt"
	processedRepos, err := loadProcessedRepos(recordFile)
	if err != nil {
		log.Printf("Warning: could not load processed repos record: %v", err)
		processedRepos = make(map[string]bool)
	}

	const suspiciousUserRecordFile = "suspicious_users.txt"

	client := initializeGitHubClient(token)
	ctx := context.Background()

	// Base search query.
	query := `created:>2025-02-02 stars:>5`
	log.Printf("Searching for repositories with query: '%s'", query)

	const maxPages = 10
	const perPage = 100

	opts := &github.SearchOptions{
		Sort:  "updated",
		Order: "desc",
		ListOptions: github.ListOptions{
			PerPage: perPage,
		},
	}

	// Track processed users to avoid duplicate analysis.
	processedUsers := make(map[string]bool)

	// Loop through pages of search results.
	for page := 1; page <= maxPages; page++ {
		opts.Page = page
		result, resp, err := client.Search.Repositories(ctx, query, opts)
		if err != nil {
			log.Fatalf("Error searching repositories on page %d: %v", page, err)
		}
		log.Printf("HTTP Response Status: %s; Page %d: Found %d repositories", resp.Status, page, len(result.Repositories))
		if len(result.Repositories) == 0 {
			break
		}

		for _, repo := range result.Repositories {
			owner := repo.GetOwner().GetLogin()
			repoName := repo.GetName()
			repoID := fmt.Sprintf("%s/%s", owner, repoName)

			if processedRepos[repoID] {
				log.Printf("Repository %s already processed, skipping.", repoID)
				continue
			}

			// If the repository is "empty", analyze the user.
			// (We use the same threshold as in analyzeUser.)
			if repo.GetSize() < 10 {
				log.Printf("Repository %s is considered empty; analyzing user %s.", repoID, owner)
				if !processedUsers[owner] {
					if analyzeUser(ctx, client, owner) {
						log.Printf("Suspicious user detected: %s", owner)
						if err := appendSuspiciousUser(suspiciousUserRecordFile, owner); err != nil {
							log.Printf("Error recording suspicious user %s: %v", owner, err)
						}
					}
					processedUsers[owner] = true
				}
			}

			// Record that this repository has been processed.
			if err := appendProcessedRepo(recordFile, repoID); err != nil {
				log.Printf("Error recording repository %s as processed: %v", repoID, err)
			} else {
				processedRepos[repoID] = true
			}
		}
	}
}
