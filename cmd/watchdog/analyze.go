package main

import (
	"bufio"
	"context"
	"log"
	"os"
	"time"

	"github.com/google/go-github/v68/github"
)

// Heuristic constants.
const (
	minTotalStarsForOriginal      = 10
	minEmptyCountForOriginal      = 20
	minSuspiciousReposCountForNew = 5
	maxContributionsForNew        = 5
	minTotalStarsForRecent        = 10
	maxAccountAgeForRecent        = 3 * 24 * time.Hour // 3 days
)

var scannedUsers = make(map[string]bool)

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

// analyzeUser retrieves the user's profile and repositories, and then
// returns true if any of the following suspicious conditions are met:
//   - suspiciousOriginal: Indicates original content exhibiting unusual patterns.
//   - suspiciousNew: Flags new or emerging patterns that require attention.
//   - suspiciousRecent: Marks recent activities as potentially suspicious.
func analyzeUser(ctx context.Context, client *github.Client, username string) bool {
	// Check if the user was already scanned.
	if scannedUsers[username] {
		log.Printf("User %s has already been scanned.", username)
		return false
	}

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
		// Mark user as scanned even if no repositories found.
		scannedUsers[username] = true
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

	suspiciousOriginal := (totalStars >= minTotalStarsForOriginal && emptyCount >= minEmptyCountForOriginal)
	suspiciousNew := (suspiciousReposCount >= minSuspiciousReposCountForNew && contributions <= maxContributionsForNew)
	suspiciousRecent := (accountAge < maxAccountAgeForRecent && totalStars >= minTotalStarsForRecent)

	// Mark user as scanned.
	scannedUsers[username] = true

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
