package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/go-github/v68/github"
)

const (
	minTotalStarsForOriginal      = 10
	minEmptyCountForOriginal      = 20
	minSuspiciousReposCountForNew = 5
	maxContributionsForNew        = 5
	minTotalStarsForRecent        = 10
	maxAccountAgeForRecent        = 3 * 24 * time.Hour // 3 days
)

type Analyzer struct {
	processedUsers map[string]bool
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		processedUsers: make(map[string]bool),
	}
}

func (a *Analyzer) contributionsLastYear(ctx context.Context, client *github.Client, username string) int {
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
		for _, event := range events {
			if event.CreatedAt != nil && event.CreatedAt.Time.After(oneYearAgo) {
				count++
			} else {
				// We can exit once an event is older than a year.
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

// analyzeUser retrieves the user's profile and repositories,
// and flags the user as suspicious if any set of heuristics is met.
func (a *Analyzer) analyzeUser(ctx context.Context, client *github.Client, username string) bool {
	if a.processedUsers[username] {
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

	// List repositories owned by the user.
	opts := &github.RepositoryListOptions{
		Type: "owner",
		ListOptions: github.ListOptions{
			PerPage: 100,
		},
	}
	var repos []*github.Repository
	for {
		r, resp, err := client.Repositories.List(ctx, username, opts)
		if err != nil {
			log.Printf("Error listing repos for user %s: %v", username, err)
			break
		}
		repos = append(repos, r...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	if len(repos) == 0 {
		log.Printf("User %s has no repositories.", username)
		a.processedUsers[username] = true
		return false
	}

	totalStars, emptyCount, suspiciousEmptyCount := 0, 0, 0
	const emptyThreshold = 10
	for _, repo := range repos {
		stars := repo.GetStargazersCount()
		totalStars += stars
		if repo.GetSize() < emptyThreshold {
			emptyCount++
			if stars >= 5 {
				suspiciousEmptyCount++
			}
		}
	}

	contributions := a.contributionsLastYear(ctx, client, username)

	log.Printf("User %s details: age %v, totalStars %d, emptyCount %d, suspiciousEmptyRepos %d, contributions %d",
		username, accountAge, totalStars, emptyCount, suspiciousEmptyCount, contributions)

	flagOriginal := totalStars >= minTotalStarsForOriginal && emptyCount >= minEmptyCountForOriginal
	flagNew := suspiciousEmptyCount >= minSuspiciousReposCountForNew && contributions <= maxContributionsForNew
	flagRecent := accountAge < maxAccountAgeForRecent && totalStars >= minTotalStarsForRecent

	a.processedUsers[username] = true

	if flagOriginal || flagNew || flagRecent {
		log.Printf("User %s flagged (original=%v, new=%v, recent=%v)", username, flagOriginal, flagNew, flagRecent)
		return true
	}
	return false
}

// loadProcessedRepos reads a file and returns a set of processed repository IDs.
func loadProcessedRepos(filename string) (map[string]bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]bool), nil
		}
		return nil, err
	}
	defer file.Close()

	processed := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			processed[line] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return processed, nil
}

// writeLineToFile appends a line to the given file.
func writeLineToFile(filename, line string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(line + "\n")
	return err
}

func appendSuspiciousUser(filename, username string) error {
	return writeLineToFile(filename, username)
}

func appendMaliciousRepo(filename, repoID string) error {
	return writeLineToFile(filename, repoID)
}

func appendMaliciousStargazer(filename, username string) error {
	return writeLineToFile(filename, username)
}

// analyzeRepo checks the repository README for malware indicators.
// If found, it categorizes the repo as malicious and records its stargazers.
func analyzeRepo(ctx context.Context, client *github.Client, owner, repoName, malRepoFile, malStargazerFile string) error {
	readme, _, err := client.Repositories.GetReadme(ctx, owner, repoName, nil)
	if err != nil {
		return fmt.Errorf("fetching README for %s/%s: %w", owner, repoName, err)
	}

	content, err := readme.GetContent()
	if err != nil {
		return fmt.Errorf("decoding README for %s/%s: %w", owner, repoName, err)
	}

	if strings.Contains(content, "# [DOWNLOAD LINK]") && strings.Contains(content, "# PASSWORD : 2025") {
		log.Printf("Repository %s/%s categorized as malware.", owner, repoName)
		repoID := fmt.Sprintf("%s/%s", owner, repoName)
		if err := appendMaliciousRepo(malRepoFile, repoID); err != nil {
			log.Printf("Recording malware repo %s: %v", repoID, err)
		}
		opts := &github.ListOptions{PerPage: 100}
		for {
			stargazers, resp, err := client.Activity.ListStargazers(ctx, owner, repoName, opts)
			if err != nil {
				log.Printf("Fetching stargazers for %s/%s: %v", owner, repoName, err)
				break
			}
			for _, user := range stargazers {
				login := user.User.GetLogin()
				if err := appendMaliciousStargazer(malStargazerFile, login); err != nil {
					log.Printf("Recording malicious stargazer %s: %v", login, err)
				}
			}
			if resp.NextPage == 0 {
				break
			}
			opts.Page = resp.NextPage
		}
	}
	return nil
}
