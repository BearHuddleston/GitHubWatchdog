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
	"golang.org/x/oauth2"
)

// suspiciousKeywords contains strings found in malicious campaigns.
// (All keywords are in lowercase for a case-insensitive match.)
var suspiciousKeywords = []string{
	".su",
	".ly",
	".tk",
	".buzz",
	".xyz",
	".top",
	".ga",
	".ml",
	".info",
	".cf",
	".gq",
	".icu",
	".wang",
	".live",
	".cn",
	".online",
	".host",
	".us",
	".loan",
	".locker",
	".gdn",
	".bid",
	".pictures",
	".pizza",
	".pink",
	".xin",
	".loans",
	".forsale",
	".lgbt",
	".vip",
	".academy",
	".auction",
	".ooo",
	".poker",
	".plus",
	".boo",
	".mobi",
	".photo",
	".boston",
	".legal",
	".army",
	".rip",
	".miami",
	".skin",
	".one",
	".rest",
	".pet",
	".fan",
	".shop",
	".ink",
	".help",
	".cyou",
	".wiki",
	".tax",
	".pro",
	".agency",
	".kim",
	".support",
	".app",
	".win",
	".world",
	".finance",
	".cfd",
	".ltd",
	".africa",
	".best",
	".blue",
	".life",
	".media",
	".party",
	".bond",
	".social",
}

func initializeGitHubClient(token string) *github.Client {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}

// analyzeRepository fetches additional data to verify suspicious patterns.
func analyzeRepository(ctx context.Context, client *github.Client, owner, repoName string) bool {
	suspicious := false

	log.Printf("Analyzing repository: %s/%s", owner, repoName)
	readme, _, err := client.Repositories.GetReadme(ctx, owner, repoName, nil)
	if err != nil {
		log.Printf("Error fetching README for %s/%s: %v", owner, repoName, err)
	} else {
		content, err := readme.GetContent()
		if err != nil {
			log.Printf("Error decoding README for %s/%s: %v", owner, repoName, err)
		} else {
			// Check for suspicious keywords in the README.
			if found, keyword := containsSuspiciousKeyword(content); found {
				log.Printf("Repository %s/%s README contains suspicious keyword: %s", owner, repoName, keyword)
				suspicious = true
			}
			// Additional check: if the README has only a "DOWNLOAD" header and a linked image.
			if isDownloadOnly(content) {
				log.Printf("Repository %s/%s has a README that only contains a DOWNLOAD header and an image hyperlinked.", owner, repoName)
				suspicious = true
			}
		}
	}

	commits, _, err := client.Repositories.ListCommits(ctx, owner, repoName, nil)
	if err != nil {
		log.Printf("Error fetching commits for %s/%s: %v", owner, repoName, err)
	} else {
		for _, commit := range commits {
			commitMsg := commit.GetCommit().GetMessage()
			if found, keyword := containsSuspiciousKeyword(commitMsg); found {
				log.Printf("Suspicious commit in %s/%s: %s (matched keyword: %s)", owner, repoName, commitMsg, keyword)
				suspicious = true
			}
		}
	}

	return suspicious
}

func containsSuspiciousKeyword(content string) (bool, string) {
	lowerContent := strings.ToLower(content)
	for _, keyword := range suspiciousKeywords {
		if strings.Contains(lowerContent, keyword) {
			return true, keyword
		}
	}
	return false, ""
}

func isDownloadOnly(content string) bool {
	lines := strings.Split(content, "\n")
	var nonEmpty []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			nonEmpty = append(nonEmpty, trimmed)
		}
	}

	if len(nonEmpty) == 2 {
		// Check both orders.
		if isDownloadLine(nonEmpty[0]) && isImageLine(nonEmpty[1]) {
			return true
		}
		if isDownloadLine(nonEmpty[1]) && isImageLine(nonEmpty[0]) {
			return true
		}
	}
	return false
}

// Helper to check if a line indicates a download link.
func isDownloadLine(line string) bool {
	upper := strings.ToUpper(line)
	// Recognize either plain "DOWNLOAD" or a markdown link "[download](url)"
	if strings.Contains(upper, "DOWNLOAD") || strings.HasPrefix(upper, "[DOWNLOAD](") {
		return true
	}
	return false
}

// Helper to check if a line is an image markdown.
func isImageLine(line string) bool {
	return strings.HasPrefix(line, "![")
}

// loadProcessedRepos reads a file of processed repositories and returns a map.
func loadProcessedRepos(filename string) (map[string]bool, error) {
	file, err := os.Open(filename)
	if err != nil {
		// If file does not exist, return an empty map without error.
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

// appendProcessedRepo appends a repository id (owner/repoName) to the processed record file.
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

// appendSuspiciousRepo appends a suspicious repository id (owner/repoName) to the suspicious record file.
func appendSuspiciousRepo(filename, repoID string) error {
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

// analyzeUser fetches the user profile, lists all user repositories,
// and returns true if the user was created within 24 hours, has at least 10 stars,
// and has at least 20 empty repositories.
func analyzeUser(ctx context.Context, client *github.Client, username string) bool {
	user, _, err := client.Users.Get(ctx, username)
	if err != nil {
		log.Printf("Error fetching user %s: %v", username, err)
		return false
	}
	if user.CreatedAt == nil {
		return false
	}
	// Check if account was created within the last 24 hours.
	if time.Since(user.GetCreatedAt().Time) > 24*time.Hour {
		return false
	}

	// List all repositories for the user.
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
		return false
	}

	// Count total stars and empty repositories (using repo size as an indicator).
	totalStars := 0
	emptyCount := 0
	for _, repo := range allRepos {
		totalStars += repo.GetStargazersCount()
		if repo.GetSize() == 0 {
			emptyCount++
		}
	}

	if totalStars >= 10 && emptyCount >= 20 {
		log.Printf("User %s meets criteria: created at %v, %d stars, %d empty repos", username, user.GetCreatedAt(), totalStars, emptyCount)
		return true
	}

	return false
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
	log.Println("GitHub token loaded successfully. Starting GitHub repository search.")

	const recordFile = "processed_repos.txt"
	const suspiciousRecordFile = "suspicious_repos.txt"
	processedRepos, err := loadProcessedRepos(recordFile)
	if err != nil {
		log.Printf("Warning: could not load processed repos record: %v", err)
		processedRepos = make(map[string]bool)
	}

	client := initializeGitHubClient(token)
	ctx := context.Background()

	const maxPages = 10
	const perPage = 100

	// Base search query.
	query := `created:>2025-02-01 stars:>5`
	log.Printf("Searching for repositories with query: '%s'", query)

	suspiciousCount := 0
	opts := &github.SearchOptions{
		Sort:  "updated",
		Order: "desc",
		ListOptions: github.ListOptions{
			PerPage: perPage,
		},
	}

	// To avoid duplicate processing, track processed users.
	processedUsers := make(map[string]bool)

	const suspiciousUserRecordFile = "suspicious_users.txt"

	// Loop through pages up to maxPages.
	for page := 1; page <= maxPages; page++ {
		opts.Page = page
		result, resp, err := client.Search.Repositories(ctx, query, opts)
		if err != nil {
			log.Fatalf("Error searching repositories on page %d: %v", page, err)
		}
		// Debug logging: print HTTP response status and total count
		log.Printf("HTTP Response Status: %s; Total repositories matching query: %d", resp.Status, result.GetTotal())
		log.Printf("Page %d: Found %d repositories", page, len(result.Repositories))
		if len(result.Repositories) == 0 {
			break
		}

		for _, repo := range result.Repositories {
			owner := repo.GetOwner().GetLogin()
			repoName := repo.GetName()
			repoID := fmt.Sprintf("%s/%s", owner, repoName)
			if processedRepos[repoID] {
				log.Printf("Repository %s already processed, skipping analysis.", repoID)
				continue
			}

			// Analyze all repositories.
			analysisFound := analyzeRepository(ctx, client, owner, repoName)
			if analysisFound {
				suspiciousCount++
				fmt.Printf("Suspicious repository found: %s\n", repoID)
				if err := appendSuspiciousRepo(suspiciousRecordFile, repoID); err != nil {
					log.Printf("Error recording suspicious repository %s: %v", repoID, err)
				}
			}

			// Record that this repository has been processed.
			if err := appendProcessedRepo(recordFile, repoID); err != nil {
				log.Printf("Error recording repository %s as processed: %v", repoID, err)
			} else {
				processedRepos[repoID] = true
			}

			// Check the owner/user if not processed before.
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
	}

	if suspiciousCount == 0 {
		log.Println("No suspicious repositories found in search results.")
	}
}
