package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/google/go-github/v68/github"
	"golang.org/x/oauth2"
)

func main() {
	// Command-line flags:
	//  -query: GitHub repository search query (e.g., "download", "exe", "phish", etc.)
	//  -max: Maximum number of repositories to scan from the search results
	//  -token: GitHub API token (optional but recommended)
	query := flag.String("query", "download", "GitHub repository search query to find candidate repos")
	maxRepos := flag.Int("max", 10, "Maximum number of repositories to scan")
	token := flag.String("token", "", "GitHub API token (optional but recommended to avoid rate limits)")
	flag.Parse()

	ctx := context.Background()

	var client *github.Client
	if *token != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: *token})
		tc := oauth2.NewClient(ctx, ts)
		client = github.NewClient(tc)
	} else {
		client = github.NewClient(nil)
	}

	fmt.Printf("Searching for repositories matching query: %q\n", *query)
	searchResult, _, err := client.Search.Repositories(ctx, *query, nil)
	if err != nil {
		log.Fatalf("Error searching repositories: %v", err)
	}

	if len(searchResult.Repositories) == 0 {
		fmt.Println("No repositories found matching the query.")
		os.Exit(0)
	}

	// Limit to the first N repositories.
	reposToCheck := searchResult.Repositories
	if len(reposToCheck) > *maxRepos {
		reposToCheck = reposToCheck[:*maxRepos]
	}

	var suspiciousRepos []string

	// For each candidate repository, check if it contains any suspicious commits.
	for _, repo := range reposToCheck {
		owner := repo.GetOwner().GetLogin()
		repoName := repo.GetName()
		fmt.Printf("Scanning repository: %s/%s\n", owner, repoName)

		suspicious, err := checkRepositoryForSuspiciousCommits(ctx, client, owner, repoName)
		if err != nil {
			log.Printf("Error scanning repository %s/%s: %v", owner, repoName, err)
			continue
		}
		if suspicious {
			suspiciousRepos = append(suspiciousRepos, fmt.Sprintf("%s/%s", owner, repoName))
		}
	}

	// Report the results.
	fmt.Println("\n=== Suspicious Repositories ===")
	if len(suspiciousRepos) == 0 {
		fmt.Println("No suspicious repositories found based on the current heuristic.")
	} else {
		for _, r := range suspiciousRepos {
			fmt.Println(r)
		}
	}
}

// checkRepositoryForSuspiciousCommits retrieves the recent commits for a given repository
// and checks each commit to see if it matches the suspicious pattern.
//
// For each commit, for every file diff (patch), every non-blank added line must contain a URL.
//
// If at least one commit in the repository is suspicious, it returns true.
func checkRepositoryForSuspiciousCommits(ctx context.Context, client *github.Client, owner, repoName string) (bool, error) {
	commits, _, err := client.Repositories.ListCommits(ctx, owner, repoName, nil)
	if err != nil {
		return false, fmt.Errorf("error listing commits: %w", err)
	}

	// For proof-of-concept, a simple regex to detect HTTP or HTTPS URLs should suffice.
	linkRegex := regexp.MustCompile(`https?://[^\s]+`)

	for _, commit := range commits {
		sha := commit.GetSHA()
		commitDetails, _, err := client.Repositories.GetCommit(ctx, owner, repoName, sha, nil)
		if err != nil {
			log.Printf("Error getting commit details for %s: %v", sha, err)
			continue
		}
		files := commitDetails.Files
		if len(files) == 0 {
			continue
		}

		// For now, assume the commit is suspicious until proven otherwise.
		commitSuspicious := true

		for _, file := range files {
			patch := file.GetPatch()
			if patch == "" {
				commitSuspicious = false
				break
			}
			// Split the patch into lines because we need to examine each line.
			lines := strings.Split(patch, "\n")
			// Need to examinine each line of the patch because the added content may span multiple lines.
			for _, line := range lines {
				if strings.HasPrefix(line, "+") {
					// Remove the '+' sign.
					content := strings.TrimPrefix(line, "+")
					// Skip blank lines.
					if strings.TrimSpace(content) == "" {
						continue
					}
					// If the added content does not contain a URL, mark the commit as non-suspicious.
					if !linkRegex.MatchString(content) {
						commitSuspicious = false
						break
					}
				}
			}
			if !commitSuspicious {
				break
			}
		}

		if commitSuspicious {
			return true, nil
		}
	}

	return false, nil
}
