package analyzer

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/arkouda/github/GitHubWatchdog/internal/github"
	"github.com/arkouda/github/GitHubWatchdog/internal/models"
)

// UserHeuristic represents a heuristic that can be applied to user data
type UserHeuristic interface {
	Evaluate(data models.UserData, repos []models.RepoData) models.HeuristicResult
}

var generatedRepoNamePattern = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)*)[-_](\d{3,})$`)

// OriginalHeuristic is the original heuristic for detecting suspicious users
type OriginalHeuristic struct{}

// Evaluate evaluates the original heuristic
func (h *OriginalHeuristic) Evaluate(data models.UserData, repos []models.RepoData) models.HeuristicResult {
	totalStars, emptyCount, _ := computeRepoMetrics(repos)
	flag := totalStars >= 10 && emptyCount >= 20
	return models.HeuristicResult{
		Category:    "Mass Repository Creation",
		Flag:        flag,
		Name:        "OriginalHeuristic",
		Description: "User has sufficient total stars and empty repositories.",
	}
}

// NewHeuristic is a newer heuristic for detecting suspicious users
type NewHeuristic struct{}

// Evaluate evaluates the new heuristic
func (h *NewHeuristic) Evaluate(data models.UserData, repos []models.RepoData) models.HeuristicResult {
	_, _, suspiciousEmptyCount := computeRepoMetrics(repos)
	flag := suspiciousEmptyCount >= 5 && data.Contributions <= 5
	return models.HeuristicResult{
		Category:    "Automated Activity",
		Flag:        flag,
		Name:        "NewHeuristic",
		Description: "User has many suspicious empty repos and low contributions.",
	}
}

// RecentHeuristic is a heuristic for detecting suspicious recent users
type RecentHeuristic struct{}

// Evaluate evaluates the recent user heuristic
func (h *RecentHeuristic) Evaluate(data models.UserData, repos []models.RepoData) models.HeuristicResult {
	totalStars, _, _ := computeRepoMetrics(repos)
	flag := time.Since(data.CreatedAt) < (10*24*time.Hour) && totalStars >= 10
	return models.HeuristicResult{
		Category:    "Spam Behavior",
		Flag:        flag,
		Name:        "RecentHeuristic",
		Description: "User is recent and has gathered enough stars.",
	}
}

// GeneratedPortfolioHeuristic detects users hosting many similarly named generated repositories.
type GeneratedPortfolioHeuristic struct{}

// Evaluate evaluates the generated portfolio heuristic.
func (h *GeneratedPortfolioHeuristic) Evaluate(data models.UserData, repos []models.RepoData) models.HeuristicResult {
	matchedCount, dominantPrefix, dominantCount, lowContentCount := generatedPortfolioStats(repos)
	flag := matchedCount >= 5 && dominantCount >= 3 && lowContentCount >= 3
	description := "User has many low-content repositories with repeated project-name plus numeric suffix patterns."
	if flag {
		description = fmt.Sprintf("User has %d generated-name repos, including %d variants of %q, with %d low-content matches.",
			matchedCount, dominantCount, dominantPrefix, lowContentCount)
	}

	return models.HeuristicResult{
		Category:    "Automated Activity",
		Flag:        flag,
		Name:        "GeneratedPortfolioHeuristic",
		Description: description,
	}
}

// RepoChecker represents a checker that can be applied to repository data
type RepoChecker interface {
	Check(ctx context.Context, repo models.RepoData) (bool, error)
}

// RepoHeuristic represents a heuristic that can be applied to repository data.
type RepoHeuristic interface {
	Evaluate(repo models.RepoData) models.HeuristicResult
}

// ReadmeChecker checks repository README files for suspicious content
type ReadmeChecker struct{}

// Check evaluates a repository's README
func (rc *ReadmeChecker) Check(ctx context.Context, repo models.RepoData) (bool, error) {
	if repo.Readme == "" {
		return false, nil
	}

	lower := strings.ToLower(repo.Readme)
	if strings.Contains(lower, "download link") && strings.Contains(lower, "password : 2025") {
		return true, nil
	}

	return false, nil
}

// LoaderChecker checks repositories for suspicious loader files
type LoaderChecker struct {
	Client *github.Client
}

// Check evaluates a repository for suspicious loader files
func (lc *LoaderChecker) Check(ctx context.Context, repo models.RepoData) (bool, error) {
	// Check tree entries for loader files
	for _, entry := range repo.TreeEntries {
		lower := strings.ToLower(entry)
		if lower == "loader.zip" || lower == "loader.rar" {
			return true, nil
		}
	}

	// Check releases for loader files
	found, err := lc.Client.CheckRepoReleases(ctx, repo.Owner, repo.Name)
	if err != nil {
		return false, err
	}

	return found, nil
}

// GeneratedRepoNamingHeuristic detects repeated project-name plus numeric suffix patterns.
type GeneratedRepoNamingHeuristic struct{}

// Evaluate evaluates the generated repo naming heuristic.
func (h *GeneratedRepoNamingHeuristic) Evaluate(repo models.RepoData) models.HeuristicResult {
	prefix, matched := generatedRepoNamePrefix(repo.Name)
	flag := matched
	description := "Repository name matches a repeated project-name plus numeric suffix pattern."
	if flag {
		description = fmt.Sprintf("Repository name %q matches generated naming prefix %q.", repo.Name, prefix)
	}

	return models.HeuristicResult{
		Category:    "Automated Activity",
		Flag:        flag,
		Name:        "GeneratedRepoNamingHeuristic",
		Description: description,
	}
}

// BoilerplateReadmeHeuristic detects generic README phrases common in mass-generated repositories.
type BoilerplateReadmeHeuristic struct{}

// Evaluate evaluates the boilerplate README heuristic.
func (h *BoilerplateReadmeHeuristic) Evaluate(repo models.RepoData) models.HeuristicResult {
	lower := strings.ToLower(repo.Readme)
	matchedPhrase := ""
	for _, phrase := range []string{
		"a cool open-source project",
		"ai-generated code",
		"added ai-generated code",
	} {
		if strings.Contains(lower, phrase) {
			matchedPhrase = phrase
			break
		}
	}

	flag := matchedPhrase != ""
	description := "Repository README contains boilerplate language associated with mass-generated repositories."
	if flag {
		description = fmt.Sprintf("README contains boilerplate phrase %q.", matchedPhrase)
	}

	return models.HeuristicResult{
		Category:    "Spam Behavior",
		Flag:        flag,
		Name:        "BoilerplateReadmeHeuristic",
		Description: description,
	}
}

// SparseProjectHeuristic detects repos with a single starter file and very little structure.
type SparseProjectHeuristic struct{}

// Evaluate evaluates the sparse project heuristic.
func (h *SparseProjectHeuristic) Evaluate(repo models.RepoData) models.HeuristicResult {
	flag := len(repo.TreeEntries) > 0 && len(repo.TreeEntries) <= 3 && hasStarterFile(repo.TreeEntries)
	description := "Repository has a very small starter-file structure often seen in generated throwaway projects."
	if flag {
		description = fmt.Sprintf("Repository has %d files and a starter entry (%s).", len(repo.TreeEntries), firstStarterFile(repo.TreeEntries))
	}

	return models.HeuristicResult{
		Category:    "Other Suspicious Patterns",
		Flag:        flag,
		Name:        "SparseProjectHeuristic",
		Description: description,
	}
}

// PromotionSpamReadmeHeuristic detects incentive-driven promotional abuse in README content.
type PromotionSpamReadmeHeuristic struct{}

// Evaluate evaluates the promotion spam README heuristic.
func (h *PromotionSpamReadmeHeuristic) Evaluate(repo models.RepoData) models.HeuristicResult {
	lower := strings.ToLower(repo.Readme)
	incentiveMatch := firstMatchingPhrase(lower, []string{"airdrop", "token", "giveaway", "reward", "referral"})
	actionMatch := firstMatchingPhrase(lower, []string{"join telegram", "join discord", "claim now", "follow for rewards", "star this repo", "dm for access"})
	flag := incentiveMatch != "" && actionMatch != ""
	description := "Repository README combines incentive language with promotional calls to action."
	if flag {
		description = fmt.Sprintf("README combines incentive phrase %q with call to action %q.", incentiveMatch, actionMatch)
	}

	return models.HeuristicResult{
		Category:    "Spam Behavior",
		Flag:        flag,
		Name:        "PromotionSpamReadmeHeuristic",
		Description: description,
	}
}

// EvaluateRepoHeuristics evaluates repository heuristics that indicate generated or inauthentic content.
func EvaluateRepoHeuristics(repo models.RepoData) []models.HeuristicResult {
	heuristics := []RepoHeuristic{
		&GeneratedRepoNamingHeuristic{},
		&BoilerplateReadmeHeuristic{},
		&SparseProjectHeuristic{},
		&PromotionSpamReadmeHeuristic{},
	}

	results := make([]models.HeuristicResult, 0, len(heuristics))
	for _, heuristic := range heuristics {
		result := heuristic.Evaluate(repo)
		if result.Flag {
			results = append(results, result)
		}
	}

	return results
}

func generatedPortfolioStats(repos []models.RepoData) (matchedCount int, dominantPrefix string, dominantCount int, lowContentCount int) {
	prefixCounts := map[string]int{}
	for _, repo := range repos {
		prefix, matched := generatedRepoNamePrefix(repo.Name)
		if !matched {
			continue
		}

		matchedCount++
		prefixCounts[prefix]++
		if repo.DiskUsage < 100 {
			lowContentCount++
		}
		if prefixCounts[prefix] > dominantCount {
			dominantPrefix = prefix
			dominantCount = prefixCounts[prefix]
		}
	}

	return matchedCount, dominantPrefix, dominantCount, lowContentCount
}

func generatedRepoNamePrefix(name string) (string, bool) {
	matches := generatedRepoNamePattern.FindStringSubmatch(name)
	if len(matches) != 3 {
		return "", false
	}

	return strings.ToLower(matches[1]), true
}

func hasStarterFile(entries []string) bool {
	return firstStarterFile(entries) != ""
}

func firstStarterFile(entries []string) string {
	for _, entry := range entries {
		switch strings.ToLower(entry) {
		case "main.py", "main.cpp", "main.js", "main.ts", "main.go", "main.java":
			return entry
		}
	}

	return ""
}

func firstMatchingPhrase(text string, phrases []string) string {
	for _, phrase := range phrases {
		if strings.Contains(text, phrase) {
			return phrase
		}
	}

	return ""
}
