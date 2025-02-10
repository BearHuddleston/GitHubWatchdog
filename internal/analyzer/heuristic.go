package analyzer

import "time"

// Thresholds for flagging user accounts.
const (
	minTotalStarsForOriginal      = 10
	minEmptyCountForOriginal      = 20
	minSuspiciousReposCountForNew = 5
	maxContributionsForNew        = 5
	minTotalStarsForRecent        = 10
	maxAccountAgeForRecent        = 10 * 24 * time.Hour // 10 days
)

// HeuristicResult represents the result of evaluating a heuristic.
type HeuristicResult struct {
	Flag        bool
	Name        string
	Description string
}

// UserHeuristic defines an interface to evaluate heuristic rules on user data.
type UserHeuristic interface {
	Evaluate(data userData, repos []repoData) HeuristicResult
}

// OriginalHeuristic checks older users based on total stars and empty repos.
type OriginalHeuristic struct{}

func (h OriginalHeuristic) Evaluate(data userData, repos []repoData) HeuristicResult {
	totalStars, emptyCount, _ := computeRepoMetrics(repos)
	flag := totalStars >= minTotalStarsForOriginal && emptyCount >= minEmptyCountForOriginal
	return HeuristicResult{
		Flag:        flag,
		Name:        "OriginalHeuristic",
		Description: "User has sufficient total stars and empty repositories.",
	}
}

// NewHeuristic checks for new accounts with limited contributions.
type NewHeuristic struct{}

func (h NewHeuristic) Evaluate(data userData, repos []repoData) HeuristicResult {
	_, _, suspiciousEmptyCount := computeRepoMetrics(repos)
	flag := suspiciousEmptyCount >= minSuspiciousReposCountForNew && data.Contributions <= maxContributionsForNew
	return HeuristicResult{
		Flag:        flag,
		Name:        "NewHeuristic",
		Description: "User has a high number of suspicious empty repos and low contributions.",
	}
}

// RecentHeuristic checks for recent accounts.
type RecentHeuristic struct{}

func (h RecentHeuristic) Evaluate(data userData, repos []repoData) HeuristicResult {
	totalStars, _, _ := computeRepoMetrics(repos)
	accountAge := time.Since(data.CreatedAt)
	flag := accountAge < maxAccountAgeForRecent && totalStars >= minTotalStarsForRecent
	return HeuristicResult{
		Flag:        flag,
		Name:        "RecentHeuristic",
		Description: "User is recent and has gathered enough stars.",
	}
}

// EvaluateUserHeuristics applies all heuristics to the given user data and repositories.
func EvaluateUserHeuristics(data userData, repos []repoData) ([]HeuristicResult, bool) {
	heuristics := []UserHeuristic{
		OriginalHeuristic{},
		NewHeuristic{},
		RecentHeuristic{},
	}
	suspicious := false
	var results []HeuristicResult
	for _, h := range heuristics {
		result := h.Evaluate(data, repos)
		if result.Flag {
			suspicious = true
		}
		results = append(results, result)
	}
	return results, suspicious
}
