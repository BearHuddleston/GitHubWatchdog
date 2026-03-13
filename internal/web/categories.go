package web

import (
	"strings"
	"time"
)

const (
	categorySpamBehavior        = "Spam Behavior"
	categoryAutomatedActivity   = "Automated Activity"
	categoryMassRepoCreation    = "Mass Repository Creation"
	categoryOtherSuspiciousness = "Other Suspicious Patterns"
)

type userCategoryInput struct {
	CreatedAt            time.Time
	TotalStars           int
	EmptyCount           int
	SuspiciousEmptyCount int
	Contributions        int
	IsSuspicious         bool
	HeuristicFlags       []string
}

func deriveUserCategories(input userCategoryInput) []string {
	categories := make([]string, 0, 4)
	seen := map[string]struct{}{}
	add := func(category string) {
		if category == "" {
			return
		}
		if _, ok := seen[category]; ok {
			return
		}
		seen[category] = struct{}{}
		categories = append(categories, category)
	}

	for _, flag := range input.HeuristicFlags {
		add(categoryFromFlag(flag))
	}

	if input.EmptyCount >= 20 {
		add(categoryMassRepoCreation)
	}
	if input.SuspiciousEmptyCount >= 5 && input.Contributions <= 5 {
		add(categoryAutomatedActivity)
	}
	if !input.CreatedAt.IsZero() && time.Since(input.CreatedAt) < 10*24*time.Hour && input.TotalStars >= 10 {
		add(categorySpamBehavior)
	}
	if input.IsSuspicious && len(categories) == 0 {
		add(categoryOtherSuspiciousness)
	}

	return categories
}

func categoryFromFlag(flag string) string {
	switch {
	case strings.HasPrefix(flag, "["):
		if end := strings.Index(flag, "]"); end > 1 {
			return strings.TrimSpace(flag[1:end])
		}
	case strings.Contains(flag, "OriginalHeuristic"):
		return categoryMassRepoCreation
	case strings.Contains(flag, "NewHeuristic"):
		return categoryAutomatedActivity
	case strings.Contains(flag, "RecentHeuristic"):
		return categorySpamBehavior
	}

	return ""
}
