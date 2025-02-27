package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/arkouda/github/GitHubWatchdog/internal/github"
)

// RepoReportResponse represents the repository report data
type RepoReportResponse struct {
	Owner          string    `json:"owner"`
	Name           string    `json:"name"`
	UpdatedAt      time.Time `json:"updated_at"`
	Size           int       `json:"size"`
	Stars          int       `json:"stars"`
	Files          []string  `json:"files"`
	ReadmeContent  string    `json:"readme_content"`
	DefaultBranch  string    `json:"default_branch"`
	Language       string    `json:"language"`
	IsMalicious    bool      `json:"is_malicious"`
	ProcessedAt    time.Time `json:"processed_at"`
	HeuristicFlags []string  `json:"heuristic_flags"`
}

// UserReportResponse represents the user report data
type UserReportResponse struct {
	Username             string    `json:"username"`
	CreatedAt            time.Time `json:"created_at"`
	TotalStars           int       `json:"total_stars"`
	Contributions        int       `json:"contributions"`
	RepoCount            int       `json:"repo_count"`
	EmptyCount           int       `json:"empty_count"`
	SuspiciousEmptyCount int       `json:"suspicious_empty_count"`
	IsSuspicious         bool      `json:"is_suspicious"`
	ProcessedAt          time.Time `json:"processed_at"`
	HeuristicFlags       []string  `json:"heuristic_flags"`
}

// repositoryReportHandler handles requests for repository report data
func (s *Server) repositoryReportHandler(w http.ResponseWriter, r *http.Request) {
	owner := r.URL.Query().Get("owner")
	repo := r.URL.Query().Get("repo")

	if owner == "" || repo == "" {
		http.Error(w, "Missing owner or repo parameter", http.StatusBadRequest)
		return
	}

	// Create GitHub client (we'll use our existing client in a real implementation)
	githubClient := github.NewClient(s.config.GitHubToken, 5, 60, true)

	// Get repository data from database
	var repoData RepoReportResponse
	repoData.Owner = owner
	repoData.Name = repo

	// Query for processed repository data
	err := s.db.QueryRow(`
		SELECT updated_at, disk_usage, stargazer_count, is_malicious, processed_at 
		FROM processed_repositories 
		WHERE owner = ? AND name = ?`, 
		owner, repo).Scan(
			&repoData.UpdatedAt,
			&repoData.Size,
			&repoData.Stars,
			&repoData.IsMalicious,
			&repoData.ProcessedAt,
		)
	
	if err != nil {
		// If not in our database, try to get basic info from GitHub
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		// Search for the repository
		searchResult, err := githubClient.SearchRepositories(ctx, fmt.Sprintf("repo:%s/%s", owner, repo), 1, 1)
		if err != nil {
			s.logger.Error("Error searching for repository: %v", err)
			http.Error(w, "Error fetching repository data", http.StatusInternalServerError)
			return
		}

		if len(searchResult.Items) == 0 {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}

		// Set data from search results
		item := searchResult.Items[0]
		repoData.UpdatedAt = item.UpdatedAt
		repoData.Size = item.Size
		repoData.Stars = item.StargazersCount
		repoData.DefaultBranch = item.DefaultBranch
	}

	// Get heuristic flags for this repository
	rows, err := s.db.Query(`
		SELECT flag FROM heuristic_flags 
		WHERE entity_type = 'repo' AND entity_id = ?`,
		fmt.Sprintf("%s/%s", owner, repo))
	
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var flag string
			if err := rows.Scan(&flag); err == nil {
				repoData.HeuristicFlags = append(repoData.HeuristicFlags, flag)
			}
		}
	}

	// Try to get the README content from GitHub
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	
	readme, err := githubClient.GetRepoReadme(ctx, owner, repo)
	if err == nil {
		// Truncate if too long
		if len(readme) > 2000 {
			repoData.ReadmeContent = readme[:2000] + "...(truncated)"
		} else {
			repoData.ReadmeContent = readme
		}
	}

	// Try to get file list
	if repoData.DefaultBranch == "" {
		repoData.DefaultBranch = "main" // Fallback to main if we don't have default branch
	}
	
	files, err := githubClient.GetRepoTree(ctx, owner, repo, repoData.DefaultBranch)
	if err == nil {
		// Only include first 50 files to avoid making response too large
		if len(files) > 50 {
			repoData.Files = files[:50]
		} else {
			repoData.Files = files
		}
	}

	// Return the report data as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(repoData)
}

// userReportHandler handles requests for user report data
func (s *Server) userReportHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	if username == "" {
		http.Error(w, "Missing username parameter", http.StatusBadRequest)
		return
	}

	// Create GitHub client
	githubClient := github.NewClient(s.config.GitHubToken, 5, 60, true)

	// Get user data from database
	var userData UserReportResponse
	userData.Username = username

	// Query for processed user data
	err := s.db.QueryRow(`
		SELECT created_at, total_stars, empty_count, suspicious_empty_count, contributions, analysis_result, processed_at 
		FROM processed_users 
		WHERE username = ?`, 
		username).Scan(
			&userData.CreatedAt,
			&userData.TotalStars,
			&userData.EmptyCount,
			&userData.SuspiciousEmptyCount,
			&userData.Contributions,
			&userData.IsSuspicious,
			&userData.ProcessedAt,
		)
	
	if err != nil {
		// If not in our database, try to get basic info from GitHub
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		// Get user creation date
		createdAt, err := githubClient.GetUserInfo(ctx, username)
		if err != nil {
			s.logger.Error("Error getting user info: %v", err)
			http.Error(w, "Error fetching user data", http.StatusInternalServerError)
			return
		}
		userData.CreatedAt = createdAt

		// Get user contributions
		contributions, err := githubClient.GetUserContributions(ctx, username)
		if err == nil {
			userData.Contributions = contributions
		}

		// Get user repositories
		repos, err := githubClient.GetUserRepositories(ctx, username)
		if err == nil {
			userData.RepoCount = len(repos)
			
			// Count repositories and stars
			emptyCount := 0
			totalStars := 0
			
			for _, repo := range repos {
				totalStars += repo.StargazerCount
				if repo.DiskUsage == 0 {
					emptyCount++
				}
			}
			
			userData.TotalStars = totalStars
			userData.EmptyCount = emptyCount
		}
	}

	// Get heuristic flags for this user
	rows, err := s.db.Query(`
		SELECT flag FROM heuristic_flags 
		WHERE entity_type = 'user' AND entity_id = ?`,
		username)
	
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var flag string
			if err := rows.Scan(&flag); err == nil {
				userData.HeuristicFlags = append(userData.HeuristicFlags, flag)
			}
		}
	}

	// Return the report data as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userData)
}