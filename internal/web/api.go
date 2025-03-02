package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/arkouda/github/GitHubWatchdog/internal/github"
	"github.com/arkouda/github/GitHubWatchdog/internal/ollama"
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
	OllamaAnalysis string    `json:"ollama_analysis,omitempty"`
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
	OllamaAnalysis       string    `json:"ollama_analysis,omitempty"`
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

	// Check if Ollama analysis is available in the database
	if s.ollamaEnabled {
		analysis, err := s.db.GetOllamaAnalysis("repo", fmt.Sprintf("%s/%s", owner, repo), s.ollamaModel)
		if err == nil && analysis != "" {
			repoData.OllamaAnalysis = analysis
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

	// Check if Ollama analysis is available in the database
	if s.ollamaEnabled {
		analysis, err := s.db.GetOllamaAnalysis("user", username, s.ollamaModel)
		if err == nil && analysis != "" {
			userData.OllamaAnalysis = analysis
		}
	}

	// Return the report data as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userData)
}

// GenerateAnalysisRequest represents a request to generate an analysis for a repository or user
type GenerateAnalysisRequest struct {
	EntityType string `json:"entity_type"` // "repo" or "user"
	EntityID   string `json:"entity_id"`   // "<owner>/<repo>" or "<username>"
}

// GenerateAnalysisResponse represents the response from the generate analysis API
type GenerateAnalysisResponse struct {
	Analysis string `json:"analysis"`
}

// generateOllamaAnalysisHandler handles requests to generate Ollama analyses
func (s *Server) generateOllamaAnalysisHandler(w http.ResponseWriter, r *http.Request) {
	// Only accept POST requests
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Only proceed if Ollama is enabled
	if !s.ollamaEnabled {
		http.Error(w, "Ollama analysis is not enabled", http.StatusBadRequest)
		return
	}

	// Parse the request
	var req GenerateAnalysisRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate the request
	if req.EntityType != "repo" && req.EntityType != "user" {
		http.Error(w, "Entity type must be 'repo' or 'user'", http.StatusBadRequest)
		return
	}
	if req.EntityID == "" {
		http.Error(w, "Entity ID is required", http.StatusBadRequest)
		return
	}

	// Check if analysis already exists in database
	existingAnalysis, err := s.db.GetOllamaAnalysis(req.EntityType, req.EntityID, s.ollamaModel)
	if err == nil && existingAnalysis != "" {
		// Return the existing analysis
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(GenerateAnalysisResponse{Analysis: existingAnalysis})
		return
	}

	// We need to generate a new analysis
	var contextContent string

	if req.EntityType == "repo" {
		// Split the entity ID into owner and repo name
		parts := strings.Split(req.EntityID, "/")
		if len(parts) != 2 {
			http.Error(w, "Invalid repository format, expected 'owner/repo'", http.StatusBadRequest)
			return
		}
		owner, repo := parts[0], parts[1]

		// Generate context for repository
		contextContent, err = s.generateRepositoryContext(r.Context(), owner, repo)
		if err != nil {
			s.logger.Error("Error generating repository context: %v", err)
			http.Error(w, "Error generating context", http.StatusInternalServerError)
			return
		}
	} else {
		// Generate context for user
		contextContent, err = s.generateUserContext(r.Context(), req.EntityID)
		if err != nil {
			s.logger.Error("Error generating user context: %v", err)
			http.Error(w, "Error generating context", http.StatusInternalServerError)
			return
		}
	}

	// Log context info for debugging
	s.logger.Info("Generated context for %s/%s (%d characters)", req.EntityType, req.EntityID, len(contextContent))
	if len(contextContent) < 100 {
		s.logger.Error("Context is too short, might cause poor analysis: %s", contextContent)
	}
	
	// Create Ollama client and send request
	ollamaClient := ollama.NewClient(s.ollamaEndpoint)
	
	// Set a longer timeout for generation
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	
	// Generate the analysis
	s.logger.Info("Sending analysis request to Ollama at %s using model %s", s.ollamaEndpoint, s.ollamaModel)
	analysis, err := ollamaClient.Generate(ctx, s.ollamaModel, contextContent)
	if err != nil {
		s.logger.Error("Error generating Ollama analysis: %v", err)
		
		// Create a fallback response explaining the error
		failureAnalysis := fmt.Sprintf(`# Analysis Error

## Error Details
* Failed to generate analysis using Ollama
* Error: %v

## Troubleshooting
* Verify Ollama is running at: %s
* Confirm the model "%s" is available
* Check if context size (%d characters) is within limits
* See logs for detailed error information

## Next Steps
* Try again later
* Check server logs for more details`, 
			err, s.ollamaEndpoint, s.ollamaModel, len(contextContent))
		
		// Return the error analysis
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(GenerateAnalysisResponse{Analysis: failureAnalysis})
		return
	}
	
	// Check if we got a valid response
	if len(analysis) < 20 {
		s.logger.Error("Ollama generated a suspiciously short response: %s", analysis)
	} else {
		s.logger.Info("Successfully generated analysis of %d characters", len(analysis))
	}

	// Store the analysis in the database
	if err := s.db.InsertOllamaAnalysis(req.EntityType, req.EntityID, contextContent, analysis, s.ollamaModel); err != nil {
		s.logger.Error("Error storing Ollama analysis: %v", err)
		// Continue anyway, we can still return the analysis
	} else {
		s.logger.Info("Successfully stored analysis in database")
	}

	// Return the analysis
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(GenerateAnalysisResponse{Analysis: analysis})
}

// generateRepositoryContext generates context for repository analysis
func (s *Server) generateRepositoryContext(ctx context.Context, owner, repo string) (string, error) {
	githubClient := github.NewClient(s.config.GitHubToken, 5, 60, true)
	
	// Create a structured prompt for the AI
	var sb strings.Builder
	
	// Start with clear instructions
	sb.WriteString(`# Security Analysis Request

## Analysis Instructions
You are a cybersecurity threat analyst examining a GitHub repository for potential security threats.
Please analyze the following information and provide a comprehensive security assessment.
Format your response in markdown with clear sections for Observations, Risk Analysis, and Recommendations.

`)

	// Basic repository information
	sb.WriteString(fmt.Sprintf("## Repository Information\n"))
	sb.WriteString(fmt.Sprintf("- **Repository:** %s/%s\n", owner, repo))
	
	// Try to get full repository details from GitHub API
	searchResult, err := githubClient.SearchRepositories(ctx, fmt.Sprintf("repo:%s/%s", owner, repo), 1, 1)
	if err == nil && len(searchResult.Items) > 0 {
		item := searchResult.Items[0]
		sb.WriteString(fmt.Sprintf("- **Last Updated:** %s\n", item.UpdatedAt.Format("2006-01-02")))
		sb.WriteString(fmt.Sprintf("- **Size:** %d KB\n", item.Size))
		sb.WriteString(fmt.Sprintf("- **Stars:** %d\n", item.StargazersCount))
		sb.WriteString(fmt.Sprintf("- **Default Branch:** %s\n", item.DefaultBranch))
		sb.WriteString(fmt.Sprintf("- **Full Name:** %s\n", item.FullName))
	}
	sb.WriteString("\n")

	// Get repository database record for additional information
	var isMalicious bool
	var processedAt time.Time
	err = s.db.QueryRow(`
		SELECT is_malicious, processed_at 
		FROM processed_repositories 
		WHERE owner = ? AND name = ?`, 
		owner, repo).Scan(&isMalicious, &processedAt)
	
	if err == nil {
		sb.WriteString("## Database Information\n")
		sb.WriteString(fmt.Sprintf("- **Currently Flagged:** %v\n", isMalicious))
		sb.WriteString(fmt.Sprintf("- **Last Processed:** %s\n\n", processedAt.Format("2006-01-02 15:04:05")))
	}

	// Get README content
	readme, err := githubClient.GetRepoReadme(ctx, owner, repo)
	if err == nil && readme != "" {
		sb.WriteString("## README Content\n```markdown\n")
		// Limit README to a reasonable size
		if len(readme) > 4000 {
			sb.WriteString(readme[:4000] + "...(truncated)")
		} else {
			sb.WriteString(readme)
		}
		sb.WriteString("\n```\n\n")
	} else {
		sb.WriteString("## README Content\n- No README found or unable to retrieve\n\n")
	}

	// Get file list with structure
	files, err := githubClient.GetRepoTree(ctx, owner, repo, "")
	if err == nil && len(files) > 0 {
		sb.WriteString("## Repository Structure\n")
		sb.WriteString("The repository contains the following files:\n```\n")
		for i, file := range files {
			if i < 100 { // Limit to 100 files to avoid context overflow
				sb.WriteString(file + "\n")
			} else {
				sb.WriteString("...(more files omitted)\n")
				break
			}
		}
		sb.WriteString("```\n\n")
	} else {
		sb.WriteString("## Repository Structure\n- Unable to retrieve file structure\n\n")
	}

	// Get heuristic flags if any
	rows, err := s.db.Query(`
		SELECT flag FROM heuristic_flags 
		WHERE entity_type = 'repo' AND entity_id = ?`,
		fmt.Sprintf("%s/%s", owner, repo))
	
	if err == nil {
		defer rows.Close()
		var flags []string
		for rows.Next() {
			var flag string
			if err := rows.Scan(&flag); err == nil {
				flags = append(flags, flag)
			}
		}
		
		if len(flags) > 0 {
			sb.WriteString("## Detected Security Flags\n")
			for _, flag := range flags {
				sb.WriteString("- " + flag + "\n")
			}
			sb.WriteString("\n")
		} else {
			sb.WriteString("## Detected Security Flags\n- No security flags currently detected\n\n")
		}
	}
	
	// Add an explicit request for analysis at the end
	sb.WriteString(`## Analysis Request
Based on the information above, please provide:

1. **Observations**: Notable patterns, unusual elements, or security-relevant features
2. **Risk Analysis**: Assessment of malicious intent or security risks, rated as High/Medium/Low with explanation
3. **Recommendations**: Security recommendations for users encountering this repository

Format the output using markdown, with appropriate headers and bullet points for clarity.
`)

	return sb.String(), nil
}

// generateUserContext generates context for user analysis
func (s *Server) generateUserContext(ctx context.Context, username string) (string, error) {
	githubClient := github.NewClient(s.config.GitHubToken, 5, 60, true)
	
	// Create a structured prompt for the AI
	var sb strings.Builder
	
	// Start with clear instructions
	sb.WriteString(`# Security Analysis Request

## Analysis Instructions
You are a cybersecurity threat analyst examining a GitHub user for potential security threats or suspicious activity.
Please analyze the following information and provide a comprehensive account security assessment.
Format your response in markdown with clear sections for Observations, Risk Analysis, and Recommendations.

`)
	
	// Basic user information
	sb.WriteString(fmt.Sprintf("## User Information\n"))
	sb.WriteString(fmt.Sprintf("- **Username:** %s\n", username))

	// Get user creation date and additional info
	createdAt, err := githubClient.GetUserInfo(ctx, username)
	if err == nil {
		sb.WriteString(fmt.Sprintf("- **Account Created:** %s\n", createdAt.Format("2006-01-02")))
		
		// Calculate account age
		accountAge := time.Since(createdAt)
		accountAgeDays := int(accountAge.Hours() / 24)
		sb.WriteString(fmt.Sprintf("- **Account Age:** %d days\n", accountAgeDays))
	} else {
		sb.WriteString("- Unable to retrieve account creation date\n")
	}

	// Get user contributions
	contributions, err := githubClient.GetUserContributions(ctx, username)
	if err == nil {
		sb.WriteString(fmt.Sprintf("- **Total Contributions:** %d\n", contributions))
	} else {
		sb.WriteString("- Unable to retrieve contribution data\n")
	}
	sb.WriteString("\n")

	// Get user database record for additional information
	var isSuspicious bool
	var processedAt time.Time
	err = s.db.QueryRow(`
		SELECT analysis_result, processed_at 
		FROM processed_users 
		WHERE username = ?`, 
		username).Scan(&isSuspicious, &processedAt)
	
	if err == nil {
		sb.WriteString("## Database Information\n")
		sb.WriteString(fmt.Sprintf("- **Currently Flagged as Suspicious:** %v\n", isSuspicious))
		sb.WriteString(fmt.Sprintf("- **Last Processed:** %s\n\n", processedAt.Format("2006-01-02 15:04:05")))
	}

	// Get repository information
	repos, err := githubClient.GetUserRepositories(ctx, username)
	if err == nil {
		// Repository statistics
		emptyCount := 0
		lowContentCount := 0
		totalStars := 0
		hasPopularRepos := false
		highStarEmptyRepos := 0
		
		for _, repo := range repos {
			totalStars += repo.StargazerCount
			
			if repo.DiskUsage == 0 {
				emptyCount++
				if repo.StargazerCount > 5 {
					highStarEmptyRepos++
				}
			} else if repo.DiskUsage < 100 { // Less than 100KB
				lowContentCount++
			}
			
			if repo.StargazerCount > 50 {
				hasPopularRepos = true
			}
		}
		
		// Repository summary
		sb.WriteString("## Repository Summary\n")
		sb.WriteString(fmt.Sprintf("- **Total Repositories:** %d\n", len(repos)))
		sb.WriteString(fmt.Sprintf("- **Total Stars:** %d\n", totalStars))
		sb.WriteString(fmt.Sprintf("- **Empty Repositories:** %d\n", emptyCount))
		sb.WriteString(fmt.Sprintf("- **Low-content Repositories:** %d\n", lowContentCount))
		sb.WriteString(fmt.Sprintf("- **Popular Repositories:** %v\n", hasPopularRepos))
		sb.WriteString(fmt.Sprintf("- **Empty Repos with Stars:** %d\n", highStarEmptyRepos))
		
		// Average stars per repo
		if len(repos) > 0 {
			sb.WriteString(fmt.Sprintf("- **Average Stars per Repo:** %.2f\n", float64(totalStars)/float64(len(repos))))
		}
		sb.WriteString("\n")
		
		// List repositories (limited to 50 for context size)
		sb.WriteString("## Repository List\n")
		sb.WriteString("```\n")
		for i, repo := range repos {
			if i < 50 {
				sb.WriteString(fmt.Sprintf("- %s (Stars: %d, Size: %d KB)\n", 
					repo.Name, repo.StargazerCount, repo.DiskUsage))
			} else {
				sb.WriteString("...(more repositories omitted)\n")
				break
			}
		}
		sb.WriteString("```\n\n")
	} else {
		sb.WriteString("## Repository Information\n- Unable to retrieve repository data\n\n")
	}

	// Get heuristic flags if any
	rows, err := s.db.Query(`
		SELECT flag FROM heuristic_flags 
		WHERE entity_type = 'user' AND entity_id = ?`,
		username)
	
	if err == nil {
		defer rows.Close()
		var flags []string
		for rows.Next() {
			var flag string
			if err := rows.Scan(&flag); err == nil {
				flags = append(flags, flag)
			}
		}
		
		if len(flags) > 0 {
			sb.WriteString("## Detected Security Flags\n")
			for _, flag := range flags {
				sb.WriteString("- " + flag + "\n")
			}
			sb.WriteString("\n")
		} else {
			sb.WriteString("## Detected Security Flags\n- No security flags currently detected\n\n")
		}
	}

	// Add an explicit request for analysis at the end
	sb.WriteString(`## Analysis Request
Based on the information above, please provide:

1. **Observations**: Notable patterns or unusual account characteristics
2. **Risk Analysis**: Assessment of suspicious activity or security concerns, rated as High/Medium/Low with explanation
3. **Recommendations**: Security recommendations for users interacting with this account

Format the output using markdown, with appropriate headers and bullet points for clarity.
`)

	return sb.String(), nil
}