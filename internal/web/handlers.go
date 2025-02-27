package web

import (
	"html/template"
	"net/http"
	"path/filepath"
	"strconv"
	"time"
)

// PageData holds common data for all pages
type PageData struct {
	Title       string
	LastUpdated time.Time
}

// RepositoryData represents a processed repository
type RepositoryData struct {
	ID            int
	RepoID        string
	Owner         string
	Name          string
	UpdatedAt     time.Time
	DiskUsage     int
	StargazerCount int
	IsMalicious   bool
	ProcessedAt   time.Time
}

// UserData represents a processed user
type UserData struct {
	ID                  int
	Username            string
	CreatedAt           time.Time
	TotalStars          int
	EmptyCount          int
	SuspiciousEmptyCount int
	Contributions       int
	AnalysisResult      bool
	ProcessedAt         time.Time
}

// FlagData represents a heuristic flag
type FlagData struct {
	ID          int
	EntityType  string
	EntityID    string
	Flag        string
	TriggeredAt time.Time
}

// indexHandler handles the main dashboard page
func (s *Server) indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Get repository stats
	repoCount, maliciousCount, err := s.getRepositoryStats()
	if err != nil {
		s.logger.Error("Error getting repository stats: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Get user stats
	userCount, suspiciousCount, err := s.getUserStats()
	if err != nil {
		s.logger.Error("Error getting user stats: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Get flag stats
	flagCount, err := s.getFlagCount()
	if err != nil {
		s.logger.Error("Error getting flag count: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		PageData
		RepoCount       int
		MaliciousCount  int
		UserCount       int
		SuspiciousCount int
		FlagCount       int
		SortBy          string
		SortOrder       string
	}{
		PageData: PageData{
			Title:       "GitHub Watchdog Dashboard",
			LastUpdated: time.Now(),
		},
		RepoCount:       repoCount,
		MaliciousCount:  maliciousCount,
		UserCount:       userCount,
		SuspiciousCount: suspiciousCount,
		FlagCount:       flagCount,
		SortBy:          "",
		SortOrder:       "",
	}

	tmpl, err := template.New("layout.html").Funcs(TemplateFuncs()).ParseFiles(
		filepath.Join("internal/web/templates", "layout.html"),
		filepath.Join("internal/web/templates", "index.html"),
	)
	if err != nil {
		s.logger.Error("Error parsing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		s.logger.Error("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// repositoriesHandler handles the repositories page
func (s *Server) repositoriesHandler(w http.ResponseWriter, r *http.Request) {
	page, limit := getPaginationParams(r)
	sortBy, sortOrder := getSortParams(r)

	repos, totalCount, err := s.getRepositories(page, limit, sortBy, sortOrder)
	if err != nil {
		s.logger.Error("Error getting repositories: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		PageData
		Repositories []RepositoryData
		Page         int
		Limit        int
		TotalCount   int
		TotalPages   int
		SortBy       string
		SortOrder    string
	}{
		PageData: PageData{
			Title:       "Repositories",
			LastUpdated: time.Now(),
		},
		Repositories: repos,
		Page:         page,
		Limit:        limit,
		TotalCount:   totalCount,
		TotalPages:   (totalCount + limit - 1) / limit,
		SortBy:       sortBy,
		SortOrder:    sortOrder,
	}

	tmpl, err := template.New("layout.html").Funcs(TemplateFuncs()).ParseFiles(
		filepath.Join("internal/web/templates", "layout.html"),
		filepath.Join("internal/web/templates", "repositories.html"),
	)
	if err != nil {
		s.logger.Error("Error parsing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		s.logger.Error("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// usersHandler handles the users page
func (s *Server) usersHandler(w http.ResponseWriter, r *http.Request) {
	page, limit := getPaginationParams(r)
	sortBy, sortOrder := getSortParams(r)

	users, totalCount, err := s.getUsers(page, limit, sortBy, sortOrder)
	if err != nil {
		s.logger.Error("Error getting users: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		PageData
		Users      []UserData
		Page       int
		Limit      int
		TotalCount int
		TotalPages int
		SortBy     string
		SortOrder  string
	}{
		PageData: PageData{
			Title:       "Users",
			LastUpdated: time.Now(),
		},
		Users:      users,
		Page:       page,
		Limit:      limit,
		TotalCount: totalCount,
		TotalPages: (totalCount + limit - 1) / limit,
		SortBy:     sortBy,
		SortOrder:  sortOrder,
	}

	tmpl, err := template.New("layout.html").Funcs(TemplateFuncs()).ParseFiles(
		filepath.Join("internal/web/templates", "layout.html"),
		filepath.Join("internal/web/templates", "users.html"),
	)
	if err != nil {
		s.logger.Error("Error parsing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		s.logger.Error("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// flagsHandler handles the flags page
func (s *Server) flagsHandler(w http.ResponseWriter, r *http.Request) {
	page, limit := getPaginationParams(r)
	sortBy, sortOrder := getSortParams(r)

	flags, totalCount, err := s.getFlags(page, limit, sortBy, sortOrder)
	if err != nil {
		s.logger.Error("Error getting flags: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := struct {
		PageData
		Flags      []FlagData
		Page       int
		Limit      int
		TotalCount int
		TotalPages int
		SortBy     string
		SortOrder  string
	}{
		PageData: PageData{
			Title:       "Heuristic Flags",
			LastUpdated: time.Now(),
		},
		Flags:      flags,
		Page:       page,
		Limit:      limit,
		TotalCount: totalCount,
		TotalPages: (totalCount + limit - 1) / limit,
		SortBy:     sortBy,
		SortOrder:  sortOrder,
	}

	tmpl, err := template.New("layout.html").Funcs(TemplateFuncs()).ParseFiles(
		filepath.Join("internal/web/templates", "layout.html"),
		filepath.Join("internal/web/templates", "flags.html"),
	)
	if err != nil {
		s.logger.Error("Error parsing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		s.logger.Error("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// staticHandler serves static files (CSS, JS, etc.)
func (s *Server) staticHandler(w http.ResponseWriter, r *http.Request) {
	http.StripPrefix("/static/", http.FileServer(http.Dir("internal/web/static"))).ServeHTTP(w, r)
}

// getPaginationParams extracts pagination parameters from the request
func getPaginationParams(r *http.Request) (int, int) {
	// Default values
	page := 1
	limit := 100

	// Parse query parameters
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if parsedPage, err := strconv.Atoi(pageStr); err == nil && parsedPage > 0 {
			page = parsedPage
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 1000 {
			limit = parsedLimit
		}
	}

	return page, limit
}

// getSortParams extracts sorting parameters from the request
func getSortParams(r *http.Request) (string, string) {
	// Default values
	sortBy := ""
	sortOrder := "DESC"
	
	// Parse query parameters
	if sort := r.URL.Query().Get("sort"); sort != "" {
		sortBy = sort
	}
	
	if order := r.URL.Query().Get("order"); order != "" {
		if order == "asc" || order == "ASC" {
			sortOrder = "ASC"
		} else if order == "desc" || order == "DESC" {
			sortOrder = "DESC"
		}
	}
	
	return sortBy, sortOrder
}

// updateRepositoryStatusHandler handles repository status updates via API
func (s *Server) updateRepositoryStatusHandler(w http.ResponseWriter, r *http.Request) {
	// Only allow POST method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// Parse form data
	if err := r.ParseForm(); err != nil {
		s.logger.Error("Error parsing form: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	
	// Get parameters
	repoIDStr := r.FormValue("repo_id")
	statusStr := r.FormValue("status")
	
	// Validate parameters
	if repoIDStr == "" || statusStr == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}
	
	// Parse repository ID
	repoID, err := strconv.Atoi(repoIDStr)
	if err != nil {
		s.logger.Error("Invalid repo ID: %v", err)
		http.Error(w, "Invalid repository ID", http.StatusBadRequest)
		return
	}
	
	// Validate status value
	isMalicious := false
	if statusStr == "malicious" {
		isMalicious = true
	} else if statusStr != "clean" {
		http.Error(w, "Invalid status value", http.StatusBadRequest)
		return
	}
	
	// Update repository status in database
	_, err = s.db.Exec("UPDATE processed_repositories SET is_malicious = ? WHERE id = ?", isMalicious, repoID)
	if err != nil {
		s.logger.Error("Error updating repository status: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	// Redirect back to repositories page
	redirectURL := "/repositories"
	if referer := r.Header.Get("Referer"); referer != "" {
		redirectURL = referer
	}
	
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// updateUserStatusHandler handles user status updates via API
func (s *Server) updateUserStatusHandler(w http.ResponseWriter, r *http.Request) {
	// Only allow POST method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	
	// Parse form data
	if err := r.ParseForm(); err != nil {
		s.logger.Error("Error parsing form: %v", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	
	// Get parameters
	userIDStr := r.FormValue("user_id")
	statusStr := r.FormValue("status")
	
	// Validate parameters
	if userIDStr == "" || statusStr == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}
	
	// Parse user ID
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		s.logger.Error("Invalid user ID: %v", err)
		http.Error(w, "Invalid user ID", http.StatusBadRequest)
		return
	}
	
	// Validate status value
	analysisResult := false
	if statusStr == "suspicious" {
		analysisResult = true
	} else if statusStr != "clean" {
		http.Error(w, "Invalid status value", http.StatusBadRequest)
		return
	}
	
	// Update user status in database
	_, err = s.db.Exec("UPDATE processed_users SET analysis_result = ? WHERE id = ?", analysisResult, userID)
	if err != nil {
		s.logger.Error("Error updating user status: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	// Redirect back to users page
	redirectURL := "/users"
	if referer := r.Header.Get("Referer"); referer != "" {
		redirectURL = referer
	}
	
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}