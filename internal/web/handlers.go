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

	repos, totalCount, err := s.getRepositories(page, limit)
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

	users, totalCount, err := s.getUsers(page, limit)
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

	flags, totalCount, err := s.getFlags(page, limit)
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