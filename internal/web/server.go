// Package web provides HTTP server functionality for displaying GitHub Watchdog data
package web

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/arkouda/github/GitHubWatchdog/internal/db"
	"github.com/arkouda/github/GitHubWatchdog/internal/logger"
)

// ServerConfig holds the configuration for the web server
type ServerConfig struct {
	GitHubToken string
}

// Server represents the HTTP server for the web interface
type Server struct {
	db      *db.Database
	logger  *logger.Logger
	server  *http.Server
	addr    string
	handler http.Handler
	config  ServerConfig
}

// NewServer creates a new web server instance
func NewServer(database *db.Database, addr string, logger *logger.Logger, githubToken string) *Server {
	s := &Server{
		db:     database,
		logger: logger,
		addr:   addr,
		config: ServerConfig{
			GitHubToken: githubToken,
		},
	}

	// Set up templates directory
	if err := ensureTemplateDirectory(); err != nil {
		logger.Error("Creating templates directory: %v", err)
	}

	// Create router with handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.indexHandler)
	mux.HandleFunc("/repositories", s.repositoriesHandler)
	mux.HandleFunc("/users", s.usersHandler)
	mux.HandleFunc("/flags", s.flagsHandler)
	mux.HandleFunc("/static/", s.staticHandler)
	mux.HandleFunc("/api/repository/status", s.updateRepositoryStatusHandler)
	mux.HandleFunc("/api/user/status", s.updateUserStatusHandler)
	mux.HandleFunc("/api/report/repository", s.repositoryReportHandler)
	mux.HandleFunc("/api/report/user", s.userReportHandler)

	s.handler = mux
	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// ensureTemplateDirectory makes sure template directory exists
func ensureTemplateDirectory() error {
	// Create static directory if it doesn't exist
	staticDir := "internal/web/static"
	if _, err := os.Stat(staticDir); os.IsNotExist(err) {
		if err := os.MkdirAll(staticDir, 0755); err != nil {
			return fmt.Errorf("creating static directory: %w", err)
		}
	}
	
	return nil
}

// Start begins the HTTP server
func (s *Server) Start() error {
	s.logger.Info("Starting web server on %s", s.addr)
	return s.server.ListenAndServe()
}

// Shutdown gracefully stops the HTTP server
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down web server")
	return s.server.Shutdown(ctx)
}