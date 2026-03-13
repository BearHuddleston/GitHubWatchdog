// Package web provides HTTP server functionality for displaying GitHub Watchdog data
package web

import (
	"context"
	"io/fs"
	"net/http"
	"time"

	"github.com/arkouda/github/GitHubWatchdog/internal/db"
	"github.com/arkouda/github/GitHubWatchdog/internal/logger"
)

// ServerConfig holds the configuration for the web server
type ServerConfig struct {
	GitHubToken    string
	OllamaEnabled  bool
	OllamaEndpoint string
	OllamaModel    string
}

// Server represents the HTTP server for the web interface
type Server struct {
	db             *db.Database
	logger         *logger.Logger
	server         *http.Server
	addr           string
	handler        http.Handler
	config         ServerConfig
	ollamaEnabled  bool
	ollamaEndpoint string
	ollamaModel    string
}

// NewServer creates a new web server instance
func NewServer(database *db.Database, addr string, logger *logger.Logger, conf *ServerConfig) *Server {
	s := &Server{
		db:             database,
		logger:         logger,
		addr:           addr,
		config:         *conf,
		ollamaEnabled:  conf.OllamaEnabled,
		ollamaEndpoint: conf.OllamaEndpoint,
		ollamaModel:    conf.OllamaModel,
	}

	// Create router with handlers
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.indexHandler)
	mux.HandleFunc("/repositories", s.repositoriesHandler)
	mux.HandleFunc("/users", s.usersHandler)
	mux.HandleFunc("/flags", s.flagsHandler)
	staticFS, err := fs.Sub(embeddedAssets, "static")
	if err != nil {
		logger.Fatal("Loading embedded static assets: %v", err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	mux.HandleFunc("/api/repository/status", s.localWriteOnly(s.updateRepositoryStatusHandler))
	mux.HandleFunc("/api/user/status", s.localWriteOnly(s.updateUserStatusHandler))
	mux.HandleFunc("/api/report/repository", s.repositoryReportHandler)
	mux.HandleFunc("/api/report/user", s.userReportHandler)
	mux.HandleFunc("/api/analysis/generate", s.localWriteOnly(s.generateOllamaAnalysisHandler))

	s.handler = mux
	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 6 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}

	return s
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
