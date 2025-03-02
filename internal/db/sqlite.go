// Package db provides database operations for the application
package db

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3" // required SQLite driver
)

// Database wraps an sql.DB and prepared statements.
type Database struct {
	db                *sql.DB
	insertRepoStmt    *sql.Stmt
	insertUserStmt    *sql.Stmt
	insertFlagStmt    *sql.Stmt
	insertOllamaStmt  *sql.Stmt
}

// QueryRow executes a query that is expected to return at most one row.
// QueryRow always returns a non-nil value. Errors are deferred until
// Row's Scan method is called.
func (d *Database) QueryRow(query string, args ...interface{}) *sql.Row {
	return d.db.QueryRow(query, args...)
}

// Query executes a query that returns rows, typically a SELECT.
func (d *Database) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return d.db.Query(query, args...)
}

// Exec executes a query without returning any rows.
// The args are for any placeholder parameters in the query.
func (d *Database) Exec(query string, args ...interface{}) (sql.Result, error) {
	return d.db.Exec(query, args...)
}

// New creates a new database connection and initializes tables
func New(dbPath string) (*Database, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(0)

	database := &Database{db: db}
	if err := database.createTables(); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating tables: %w", err)
	}
	if err := database.prepareStatements(); err != nil {
		db.Close()
		return nil, fmt.Errorf("preparing statements: %w", err)
	}
	return database, nil
}

// Close closes all database resources
func (d *Database) Close() error {
	var closeErr error
	if d.insertRepoStmt != nil {
		if err := d.insertRepoStmt.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("closing insertRepoStmt: %w", err))
		}
	}
	if d.insertUserStmt != nil {
		if err := d.insertUserStmt.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("closing insertUserStmt: %w", err))
		}
	}
	if d.insertFlagStmt != nil {
		if err := d.insertFlagStmt.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("closing insertFlagStmt: %w", err))
		}
	}
	if d.insertOllamaStmt != nil {
		if err := d.insertOllamaStmt.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("closing insertOllamaStmt: %w", err))
		}
	}
	if d.db != nil {
		if err := d.db.Close(); err != nil {
			closeErr = errors.Join(closeErr, fmt.Errorf("closing database: %w", err))
		}
	}
	return closeErr
}

func (d *Database) createTables() error {
	repoTable := `
	CREATE TABLE IF NOT EXISTS processed_repositories (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		repo_id TEXT UNIQUE,
		owner TEXT,
		name TEXT,
		updated_at TIMESTAMP,
		disk_usage INTEGER,
		stargazer_count INTEGER,
		is_malicious BOOLEAN,
		processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := d.db.Exec(repoTable); err != nil {
		return fmt.Errorf("creating processed_repositories table: %w", err)
	}
	userTable := `
	CREATE TABLE IF NOT EXISTS processed_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE,
		created_at TIMESTAMP,
		total_stars INTEGER,
		empty_count INTEGER,
		suspicious_empty_count INTEGER,
		contributions INTEGER,
		analysis_result BOOLEAN,
		processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := d.db.Exec(userTable); err != nil {
		return fmt.Errorf("creating processed_users table: %w", err)
	}
	flagTable := `
	CREATE TABLE IF NOT EXISTS heuristic_flags (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		entity_type TEXT,
		entity_id TEXT,
		flag TEXT,
		triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := d.db.Exec(flagTable); err != nil {
		return fmt.Errorf("creating heuristic_flags table: %w", err)
	}
	ollamaTable := `
	CREATE TABLE IF NOT EXISTS ollama_analyses (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		entity_type TEXT,
		entity_id TEXT,
		context TEXT,
		analysis TEXT,
		model TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(entity_type, entity_id, model)
	);`
	if _, err := d.db.Exec(ollamaTable); err != nil {
		return fmt.Errorf("creating ollama_analyses table: %w", err)
	}
	return nil
}

func (d *Database) prepareStatements() error {
	var err error
	d.insertRepoStmt, err = d.db.Prepare(`
		INSERT OR IGNORE INTO processed_repositories 
			(repo_id, owner, name, updated_at, disk_usage, stargazer_count, is_malicious)
		VALUES (?, ?, ?, ?, ?, ?, ?);
	`)
	if err != nil {
		return fmt.Errorf("preparing insertRepoStmt: %w", err)
	}
	d.insertUserStmt, err = d.db.Prepare(`
		INSERT OR IGNORE INTO processed_users 
			(username, created_at, total_stars, empty_count, suspicious_empty_count, contributions, analysis_result)
		VALUES (?, ?, ?, ?, ?, ?, ?);
	`)
	if err != nil {
		return fmt.Errorf("preparing insertUserStmt: %w", err)
	}
	d.insertFlagStmt, err = d.db.Prepare(`
		INSERT INTO heuristic_flags (entity_type, entity_id, flag)
		VALUES (?, ?, ?);
	`)
	if err != nil {
		return fmt.Errorf("preparing insertFlagStmt: %w", err)
	}
	d.insertOllamaStmt, err = d.db.Prepare(`
		INSERT OR REPLACE INTO ollama_analyses (entity_type, entity_id, context, analysis, model)
		VALUES (?, ?, ?, ?, ?);
	`)
	if err != nil {
		return fmt.Errorf("preparing insertOllamaStmt: %w", err)
	}
	return nil
}

// InsertProcessedRepo inserts a processed repository record
func (d *Database) InsertProcessedRepo(repoID, owner, name string, updatedAt time.Time, diskUsage, stargazerCount int, isMalicious bool) error {
	_, err := d.insertRepoStmt.Exec(repoID, owner, name, updatedAt, diskUsage, stargazerCount, isMalicious)
	if err != nil {
		return fmt.Errorf("inserting processed repository: %w", err)
	}
	return nil
}

// InsertProcessedUser inserts a processed user record
func (d *Database) InsertProcessedUser(username string, createdAt time.Time, totalStars, emptyCount, suspiciousEmptyCount, contributions int, analysisResult bool) error {
	_, err := d.insertUserStmt.Exec(username, createdAt, totalStars, emptyCount, suspiciousEmptyCount, contributions, analysisResult)
	if err != nil {
		return fmt.Errorf("inserting processed user: %w", err)
	}
	return nil
}

// InsertHeuristicFlag inserts a heuristic flag record
func (d *Database) InsertHeuristicFlag(entityType, entityID, flag string) error {
	_, err := d.insertFlagStmt.Exec(entityType, entityID, flag)
	if err != nil {
		return fmt.Errorf("inserting heuristic flag: %w", err)
	}
	return nil
}

// GetProcessedUsers returns a list of all processed usernames
func (d *Database) GetProcessedUsers() ([]string, error) {
	rows, err := d.db.Query(`SELECT username FROM processed_users;`)
	if err != nil {
		return nil, fmt.Errorf("querying processed users: %w", err)
	}
	defer rows.Close()
	var processed []string
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return nil, fmt.Errorf("scanning username: %w", err)
		}
		processed = append(processed, username)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating processed users: %w", err)
	}
	return processed, nil
}

// WasRepoProcessed checks if a repository has already been processed
func (d *Database) WasRepoProcessed(repoID string, updatedAt time.Time) (bool, error) {
	var storedUpdatedAt time.Time
	err := d.db.QueryRow("SELECT updated_at FROM processed_repositories WHERE repo_id = ?", repoID).Scan(&storedUpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("querying processed repository: %w", err)
	}
	return !updatedAt.After(storedUpdatedAt), nil
}

// InsertOllamaAnalysis stores an Ollama analysis for an entity
func (d *Database) InsertOllamaAnalysis(entityType, entityID, context, analysis, model string) error {
	_, err := d.insertOllamaStmt.Exec(entityType, entityID, context, analysis, model)
	if err != nil {
		return fmt.Errorf("inserting ollama analysis: %w", err)
	}
	return nil
}

// GetOllamaAnalysis retrieves an Ollama analysis for an entity if it exists
func (d *Database) GetOllamaAnalysis(entityType, entityID, model string) (string, error) {
	var analysis string
	err := d.db.QueryRow(
		"SELECT analysis FROM ollama_analyses WHERE entity_type = ? AND entity_id = ? AND model = ?",
		entityType, entityID, model,
	).Scan(&analysis)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("querying ollama analysis: %w", err)
	}
	return analysis, nil
}