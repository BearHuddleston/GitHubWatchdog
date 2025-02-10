package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Database wraps a sql.DB connection.
type Database struct {
	*sql.DB
}

// NewDatabase opens (or creates) the SQLite database and creates necessary tables.
func NewDatabase(dbPath string) (*Database, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	database := &Database{db}
	if err := database.createTables(); err != nil {
		return nil, err
	}
	return database, nil
}

func (d *Database) createTables() error {
	// Table for processed repositories.
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
	if _, err := d.Exec(repoTable); err != nil {
		return fmt.Errorf("creating processed_repositories table: %w", err)
	}

	// Table for processed users.
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
	if _, err := d.Exec(userTable); err != nil {
		return fmt.Errorf("creating processed_users table: %w", err)
	}

	// Table for heuristic flags.
	flagTable := `
    CREATE TABLE IF NOT EXISTS heuristic_flags (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT,
        entity_id TEXT,
        flag TEXT,
        triggered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`
	if _, err := d.Exec(flagTable); err != nil {
		return fmt.Errorf("creating heuristic_flags table: %w", err)
	}
	return nil
}

// InsertProcessedRepo records a repository in the database.
func (d *Database) InsertProcessedRepo(repoID, owner, name string, updatedAt time.Time, diskUsage, stargazerCount int, isMalicious bool) error {
	query := `
    INSERT OR IGNORE INTO processed_repositories 
        (repo_id, owner, name, updated_at, disk_usage, stargazer_count, is_malicious)
    VALUES (?, ?, ?, ?, ?, ?, ?);`
	_, err := d.Exec(query, repoID, owner, name, updatedAt, diskUsage, stargazerCount, isMalicious)
	return err
}

// InsertProcessedUser records a user along with the overall suspicious analysis result.
func (d *Database) InsertProcessedUser(username string, createdAt time.Time, totalStars, emptyCount, suspiciousEmptyCount, contributions int, analysisResult bool) error {
	query := `
    INSERT OR IGNORE INTO processed_users 
        (username, created_at, total_stars, empty_count, suspicious_empty_count, contributions, analysis_result)
    VALUES (?, ?, ?, ?, ?, ?, ?);`
	_, err := d.Exec(query, username, createdAt, totalStars, emptyCount, suspiciousEmptyCount, contributions, analysisResult)
	return err
}

// InsertHeuristicFlag logs a heuristic flag event.
func (d *Database) InsertHeuristicFlag(entityType, entityID, flag string) error {
	query := `
    INSERT INTO heuristic_flags (entity_type, entity_id, flag)
    VALUES (?, ?, ?);`
	_, err := d.Exec(query, entityType, entityID, flag)
	return err
}

func (d *Database) GetProcessedUsers() (map[string]bool, error) {
	query := `SELECT username FROM processed_users;`
	rows, err := d.Query(query)
	if err != nil {
		return nil, fmt.Errorf("querying processed users: %w", err)
	}
	defer rows.Close()

	processed := make(map[string]bool)
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return nil, fmt.Errorf("scanning username: %w", err)
		}
		processed[username] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating processed users: %w", err)
	}
	return processed, nil
}
