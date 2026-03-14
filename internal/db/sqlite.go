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
	db             *sql.DB
	insertRepoStmt *sql.Stmt
	insertUserStmt *sql.Stmt
	insertFlagStmt *sql.Stmt
}

// SearchCheckpoint stores resume information for named CLI scans.
type SearchCheckpoint struct {
	Name              string    `json:"name"`
	ProfileName       string    `json:"profile_name,omitempty"`
	Activity          string    `json:"activity,omitempty"`
	BaseQuery         string    `json:"base_query,omitempty"`
	EffectiveQuery    string    `json:"effective_query,omitempty"`
	QueriesJSON       string    `json:"queries_json,omitempty"`
	Since             string    `json:"since,omitempty"`
	CreatedSince      string    `json:"created_since,omitempty"`
	CreatedBefore     string    `json:"created_before,omitempty"`
	UpdatedSince      string    `json:"updated_since,omitempty"`
	UpdatedBefore     string    `json:"updated_before,omitempty"`
	NextCreatedBefore string    `json:"next_created_before,omitempty"`
	NextUpdatedBefore string    `json:"next_updated_before,omitempty"`
	OldestCreatedAt   time.Time `json:"oldest_created_at,omitempty"`
	OldestUpdatedAt   time.Time `json:"oldest_updated_at,omitempty"`
	CompletedAt       time.Time `json:"completed_at,omitempty"`
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
	if err := database.migrateTables(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating tables: %w", err)
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
	checkpointTable := `
	CREATE TABLE IF NOT EXISTS search_checkpoints (
		name TEXT PRIMARY KEY,
		profile_name TEXT,
		activity TEXT,
		base_query TEXT,
		effective_query TEXT,
		queries_json TEXT,
		since TEXT,
		created_since TEXT,
		created_before TEXT,
		updated_since TEXT,
		updated_before TEXT,
		next_created_before TEXT,
		next_updated_before TEXT,
		oldest_created_at TIMESTAMP,
		oldest_updated_at TIMESTAMP,
		completed_at TIMESTAMP
	);`
	if _, err := d.db.Exec(checkpointTable); err != nil {
		return fmt.Errorf("creating search_checkpoints table: %w", err)
	}
	return nil
}

func (d *Database) migrateTables() error {
	columns, err := d.tableColumns("search_checkpoints")
	if err != nil {
		return err
	}
	required := map[string]string{
		"activity":            "ALTER TABLE search_checkpoints ADD COLUMN activity TEXT;",
		"queries_json":        "ALTER TABLE search_checkpoints ADD COLUMN queries_json TEXT;",
		"created_since":       "ALTER TABLE search_checkpoints ADD COLUMN created_since TEXT;",
		"created_before":      "ALTER TABLE search_checkpoints ADD COLUMN created_before TEXT;",
		"updated_since":       "ALTER TABLE search_checkpoints ADD COLUMN updated_since TEXT;",
		"next_created_before": "ALTER TABLE search_checkpoints ADD COLUMN next_created_before TEXT;",
		"oldest_created_at":   "ALTER TABLE search_checkpoints ADD COLUMN oldest_created_at TIMESTAMP;",
	}
	for name, stmt := range required {
		if columns[name] {
			continue
		}
		if _, err := d.db.Exec(stmt); err != nil {
			return fmt.Errorf("adding %s to search_checkpoints: %w", name, err)
		}
	}
	return nil
}

func (d *Database) tableColumns(table string) (map[string]bool, error) {
	rows, err := d.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return nil, fmt.Errorf("querying table info for %s: %w", table, err)
	}
	defer rows.Close()

	columns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull, pk int
		var defaultValue interface{}
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return nil, fmt.Errorf("scanning table info for %s: %w", table, err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating table info for %s: %w", table, err)
	}
	return columns, nil
}

func (d *Database) prepareStatements() error {
	var err error
	d.insertRepoStmt, err = d.db.Prepare(`
		INSERT INTO processed_repositories 
			(repo_id, owner, name, updated_at, disk_usage, stargazer_count, is_malicious)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(repo_id) DO UPDATE SET
			owner = excluded.owner,
			name = excluded.name,
			updated_at = excluded.updated_at,
			disk_usage = excluded.disk_usage,
			stargazer_count = excluded.stargazer_count,
			is_malicious = excluded.is_malicious,
			processed_at = CURRENT_TIMESTAMP;
	`)
	if err != nil {
		return fmt.Errorf("preparing insertRepoStmt: %w", err)
	}
	d.insertUserStmt, err = d.db.Prepare(`
		INSERT INTO processed_users 
			(username, created_at, total_stars, empty_count, suspicious_empty_count, contributions, analysis_result)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			created_at = excluded.created_at,
			total_stars = excluded.total_stars,
			empty_count = excluded.empty_count,
			suspicious_empty_count = excluded.suspicious_empty_count,
			contributions = excluded.contributions,
			analysis_result = excluded.analysis_result,
			processed_at = CURRENT_TIMESTAMP;
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

// UpsertSearchCheckpoint stores or updates a named search checkpoint.
func (d *Database) UpsertSearchCheckpoint(checkpoint SearchCheckpoint) error {
	_, err := d.db.Exec(`
		INSERT INTO search_checkpoints
			(name, profile_name, activity, base_query, effective_query, queries_json, since, created_since, created_before, updated_since, updated_before, next_created_before, next_updated_before, oldest_created_at, oldest_updated_at, completed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			profile_name = excluded.profile_name,
			activity = excluded.activity,
			base_query = excluded.base_query,
			effective_query = excluded.effective_query,
			queries_json = excluded.queries_json,
			since = excluded.since,
			created_since = excluded.created_since,
			created_before = excluded.created_before,
			updated_since = excluded.updated_since,
			updated_before = excluded.updated_before,
			next_created_before = excluded.next_created_before,
			next_updated_before = excluded.next_updated_before,
			oldest_created_at = excluded.oldest_created_at,
			oldest_updated_at = excluded.oldest_updated_at,
			completed_at = excluded.completed_at;
	`,
		checkpoint.Name,
		checkpoint.ProfileName,
		checkpoint.Activity,
		checkpoint.BaseQuery,
		checkpoint.EffectiveQuery,
		checkpoint.QueriesJSON,
		checkpoint.Since,
		checkpoint.CreatedSince,
		checkpoint.CreatedBefore,
		checkpoint.UpdatedSince,
		checkpoint.UpdatedBefore,
		checkpoint.NextCreatedBefore,
		checkpoint.NextUpdatedBefore,
		checkpoint.OldestCreatedAt,
		checkpoint.OldestUpdatedAt,
		checkpoint.CompletedAt,
	)
	if err != nil {
		return fmt.Errorf("upserting search checkpoint: %w", err)
	}
	return nil
}

// GetSearchCheckpoint retrieves a named search checkpoint.
func (d *Database) GetSearchCheckpoint(name string) (SearchCheckpoint, error) {
	var checkpoint SearchCheckpoint
	err := d.db.QueryRow(`
		SELECT name, profile_name, activity, base_query, effective_query, queries_json, since, created_since, created_before, updated_since, updated_before, next_created_before, next_updated_before, oldest_created_at, oldest_updated_at, completed_at
		FROM search_checkpoints
		WHERE name = ?`,
		name,
	).Scan(
		&checkpoint.Name,
		&checkpoint.ProfileName,
		&checkpoint.Activity,
		&checkpoint.BaseQuery,
		&checkpoint.EffectiveQuery,
		&checkpoint.QueriesJSON,
		&checkpoint.Since,
		&checkpoint.CreatedSince,
		&checkpoint.CreatedBefore,
		&checkpoint.UpdatedSince,
		&checkpoint.UpdatedBefore,
		&checkpoint.NextCreatedBefore,
		&checkpoint.NextUpdatedBefore,
		&checkpoint.OldestCreatedAt,
		&checkpoint.OldestUpdatedAt,
		&checkpoint.CompletedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return SearchCheckpoint{}, fmt.Errorf("search checkpoint %q not found", name)
		}
		return SearchCheckpoint{}, fmt.Errorf("querying search checkpoint: %w", err)
	}
	return checkpoint, nil
}

// ListSearchCheckpoints returns all stored search checkpoints ordered by name.
func (d *Database) ListSearchCheckpoints() ([]SearchCheckpoint, error) {
	rows, err := d.db.Query(`
		SELECT name, profile_name, activity, base_query, effective_query, queries_json, since, created_since, created_before, updated_since, updated_before, next_created_before, next_updated_before, oldest_created_at, oldest_updated_at, completed_at
		FROM search_checkpoints
		ORDER BY name ASC`)
	if err != nil {
		return nil, fmt.Errorf("querying search checkpoints: %w", err)
	}
	defer rows.Close()

	checkpoints := make([]SearchCheckpoint, 0)
	for rows.Next() {
		var checkpoint SearchCheckpoint
		if err := rows.Scan(
			&checkpoint.Name,
			&checkpoint.ProfileName,
			&checkpoint.Activity,
			&checkpoint.BaseQuery,
			&checkpoint.EffectiveQuery,
			&checkpoint.QueriesJSON,
			&checkpoint.Since,
			&checkpoint.CreatedSince,
			&checkpoint.CreatedBefore,
			&checkpoint.UpdatedSince,
			&checkpoint.UpdatedBefore,
			&checkpoint.NextCreatedBefore,
			&checkpoint.NextUpdatedBefore,
			&checkpoint.OldestCreatedAt,
			&checkpoint.OldestUpdatedAt,
			&checkpoint.CompletedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning search checkpoint: %w", err)
		}
		checkpoints = append(checkpoints, checkpoint)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating search checkpoints: %w", err)
	}
	return checkpoints, nil
}

// DeleteSearchCheckpoint removes a named search checkpoint.
func (d *Database) DeleteSearchCheckpoint(name string) error {
	result, err := d.db.Exec(`DELETE FROM search_checkpoints WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("deleting search checkpoint: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking deleted checkpoint rows: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("search checkpoint %q not found", name)
	}
	return nil
}
