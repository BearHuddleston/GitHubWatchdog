package web

import (
	"fmt"
)

// getRepositoryStats returns the total count of repositories and count of malicious repositories
func (s *Server) getRepositoryStats() (int, int, error) {
	var repoCount, maliciousCount int
	
	err := s.db.QueryRow("SELECT COUNT(*) FROM processed_repositories").Scan(&repoCount)
	if err != nil {
		return 0, 0, fmt.Errorf("counting repositories: %w", err)
	}
	
	err = s.db.QueryRow("SELECT COUNT(*) FROM processed_repositories WHERE is_malicious = 1").Scan(&maliciousCount)
	if err != nil {
		return 0, 0, fmt.Errorf("counting malicious repositories: %w", err)
	}
	
	return repoCount, maliciousCount, nil
}

// getUserStats returns the total count of users and count of suspicious users
func (s *Server) getUserStats() (int, int, error) {
	var userCount, suspiciousCount int
	
	err := s.db.QueryRow("SELECT COUNT(*) FROM processed_users").Scan(&userCount)
	if err != nil {
		return 0, 0, fmt.Errorf("counting users: %w", err)
	}
	
	err = s.db.QueryRow("SELECT COUNT(*) FROM processed_users WHERE analysis_result = 1").Scan(&suspiciousCount)
	if err != nil {
		return 0, 0, fmt.Errorf("counting suspicious users: %w", err)
	}
	
	return userCount, suspiciousCount, nil
}

// getFlagCount returns the total count of heuristic flags
func (s *Server) getFlagCount() (int, error) {
	var flagCount int
	
	err := s.db.QueryRow("SELECT COUNT(*) FROM heuristic_flags").Scan(&flagCount)
	if err != nil {
		return 0, fmt.Errorf("counting flags: %w", err)
	}
	
	return flagCount, nil
}

// getRepositories returns a paginated list of repositories
func (s *Server) getRepositories(page, limit int, sortBy, sortOrder string) ([]RepositoryData, int, error) {
	offset := (page - 1) * limit
	
	// Get total count
	var totalCount int
	err := s.db.QueryRow("SELECT COUNT(*) FROM processed_repositories").Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("counting repositories: %w", err)
	}
	
	// Default sort
	if sortBy == "" {
		sortBy = "processed_at"
	}
	
	// Validate the sort column to prevent SQL injection
	validColumns := map[string]bool{
		"id": true, "repo_id": true, "owner": true, "name": true, 
		"updated_at": true, "disk_usage": true, "stargazer_count": true, 
		"is_malicious": true, "processed_at": true,
	}
	
	if !validColumns[sortBy] {
		sortBy = "processed_at"
	}
	
	// Validate sort order
	if sortOrder != "ASC" && sortOrder != "DESC" {
		sortOrder = "DESC"
	}
	
	// Get paginated repositories with sorting
	query := fmt.Sprintf(`
		SELECT id, repo_id, owner, name, updated_at, disk_usage, stargazer_count, is_malicious, processed_at 
		FROM processed_repositories 
		ORDER BY %s %s 
		LIMIT ? OFFSET ?`, sortBy, sortOrder)
		
	rows, err := s.db.Query(query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("querying repositories: %w", err)
	}
	defer rows.Close()
	
	var repositories []RepositoryData
	for rows.Next() {
		var repo RepositoryData
		if err := rows.Scan(
			&repo.ID,
			&repo.RepoID,
			&repo.Owner,
			&repo.Name,
			&repo.UpdatedAt,
			&repo.DiskUsage,
			&repo.StargazerCount,
			&repo.IsMalicious,
			&repo.ProcessedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning repository row: %w", err)
		}
		repositories = append(repositories, repo)
	}
	
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterating repository rows: %w", err)
	}
	
	return repositories, totalCount, nil
}

// getUsers returns a paginated list of users
func (s *Server) getUsers(page, limit int, sortBy, sortOrder string) ([]UserData, int, error) {
	offset := (page - 1) * limit
	
	// Get total count
	var totalCount int
	err := s.db.QueryRow("SELECT COUNT(*) FROM processed_users").Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("counting users: %w", err)
	}
	
	// Default sort
	if sortBy == "" {
		sortBy = "processed_at"
	}
	
	// Validate the sort column to prevent SQL injection
	validColumns := map[string]bool{
		"id": true, "username": true, "created_at": true, "total_stars": true, 
		"empty_count": true, "suspicious_empty_count": true, "contributions": true, 
		"analysis_result": true, "processed_at": true,
	}
	
	if !validColumns[sortBy] {
		sortBy = "processed_at"
	}
	
	// Validate sort order
	if sortOrder != "ASC" && sortOrder != "DESC" {
		sortOrder = "DESC"
	}
	
	// Get paginated users with sorting
	query := fmt.Sprintf(`
		SELECT id, username, created_at, total_stars, empty_count, 
		       suspicious_empty_count, contributions, analysis_result, processed_at 
		FROM processed_users 
		ORDER BY %s %s 
		LIMIT ? OFFSET ?`, sortBy, sortOrder)
		
	rows, err := s.db.Query(query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("querying users: %w", err)
	}
	defer rows.Close()
	
	var users []UserData
	for rows.Next() {
		var user UserData
		if err := rows.Scan(
			&user.ID,
			&user.Username,
			&user.CreatedAt,
			&user.TotalStars,
			&user.EmptyCount,
			&user.SuspiciousEmptyCount,
			&user.Contributions,
			&user.AnalysisResult,
			&user.ProcessedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning user row: %w", err)
		}
		users = append(users, user)
	}
	
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterating user rows: %w", err)
	}
	
	return users, totalCount, nil
}

// getFlags returns a paginated list of heuristic flags
func (s *Server) getFlags(page, limit int, sortBy, sortOrder string) ([]FlagData, int, error) {
	offset := (page - 1) * limit
	
	// Get total count
	var totalCount int
	err := s.db.QueryRow("SELECT COUNT(*) FROM heuristic_flags").Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("counting flags: %w", err)
	}
	
	// Default sort
	if sortBy == "" {
		sortBy = "triggered_at"
	}
	
	// Validate the sort column to prevent SQL injection
	validColumns := map[string]bool{
		"id": true, "entity_type": true, "entity_id": true, 
		"flag": true, "triggered_at": true,
	}
	
	if !validColumns[sortBy] {
		sortBy = "triggered_at"
	}
	
	// Validate sort order
	if sortOrder != "ASC" && sortOrder != "DESC" {
		sortOrder = "DESC"
	}
	
	// Get paginated flags with sorting
	query := fmt.Sprintf(`
		SELECT id, entity_type, entity_id, flag, triggered_at 
		FROM heuristic_flags 
		ORDER BY %s %s 
		LIMIT ? OFFSET ?`, sortBy, sortOrder)
		
	rows, err := s.db.Query(query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("querying flags: %w", err)
	}
	defer rows.Close()
	
	var flags []FlagData
	for rows.Next() {
		var flag FlagData
		if err := rows.Scan(
			&flag.ID,
			&flag.EntityType,
			&flag.EntityID,
			&flag.Flag,
			&flag.TriggeredAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning flag row: %w", err)
		}
		flags = append(flags, flag)
	}
	
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterating flag rows: %w", err)
	}
	
	return flags, totalCount, nil
}