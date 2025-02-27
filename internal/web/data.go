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
func (s *Server) getRepositories(page, limit int) ([]RepositoryData, int, error) {
	offset := (page - 1) * limit
	
	// Get total count
	var totalCount int
	err := s.db.QueryRow("SELECT COUNT(*) FROM processed_repositories").Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("counting repositories: %w", err)
	}
	
	// Get paginated repositories
	rows, err := s.db.Query(`
		SELECT id, repo_id, owner, name, updated_at, disk_usage, stargazer_count, is_malicious, processed_at 
		FROM processed_repositories 
		ORDER BY processed_at DESC 
		LIMIT ? OFFSET ?`,
		limit, offset,
	)
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
func (s *Server) getUsers(page, limit int) ([]UserData, int, error) {
	offset := (page - 1) * limit
	
	// Get total count
	var totalCount int
	err := s.db.QueryRow("SELECT COUNT(*) FROM processed_users").Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("counting users: %w", err)
	}
	
	// Get paginated users
	rows, err := s.db.Query(`
		SELECT id, username, created_at, total_stars, empty_count, 
		       suspicious_empty_count, contributions, analysis_result, processed_at 
		FROM processed_users 
		ORDER BY processed_at DESC 
		LIMIT ? OFFSET ?`,
		limit, offset,
	)
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
func (s *Server) getFlags(page, limit int) ([]FlagData, int, error) {
	offset := (page - 1) * limit
	
	// Get total count
	var totalCount int
	err := s.db.QueryRow("SELECT COUNT(*) FROM heuristic_flags").Scan(&totalCount)
	if err != nil {
		return nil, 0, fmt.Errorf("counting flags: %w", err)
	}
	
	// Get paginated flags
	rows, err := s.db.Query(`
		SELECT id, entity_type, entity_id, flag, triggered_at 
		FROM heuristic_flags 
		ORDER BY triggered_at DESC 
		LIMIT ? OFFSET ?`,
		limit, offset,
	)
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