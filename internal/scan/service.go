package scan

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/arkouda/github/GitHubWatchdog/internal/analyzer"
	"github.com/arkouda/github/GitHubWatchdog/internal/db"
	"github.com/arkouda/github/GitHubWatchdog/internal/github"
	"github.com/arkouda/github/GitHubWatchdog/internal/models"
)

// Service coordinates GitHub scanning, heuristic analysis, and optional persistence.
type Service struct {
	client   *github.Client
	analyzer *analyzer.Analyzer
	db       *db.Database
}

// SearchOptions controls batch repository scanning.
type SearchOptions struct {
	ProfileName   string
	BaseQuery     string
	Query         string
	Since         string
	UpdatedBefore string
	MaxPages      int
	PerPage       int
	MaxConcurrent int
	Persist       bool
}

// RepoOptions controls direct repository scanning.
type RepoOptions struct {
	Persist          bool
	SkipIfUnchanged  bool
	AnalyzeOwner     bool
	OwnerIfSmallOnly bool
}

// UserOptions controls direct user scanning.
type UserOptions struct {
	Persist bool
}

// SearchReport is the machine-readable output from a search scan.
type SearchReport struct {
	ProfileName     string       `json:"profile_name,omitempty"`
	BaseQuery       string       `json:"base_query,omitempty"`
	Query           string       `json:"query"`
	Since           string       `json:"since,omitempty"`
	UpdatedBefore   string       `json:"updated_before,omitempty"`
	StartedAt       time.Time    `json:"started_at"`
	CompletedAt     time.Time    `json:"completed_at"`
	OldestUpdatedAt time.Time    `json:"oldest_updated_at,omitempty"`
	Results         []RepoReport `json:"results"`
}

// RepoReport is the machine-readable output from a repository scan.
type RepoReport struct {
	RepoID        string                   `json:"repo_id"`
	Owner         string                   `json:"owner"`
	Name          string                   `json:"name"`
	DefaultBranch string                   `json:"default_branch,omitempty"`
	UpdatedAt     time.Time                `json:"updated_at"`
	DiskUsage     int                      `json:"disk_usage"`
	Stargazers    int                      `json:"stargazers"`
	ReadmePresent bool                     `json:"readme_present"`
	FileCount     int                      `json:"file_count"`
	Skipped       bool                     `json:"skipped,omitempty"`
	SkipReason    string                   `json:"skip_reason,omitempty"`
	IsMalicious   bool                     `json:"is_malicious"`
	RepoFlags     []models.HeuristicResult `json:"repo_flags,omitempty"`
	OwnerAnalysis *UserReport              `json:"owner_analysis,omitempty"`
	Persisted     bool                     `json:"persisted"`
	Errors        []string                 `json:"errors,omitempty"`
}

// UserReport is the machine-readable output from a user scan.
type UserReport struct {
	Username             string                   `json:"username"`
	CreatedAt            time.Time                `json:"created_at"`
	Contributions        int                      `json:"contributions"`
	TotalStars           int                      `json:"total_stars"`
	EmptyCount           int                      `json:"empty_count"`
	SuspiciousEmptyCount int                      `json:"suspicious_empty_count"`
	Suspicious           bool                     `json:"is_suspicious"`
	Heuristics           []models.HeuristicResult `json:"heuristics,omitempty"`
	Persisted            bool                     `json:"persisted"`
	Errors               []string                 `json:"errors,omitempty"`
}

// NewService creates a new scan service.
func NewService(client *github.Client, database *db.Database) *Service {
	return &Service{
		client:   client,
		analyzer: analyzer.New(client),
		db:       database,
	}
}

// Search scans repositories matching the provided search query.
func (s *Service) Search(ctx context.Context, opts SearchOptions) (SearchReport, error) {
	return s.SearchStream(ctx, opts, nil)
}

// SearchStream scans repositories and invokes onResult for each completed repository report.
func (s *Service) SearchStream(ctx context.Context, opts SearchOptions, onResult func(RepoReport) error) (SearchReport, error) {
	report := SearchReport{
		ProfileName:   opts.ProfileName,
		BaseQuery:     opts.BaseQuery,
		Query:         opts.Query,
		Since:         opts.Since,
		UpdatedBefore: opts.UpdatedBefore,
		StartedAt:     time.Now().UTC(),
	}

	opts = normalizeSearchOptions(opts)

	for page := 1; page <= opts.MaxPages; page++ {
		result, err := s.client.SearchRepositories(ctx, opts.Query, page, opts.PerPage)
		if err != nil {
			return report, err
		}
		if len(result.Items) == 0 {
			break
		}

		pageResults, err := s.processSearchPage(ctx, result.Items, opts, onResult, &report)
		report.Results = append(report.Results, pageResults...)
		if err != nil {
			return report, err
		}

		if len(result.Items) < opts.PerPage {
			break
		}
	}

	report.CompletedAt = time.Now().UTC()
	return report, nil
}

func normalizeSearchOptions(opts SearchOptions) SearchOptions {
	if opts.MaxPages <= 0 {
		opts.MaxPages = 1
	}
	if opts.PerPage <= 0 {
		opts.PerPage = 100
	}
	if opts.MaxConcurrent <= 0 {
		opts.MaxConcurrent = 10
	}
	return opts
}

func (s *Service) processSearchPage(
	ctx context.Context,
	items []models.RepoItem,
	opts SearchOptions,
	onResult func(RepoReport) error,
	report *SearchReport,
) ([]RepoReport, error) {
	type pageResult struct {
		report RepoReport
	}

	resultsCh := make(chan pageResult, len(items))
	sem := make(chan struct{}, opts.MaxConcurrent)
	var wg sync.WaitGroup

	for _, item := range items {
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			resultsCh <- pageResult{
				report: s.scanRepoItem(ctx, item, RepoOptions{
					Persist:          opts.Persist,
					SkipIfUnchanged:  true,
					AnalyzeOwner:     true,
					OwnerIfSmallOnly: true,
				}),
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	pageResults := make([]RepoReport, 0, len(items))
	var callbackErr error
	for result := range resultsCh {
		pageResults = append(pageResults, result.report)
		if report.OldestUpdatedAt.IsZero() || result.report.UpdatedAt.Before(report.OldestUpdatedAt) {
			report.OldestUpdatedAt = result.report.UpdatedAt
		}
		if callbackErr == nil && onResult != nil {
			callbackErr = onResult(result.report)
		}
	}

	if callbackErr != nil {
		return pageResults, callbackErr
	}

	return pageResults, nil
}

// ScanRepository scans a specific repository by owner/name.
func (s *Service) ScanRepository(ctx context.Context, owner, name string, opts RepoOptions) (RepoReport, error) {
	query := fmt.Sprintf("repo:%s/%s", owner, name)
	result, err := s.client.SearchRepositories(ctx, query, 1, 1)
	if err != nil {
		return RepoReport{}, err
	}
	if len(result.Items) == 0 {
		return RepoReport{}, fmt.Errorf("repository %s/%s not found", owner, name)
	}

	return s.scanRepoItem(ctx, result.Items[0], opts), nil
}

// ScanUser scans a specific user.
func (s *Service) ScanUser(ctx context.Context, username string, opts UserOptions) (UserReport, error) {
	analysis, err := s.analyzer.AnalyzeUser(ctx, username)
	report := UserReport{
		Username:             username,
		CreatedAt:            analysis.CreatedAt,
		Contributions:        analysis.Contributions,
		TotalStars:           analysis.TotalStars,
		EmptyCount:           analysis.EmptyCount,
		SuspiciousEmptyCount: analysis.SuspiciousEmptyCount,
		Suspicious:           analysis.Suspicious,
		Heuristics:           analysis.HeuristicResults,
	}

	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report, err
	}

	if opts.Persist {
		if err := s.persistUser(report); err != nil {
			report.Errors = append(report.Errors, err.Error())
			return report, err
		}
		report.Persisted = true
	}

	return report, nil
}

// AnalyzedCount returns the number of repositories that were fully analyzed.
func (r SearchReport) AnalyzedCount() int {
	count := 0
	for _, result := range r.Results {
		if !result.Skipped {
			count++
		}
	}
	return count
}

// FlaggedCount returns the number of repositories with suspicious findings.
func (r SearchReport) FlaggedCount() int {
	count := 0
	for _, result := range r.Results {
		if result.IsFlagged() {
			count++
		}
	}
	return count
}

// Filter returns a copy of the report filtered for agent or operator consumption.
func (r SearchReport) Filter(onlyFlagged, includeSkipped bool) SearchReport {
	filtered := r
	filtered.Results = make([]RepoReport, 0, len(r.Results))

	for _, result := range r.Results {
		if !includeSkipped && result.Skipped {
			continue
		}
		if onlyFlagged && !result.IsFlagged() {
			continue
		}
		filtered.Results = append(filtered.Results, result)
	}

	return filtered
}

// IsFlagged returns whether the repository report contains suspicious findings.
func (r RepoReport) IsFlagged() bool {
	if r.IsMalicious || len(r.RepoFlags) > 0 {
		return true
	}
	return r.OwnerAnalysis != nil && r.OwnerAnalysis.Suspicious
}

func (s *Service) scanRepoItem(ctx context.Context, item models.RepoItem, opts RepoOptions) RepoReport {
	repo := RepoReport{
		RepoID:        fmt.Sprintf("%s/%s", item.Owner.Login, item.Name),
		Owner:         item.Owner.Login,
		Name:          item.Name,
		DefaultBranch: item.DefaultBranch,
		UpdatedAt:     item.UpdatedAt,
		DiskUsage:     item.Size,
		Stargazers:    item.StargazersCount,
	}
	if repo.DefaultBranch == "" {
		repo.DefaultBranch = "main"
	}

	if opts.Persist && opts.SkipIfUnchanged && s.db != nil {
		already, err := s.db.WasRepoProcessed(repo.RepoID, repo.UpdatedAt)
		if err != nil {
			repo.Errors = append(repo.Errors, fmt.Sprintf("checking persisted state: %v", err))
		} else if already {
			repo.Skipped = true
			repo.SkipReason = "repository already processed at this revision"
			return repo
		}
	}

	analyzedRepo := models.RepoData{
		Owner:          repo.Owner,
		Name:           repo.Name,
		DiskUsage:      repo.DiskUsage,
		StargazerCount: repo.Stargazers,
	}

	if repo.DefaultBranch != "" && repo.DiskUsage > 0 {
		repoData, malicious, err := s.analyzer.CheckRepoFiles(ctx, repo.Owner, repo.Name, repo.DefaultBranch)
		if err != nil {
			repo.Errors = append(repo.Errors, fmt.Sprintf("checking repository files: %v", err))
		} else {
			analyzedRepo = repoData
			analyzedRepo.DiskUsage = repo.DiskUsage
			analyzedRepo.StargazerCount = repo.Stargazers
			repo.IsMalicious = malicious
			repo.ReadmePresent = repoData.Readme != ""
			repo.FileCount = len(repoData.TreeEntries)
		}
	}

	repo.RepoFlags = analyzer.EvaluateRepoHeuristics(analyzedRepo)
	if opts.Persist && s.db != nil {
		if err := s.persistRepo(repo); err != nil {
			repo.Errors = append(repo.Errors, err.Error())
		} else {
			repo.Persisted = true
		}
	}

	if !opts.AnalyzeOwner {
		return repo
	}
	if opts.OwnerIfSmallOnly && repo.DiskUsage >= 10 {
		return repo
	}

	userReport, err := s.ScanUser(ctx, repo.Owner, UserOptions{Persist: opts.Persist})
	repo.OwnerAnalysis = &userReport
	if err != nil {
		repo.Errors = append(repo.Errors, fmt.Sprintf("analyzing owner: %v", err))
	}

	return repo
}

func (s *Service) persistRepo(repo RepoReport) error {
	if s.db == nil {
		return nil
	}

	for _, flag := range repo.RepoFlags {
		flagMsg := fmt.Sprintf("[%s] %s: %s", flag.Category, flag.Name, flag.Description)
		if err := s.db.InsertHeuristicFlag("repo", repo.RepoID, flagMsg); err != nil {
			return fmt.Errorf("recording repo flag: %w", err)
		}
	}

	if err := s.db.InsertProcessedRepo(
		repo.RepoID,
		repo.Owner,
		repo.Name,
		repo.UpdatedAt,
		repo.DiskUsage,
		repo.Stargazers,
		repo.IsMalicious,
	); err != nil {
		return fmt.Errorf("recording repository: %w", err)
	}

	return nil
}

func (s *Service) persistUser(report UserReport) error {
	if s.db == nil {
		return nil
	}

	if !s.analyzer.IsUserFlagged(report.Username) {
		for _, hr := range report.Heuristics {
			if !hr.Flag {
				continue
			}
			flagMsg := fmt.Sprintf("[%s] %s: %s", hr.Category, hr.Name, hr.Description)
			if err := s.db.InsertHeuristicFlag("user", report.Username, flagMsg); err != nil {
				return fmt.Errorf("recording user flag: %w", err)
			}
		}
		s.analyzer.MarkUserFlagged(report.Username)
	}

	if err := s.db.InsertProcessedUser(
		report.Username,
		report.CreatedAt,
		report.TotalStars,
		report.EmptyCount,
		report.SuspiciousEmptyCount,
		report.Contributions,
		report.Suspicious,
	); err != nil {
		return fmt.Errorf("recording user: %w", err)
	}

	return nil
}
