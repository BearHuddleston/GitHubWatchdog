package db

import (
	"path/filepath"
	"testing"
	"time"
)

func TestInsertProcessedRepoUpsertsUpdatedAt(t *testing.T) {
	database, err := New(filepath.Join(t.TempDir(), "watchdog.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer database.Close()

	initial := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	updated := initial.Add(24 * time.Hour)

	if err := database.InsertProcessedRepo("owner/repo", "owner", "repo", initial, 1, 2, false); err != nil {
		t.Fatalf("InsertProcessedRepo() initial error = %v", err)
	}
	if err := database.InsertProcessedRepo("owner/repo", "owner", "repo", updated, 3, 4, true); err != nil {
		t.Fatalf("InsertProcessedRepo() updated error = %v", err)
	}

	already, err := database.WasRepoProcessed("owner/repo", updated)
	if err != nil {
		t.Fatalf("WasRepoProcessed() error = %v", err)
	}
	if !already {
		t.Fatal("expected updated repository timestamp to be stored")
	}
}

func TestInsertProcessedUserUpsertsMetrics(t *testing.T) {
	database, err := New(filepath.Join(t.TempDir(), "watchdog.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer database.Close()

	createdAt := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)

	if err := database.InsertProcessedUser("octocat", createdAt, 10, 1, 1, 2, false); err != nil {
		t.Fatalf("InsertProcessedUser() initial error = %v", err)
	}
	if err := database.InsertProcessedUser("octocat", createdAt, 20, 3, 2, 5, true); err != nil {
		t.Fatalf("InsertProcessedUser() updated error = %v", err)
	}

	var totalStars, emptyCount, suspiciousEmptyCount, contributions int
	var analysisResult bool
	if err := database.QueryRow(`
		SELECT total_stars, empty_count, suspicious_empty_count, contributions, analysis_result
		FROM processed_users
		WHERE username = ?`,
		"octocat",
	).Scan(&totalStars, &emptyCount, &suspiciousEmptyCount, &contributions, &analysisResult); err != nil {
		t.Fatalf("QueryRow().Scan() error = %v", err)
	}

	if totalStars != 20 || emptyCount != 3 || suspiciousEmptyCount != 2 || contributions != 5 || !analysisResult {
		t.Fatalf("processed_users row was not updated: got stars=%d empty=%d suspicious_empty=%d contributions=%d suspicious=%v",
			totalStars, emptyCount, suspiciousEmptyCount, contributions, analysisResult)
	}
}

func TestSearchCheckpointUpsertAndGet(t *testing.T) {
	database, err := New(filepath.Join(t.TempDir(), "watchdog.db"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer database.Close()

	firstCompleted := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	secondCompleted := firstCompleted.Add(1 * time.Hour)

	if err := database.UpsertSearchCheckpoint(SearchCheckpoint{
		Name:              "recent-scan",
		ProfileName:       "recent",
		BaseQuery:         "stars:>5",
		EffectiveQuery:    "stars:>5 updated:>=2026-03-06",
		Since:             "2026-03-06",
		UpdatedBefore:     "",
		NextUpdatedBefore: "2026-03-12T11:59:59Z",
		OldestUpdatedAt:   time.Date(2026, 3, 12, 12, 0, 0, 0, time.UTC),
		CompletedAt:       firstCompleted,
	}); err != nil {
		t.Fatalf("UpsertSearchCheckpoint() initial error = %v", err)
	}
	if err := database.UpsertSearchCheckpoint(SearchCheckpoint{
		Name:              "recent-scan",
		ProfileName:       "backfill",
		BaseQuery:         "stars:>10",
		EffectiveQuery:    "stars:>10 updated:<=2026-03-10",
		Since:             "",
		UpdatedBefore:     "2026-03-10",
		NextUpdatedBefore: "2026-03-09T23:59:59Z",
		OldestUpdatedAt:   time.Date(2026, 3, 10, 0, 0, 0, 0, time.UTC),
		CompletedAt:       secondCompleted,
	}); err != nil {
		t.Fatalf("UpsertSearchCheckpoint() update error = %v", err)
	}

	checkpoint, err := database.GetSearchCheckpoint("recent-scan")
	if err != nil {
		t.Fatalf("GetSearchCheckpoint() error = %v", err)
	}

	if checkpoint.ProfileName != "backfill" || checkpoint.BaseQuery != "stars:>10" || checkpoint.NextUpdatedBefore != "2026-03-09T23:59:59Z" {
		t.Fatalf("search checkpoint row was not updated: %+v", checkpoint)
	}
	if !checkpoint.CompletedAt.Equal(secondCompleted) {
		t.Fatalf("CompletedAt = %v, want %v", checkpoint.CompletedAt, secondCompleted)
	}
}
