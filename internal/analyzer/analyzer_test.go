package analyzer

import (
	"context"
	"errors"
	"testing"

	"github.com/arkouda/github/GitHubWatchdog/internal/logger"
)

func TestAnalyzeUserReturnsStoredErrorForFailedHolder(t *testing.T) {
	a := &Analyzer{
		logger: logger.New(false),
	}

	holder := &ResultHolder{
		Err:   errors.New("boom"),
		Ready: make(chan struct{}),
	}
	close(holder.Ready)
	a.processedUsers.Store("octocat", holder)

	_, err := a.AnalyzeUser(context.Background(), "octocat")
	if err == nil {
		t.Fatal("expected stored error to be returned")
	}

	if _, ok := a.processedUsers.Load("octocat"); ok {
		t.Fatal("expected failed holder to be removed so future calls can retry")
	}
}
