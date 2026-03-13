package config

import (
	"errors"
	"testing"
)

func TestResolveGitHubTokenWithEnvPrecedence(t *testing.T) {
	getenv := func(name string) string {
		switch name {
		case "GITHUB_TOKEN":
			return "github-token"
		case "GH_TOKEN":
			return "gh-token"
		default:
			return ""
		}
	}

	token := resolveGitHubTokenWith(getenv, func() (string, error) {
		t.Fatal("gh token lookup should not run when env token is set")
		return "", nil
	})

	if token != "github-token" {
		t.Fatalf("resolveGitHubTokenWith() = %q, want github-token", token)
	}
}

func TestResolveGitHubTokenWithGHEnvFallback(t *testing.T) {
	getenv := func(name string) string {
		if name == "GH_TOKEN" {
			return "gh-token"
		}
		return ""
	}

	token := resolveGitHubTokenWith(getenv, func() (string, error) {
		t.Fatal("gh token lookup should not run when GH_TOKEN is set")
		return "", nil
	})

	if token != "gh-token" {
		t.Fatalf("resolveGitHubTokenWith() = %q, want gh-token", token)
	}
}

func TestResolveGitHubTokenWithGHAuthFallback(t *testing.T) {
	token := resolveGitHubTokenWith(func(string) string { return "" }, func() (string, error) {
		return "cli-token\n", nil
	})

	if token != "cli-token" {
		t.Fatalf("resolveGitHubTokenWith() = %q, want cli-token", token)
	}
}

func TestResolveGitHubTokenWithNoSource(t *testing.T) {
	token := resolveGitHubTokenWith(func(string) string { return "" }, func() (string, error) {
		return "", errors.New("missing")
	})

	if token != "" {
		t.Fatalf("resolveGitHubTokenWith() = %q, want empty", token)
	}
}
