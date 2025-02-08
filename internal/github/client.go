package github

import (
	"context"

	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

// NewClient creates a new GitHub GraphQL client using the provided token.
func NewClient(token string) *githubv4.Client {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	return githubv4.NewClient(tc)
}
