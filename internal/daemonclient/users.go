package daemonclient

import (
	"context"
	"time"

	apiclient "go.kenn.io/msgvault/pkg/client"
	"go.kenn.io/msgvault/pkg/client/generated"
)

// User is one user of the daemon as administrators see them.
type User struct {
	ID          int64
	Email       string
	DisplayName string
	Role        string
	Disabled    bool
	LastLoginAt *time.Time
	SourceIDs   []int64
}

func userFromGenerated(summary generated.UserSummary) User {
	user := User{
		ID: summary.ID, Email: summary.Email, Role: string(summary.Role), Disabled: summary.Disabled,
		LastLoginAt: summary.LastLoginAt, SourceIDs: append([]int64(nil), summary.SourceIds...),
	}
	if summary.DisplayName != nil {
		user.DisplayName = *summary.DisplayName
	}
	if user.SourceIDs == nil {
		user.SourceIDs = []int64{}
	}
	return user
}

// ListUsers returns every user with their bound sources.
func (c *Client) ListUsers(ctx context.Context) ([]User, error) {
	resp, err := APIResponse(c, func(client *apiclient.Client) (*generated.ListUsersResp, error) {
		return client.ListUsersWithResponse(ctx)
	})
	if err != nil {
		return nil, err
	}
	users := make([]User, 0, len(resp.JSON200.Users))
	for _, summary := range resp.JSON200.Users {
		users = append(users, userFromGenerated(summary))
	}
	return users, nil
}

// SetUserSources replaces the sources a user may read.
func (c *Client) SetUserSources(ctx context.Context, userID int64, sourceIDs []int64) (*User, error) {
	if sourceIDs == nil {
		sourceIDs = []int64{}
	}
	resp, err := APIResponse(c, func(client *apiclient.Client) (*generated.SetUserSourcesResp, error) {
		return client.SetUserSourcesWithResponse(ctx, &generated.SetUserSourcesRequestOptions{
			PathParams: &generated.SetUserSourcesPath{ID: userID},
			Body:       &generated.SetUserSourcesBody{SourceIds: sourceIDs},
		})
	})
	if err != nil {
		return nil, err
	}
	user := userFromGenerated(*resp.JSON200)
	return &user, nil
}

// SetUserDisabled blocks or restores a user.
func (c *Client) SetUserDisabled(ctx context.Context, userID int64, disabled bool) (*User, error) {
	resp, err := APIResponse(c, func(client *apiclient.Client) (*generated.PatchUserResp, error) {
		return client.PatchUserWithResponse(ctx, &generated.PatchUserRequestOptions{
			PathParams: &generated.PatchUserPath{ID: userID},
			Body:       &generated.PatchUserBody{Disabled: &disabled},
		})
	})
	if err != nil {
		return nil, err
	}
	user := userFromGenerated(*resp.JSON200)
	return &user, nil
}
