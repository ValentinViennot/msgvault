package authz

import "context"

type actingUserContextKey struct{}

// WithActingUser marks a request as made on behalf of the user with this
// address. A service that authenticates with its own credential (the MCP
// sidecar) sets it so the daemon applies that user's role and visibility.
func WithActingUser(ctx context.Context, email string) context.Context {
	if email == "" {
		return ctx
	}
	return context.WithValue(ctx, actingUserContextKey{}, email)
}

// ActingUser returns the address set by WithActingUser, if any.
func ActingUser(ctx context.Context) string {
	email, _ := ctx.Value(actingUserContextKey{}).(string)
	return email
}

// ActingUserHeader carries the acting user between a service and the daemon.
// The daemon honours it only from keys configured with on_behalf_of.
const ActingUserHeader = "X-Msgvault-On-Behalf-Of"
