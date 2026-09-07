package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"go.kenn.io/msgvault/internal/authz"
)

// actingUserRefusedErrorCode is the JSON-RPC error a resource read answers
// when the daemon refuses the person the listener acts for (server-defined
// range; -32000 is the invocation limit).
const actingUserRefusedErrorCode = -32001

// daemonUnauthorizedCode is the daemon's stable error code for a request it
// does not authenticate.
const daemonUnauthorizedCode = "unauthorized"

// actingUserRefused recognises a daemon that turned away a request the
// listener made on behalf of a signed-in person. The person authenticated
// here, so the daemon's refusal means it does not accept them as a user:
// most often it has never seen them, because it records users at sign-in.
// Rather than a generic internal error, the person gets told what to do.
func actingUserRefused(ctx context.Context, err error) (string, bool) {
	email := authz.ActingUser(ctx)
	if email == "" {
		return "", false
	}
	var coded daemonAPIErrorCoder
	if !errors.As(err, &coded) || coded.APIErrorCode() != daemonUnauthorizedCode {
		return "", false
	}
	slog.Warn("daemon refused the acting user; the person must sign in to the web UI once",
		"acting_user", email, "error", err)
	return fmt.Sprintf("acting_user_refused: the daemon refused to act as %s. "+
		"Sign in to the msgvault web UI once with this account, then retry: "+
		"the daemon records your user at that sign-in. If it still refuses, "+
		"the account is disabled on the archive or the MCP server's daemon key "+
		"is not allowed to act on behalf of users (on_behalf_of).", email), true
}
