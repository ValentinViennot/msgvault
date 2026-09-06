// Package authz defines the caller roles and the request principal shared by
// the daemon HTTP API and the MCP server.
package authz

import "fmt"

// Role is the permission level of a caller. Roles are ordered: each role
// includes every permission of the roles below it.
type Role string

const (
	// RoleViewer may read the archive and run analytical queries.
	RoleViewer Role = "viewer"
	// RoleMember may additionally curate: Saved Views, people, organizations,
	// relationships, notes, day entries, and message task links.
	RoleMember Role = "member"
	// RoleAdmin may do everything, including operations that change what the
	// archive contains or how the daemon runs.
	RoleAdmin Role = "admin"
)

// Roles lists every role from least to most privileged.
var Roles = []Role{RoleViewer, RoleMember, RoleAdmin}

// ParseRole validates a configured role name.
func ParseRole(value string) (Role, error) {
	switch role := Role(value); role {
	case RoleViewer, RoleMember, RoleAdmin:
		return role, nil
	}
	return "", fmt.Errorf("unknown role %q (want viewer, member, or admin)", value)
}

func (r Role) rank() int {
	switch r {
	case RoleViewer:
		return 1
	case RoleMember:
		return 2
	case RoleAdmin:
		return 3
	}
	return 0
}

// AtLeast reports whether r grants everything required grants. An empty or
// unknown role on either side grants nothing.
func (r Role) AtLeast(required Role) bool {
	return r.rank() > 0 && required.rank() > 0 && r.rank() >= required.rank()
}

// PrincipalKind says which credential a principal came from.
type PrincipalKind string

const (
	// PrincipalLoopback is the keyless daemon's implicit local operator.
	PrincipalLoopback PrincipalKind = "loopback"
	// PrincipalAPIKey is [server].api_key or a named [[auth.api_keys]] entry.
	PrincipalAPIKey PrincipalKind = "api_key"
	// PrincipalUser is a person signed in through an identity provider.
	PrincipalUser PrincipalKind = "user"
)

// Principal is the authenticated caller of one request.
type Principal struct {
	Kind  PrincipalKind
	Name  string
	Email string
	Role  Role
	// IdentityIssuer and IdentitySubject name the identity-provider account
	// behind a user principal, when one signed in.
	IdentityIssuer  string
	IdentitySubject string
	// UserID is the users row the principal resolved to, or 0.
	UserID int64
	// VisibleSourceIDs confines the caller to these sources. Nil means every
	// source (administrators); an empty, non-nil slice means none.
	VisibleSourceIDs []int64
}

// Can reports whether the principal holds at least the required role.
func (p Principal) Can(required Role) bool { return p.Role.AtLeast(required) }

// IsZero reports whether no principal was established.
func (p Principal) IsZero() bool {
	return p.Kind == "" && p.Name == "" && p.Email == "" && p.Role == ""
}

// Scoped reports whether the principal sees only some sources.
func (p Principal) Scoped() bool { return p.VisibleSourceIDs != nil }

// Sees reports whether the principal may read the source.
func (p Principal) Sees(sourceID int64) bool {
	if !p.Scoped() {
		return true
	}
	for _, id := range p.VisibleSourceIDs {
		if id == sourceID {
			return true
		}
	}
	return false
}

// RestrictSources intersects a requested source set with the visible one. A
// nil request means every visible source. The result is nil for an unscoped
// principal with no request, and an empty slice when nothing remains.
func (p Principal) RestrictSources(requested []int64) []int64 {
	if !p.Scoped() {
		return requested
	}
	if requested == nil {
		out := make([]int64, len(p.VisibleSourceIDs))
		copy(out, p.VisibleSourceIDs)
		return out
	}
	out := make([]int64, 0, len(requested))
	for _, id := range requested {
		if p.Sees(id) {
			out = append(out, id)
		}
	}
	return out
}

// ServerKey is the principal behind [server].api_key.
func ServerKey() Principal {
	return Principal{Kind: PrincipalAPIKey, Name: "server", Role: RoleAdmin}
}

// Loopback is the principal of a keyless daemon's requests.
func Loopback() Principal {
	return Principal{Kind: PrincipalLoopback, Name: "loopback", Role: RoleAdmin}
}
