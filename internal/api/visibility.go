package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.kenn.io/msgvault/internal/authz"
	"go.kenn.io/msgvault/internal/query"
	"go.kenn.io/msgvault/internal/store"
)

// UserStore is the daemon's view of users: identity-provider sign-ins, the
// binding of principals to users, and the sources each user may read.
type UserStore interface {
	RecordUserLogin(ctx context.Context, login store.UserLogin) (*store.User, error)
	GetUser(ctx context.Context, id int64) (*store.User, error)
	GetUserByEmail(ctx context.Context, email string) (*store.User, error)
	GetUserByIdentity(ctx context.Context, issuer, subject string) (*store.User, error)
	ListUsers(ctx context.Context) ([]store.User, error)
	ListUserSourceIDs(ctx context.Context, userID int64) ([]int64, error)
	SetUserSources(ctx context.Context, userID int64, sourceIDs []int64) error
	SetUserDisabled(ctx context.Context, id int64, disabled bool) error
}

// visibilityTTL bounds how long a binding change (sources, disabled) takes
// to reach a live session or key.
const visibilityTTL = 30 * time.Second

var (
	errActingUserNotAllowed = errors.New("this credential may not act on behalf of a user")
	errActingUserUnknown    = errors.New("acting user is not a known user")
	errUserDisabled         = errors.New("user is disabled")
)

type visibilityEntry struct {
	principal authz.Principal
	err       error
	expires   time.Time
}

type visibilityCache struct {
	mu      sync.Mutex
	entries map[string]visibilityEntry
	now     func() time.Time
}

func newVisibilityCache() *visibilityCache {
	return &visibilityCache{entries: make(map[string]visibilityEntry), now: time.Now}
}

func (c *visibilityCache) get(key string) (visibilityEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok || !c.now().Before(entry.expires) {
		delete(c.entries, key)
		return visibilityEntry{}, false
	}
	return entry, true
}

// reset drops every cached binding after an administrative change.
func (c *visibilityCache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]visibilityEntry)
}

func (c *visibilityCache) put(key string, entry visibilityEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) > 1024 {
		c.entries = make(map[string]visibilityEntry)
	}
	entry.expires = c.now().Add(visibilityTTL)
	c.entries[key] = entry
}

// finishAuthentication completes a credential-derived principal: an acting
// user replaces the caller when the credential allows it, and every
// non-administrator is confined to the sources bound to their user. It fails
// closed: a resolution error, a disabled user, or a principal with no user
// leaves the caller unauthenticated or with no visible source.
func (s *Server) finishAuthentication(r *http.Request, auth requestAuthentication, allowActing bool) requestAuthentication {
	if auth.Mode == AuthModeRequired || auth.Mode == AuthModeLoopback {
		return auth
	}
	acting := strings.TrimSpace(r.Header.Get(authz.ActingUserHeader))
	principal, err := s.resolvePrincipal(r.Context(), auth.Principal, acting, allowActing)
	if err != nil {
		s.logger.Warn("principal resolution refused",
			"principal", string(auth.Principal.Kind)+":"+auth.Principal.Name,
			"acting_user", acting, "error", err)
		return requestAuthentication{Mode: AuthModeRequired}
	}
	auth.Principal = principal
	if auth.Mode == AuthModeAPIKey && acting != "" {
		// The credential is a service key; the request is the user's.
		auth.trustedForCLIDuration = principal.Role == authz.RoleAdmin
	}
	return auth
}

func (s *Server) resolvePrincipal(ctx context.Context, principal authz.Principal, acting string, allowActing bool) (authz.Principal, error) {
	if acting != "" {
		if !allowActing {
			return authz.Principal{}, errActingUserNotAllowed
		}
		if s.userStore == nil {
			return authz.Principal{}, errActingUserUnknown
		}
		user, err := s.userStore.GetUserByEmail(ctx, acting)
		if errors.Is(err, store.ErrUserNotFound) {
			return authz.Principal{}, errActingUserUnknown
		}
		if err != nil {
			return authz.Principal{}, err
		}
		role, err := authz.ParseRole(user.Role)
		if err != nil {
			role = authz.RoleViewer
		}
		name := user.DisplayName
		if name == "" {
			name = user.Email
		}
		principal = authz.Principal{Kind: authz.PrincipalUser, Name: name, Email: user.Email, Role: role, UserID: user.ID}
	}
	if principal.Role == authz.RoleAdmin {
		principal.VisibleSourceIDs = nil
		return principal, nil
	}
	key := cacheKey(principal)
	if entry, ok := s.visibility.get(key); ok {
		if entry.err != nil {
			return authz.Principal{}, entry.err
		}
		principal.UserID = entry.principal.UserID
		principal.VisibleSourceIDs = entry.principal.VisibleSourceIDs
		return principal, nil
	}
	resolved, err := s.lookupVisibility(ctx, principal)
	s.visibility.put(key, visibilityEntry{principal: resolved, err: err})
	if err != nil {
		return authz.Principal{}, err
	}
	return resolved, nil
}

func cacheKey(principal authz.Principal) string {
	return strings.Join([]string{string(principal.Kind), principal.Name, principal.Email,
		principal.IdentityIssuer, principal.IdentitySubject, string(principal.Role)}, "\x00")
}

// lookupVisibility finds the user behind a non-administrator principal and
// loads the sources bound to them. No user means no sources.
func (s *Server) lookupVisibility(ctx context.Context, principal authz.Principal) (authz.Principal, error) {
	principal.VisibleSourceIDs = []int64{}
	if s.userStore == nil {
		return principal, nil
	}
	var (
		user *store.User
		err  error
	)
	switch {
	case principal.UserID != 0:
		user, err = s.userStore.GetUser(ctx, principal.UserID)
	case principal.IdentityIssuer != "" && principal.IdentitySubject != "":
		user, err = s.userStore.GetUserByIdentity(ctx, principal.IdentityIssuer, principal.IdentitySubject)
		if errors.Is(err, store.ErrUserNotFound) && principal.Email != "" {
			user, err = s.userStore.GetUserByEmail(ctx, principal.Email)
		}
	case principal.Email != "":
		user, err = s.userStore.GetUserByEmail(ctx, principal.Email)
	default:
		return principal, nil
	}
	if errors.Is(err, store.ErrUserNotFound) {
		return principal, nil
	}
	if err != nil {
		return authz.Principal{}, err
	}
	if user.Disabled {
		return authz.Principal{}, errUserDisabled
	}
	principal.UserID = user.ID
	sources, err := s.userStore.ListUserSourceIDs(ctx, user.ID)
	if err != nil {
		return authz.Principal{}, err
	}
	principal.VisibleSourceIDs = sources
	return principal, nil
}

// principalFromContext returns the request principal recorded by the
// security middleware, or a zero principal outside a request.
func principalFromContext(ctx context.Context) authz.Principal {
	if security, ok := ctx.Value(requestSecurityContextKey{}).(requestSecurity); ok {
		return security.auth.Principal
	}
	return authz.Principal{}
}

// requestPrincipal returns the caller of r.
func (s *Server) requestPrincipal(r *http.Request) authz.Principal {
	return s.requestAuthentication(r).Principal
}

// scopeEngine confines an engine to the principal's sources.
func scopeEngine(engine query.Engine, principal authz.Principal) query.Engine {
	if engine == nil || !principal.Scoped() {
		return engine
	}
	return query.NewScopedEngine(engine, principal.VisibleSourceIDs)
}

// writeScopeError maps the scoped engine's refusals to client errors.
func writeScopeError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, query.ErrScopeRequiresSource):
		writeError(w, http.StatusBadRequest, "scope_requires_source", err.Error())
		return true
	case errors.Is(err, query.ErrScopedSQL):
		writeError(w, http.StatusForbidden, "forbidden", err.Error())
		return true
	}
	return false
}
