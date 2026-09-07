package api

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/authz"
	"go.kenn.io/msgvault/internal/config"
	"go.kenn.io/msgvault/internal/query"
	"go.kenn.io/msgvault/internal/query/querytest"
	"go.kenn.io/msgvault/internal/store"
	"go.kenn.io/msgvault/internal/testutil"
)

type visibilityFixture struct {
	srv   *Server
	st    *store.Store
	alice *store.User
	one   int64
	two   int64
}

func newVisibilityFixture(t *testing.T) visibilityFixture {
	t.Helper()
	require := require.New(t)
	st := testutil.NewTestStore(t)
	one, err := st.GetOrCreateSource("gmail", "one@example.com")
	require.NoError(err)
	two, err := st.GetOrCreateSource("gmail", "two@example.com")
	require.NoError(err)
	alice, err := st.RecordUserLogin(t.Context(), store.UserLogin{
		Issuer: "https://idp.example", Subject: "alice", Email: "alice@example.com", DisplayName: "Alice", Role: "member",
	})
	require.NoError(err)
	require.NoError(st.SetUserSources(t.Context(), alice.ID, []int64{one.ID}))

	engine := &querytest.MockEngine{Messages: map[int64]*query.MessageDetail{
		11: {ID: 11, SourceID: one.ID, Subject: "in source one"},
		22: {ID: 22, SourceID: two.ID, Subject: "in source two"},
	}}
	cfg := &config.Config{
		Server: config.ServerConfig{APIKey: "admin-secret-value"},
		Auth: config.AuthConfig{APIKeys: []config.APIKeyConfig{
			{Name: "alice-key", Key: "alice-secret-value", Role: "member", User: "alice@example.com"},
			{Name: "reader", Key: "reader-secret-value", Role: "viewer"},
			{Name: "sidecar", Key: "sidecar-secret-value", Role: "admin", OnBehalfOf: true},
		}},
	}
	srv := NewServerWithOptions(ServerOptions{Config: cfg, Engine: engine, UserStore: st, Logger: testLogger()})
	t.Cleanup(func() {
		require.NoError(srv.Shutdown(context.Background()))
	})
	return visibilityFixture{srv: srv, st: st, alice: alice, one: one.ID, two: two.ID}
}

func withKey(key string, extra ...string) http.Header {
	headers := http.Header{"Authorization": []string{"Bearer " + key}}
	for i := 0; i+1 < len(extra); i += 2 {
		headers.Set(extra[i], extra[i+1])
	}
	return headers
}

func TestVisibilityConfinesCallersToTheirSources(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newVisibilityFixture(t)
	get := func(path string, headers http.Header) int {
		return performSessionRequest(t, f.srv, http.MethodGet, path, nil, headers, false).Code
	}

	assert.Equal(http.StatusOK, get("/api/v1/messages/11", withKey("alice-secret-value")))
	assert.Equal(http.StatusNotFound, get("/api/v1/messages/22", withKey("alice-secret-value")), "a bound key sees only its user's sources")
	assert.Equal(http.StatusNotFound, get("/api/v1/messages/11", withKey("reader-secret-value")), "a key without a user sees no source")
	assert.Equal(http.StatusOK, get("/api/v1/messages/11", withKey("admin-secret-value")))
	assert.Equal(http.StatusOK, get("/api/v1/messages/22", withKey("admin-secret-value")), "administrators see everything")

	me := performSessionRequest(t, f.srv, http.MethodGet, "/api/v1/me", nil, withKey("alice-secret-value"), false)
	require.Equal(http.StatusOK, me.Code)
	var principal PrincipalInfo
	require.NoError(decodeJSONBody(me, &principal))
	assert.Equal(PrincipalInfo{Kind: authz.PrincipalAPIKey, Name: "alice-key", Email: "alice@example.com", Role: authz.RoleMember}, principal)
}

func TestVisibilityOnBehalfOf(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newVisibilityFixture(t)
	acting := withKey("sidecar-secret-value", authz.ActingUserHeader, "alice@example.com")

	me := performSessionRequest(t, f.srv, http.MethodGet, "/api/v1/me", nil, acting, false)
	require.Equal(http.StatusOK, me.Code, me.Body.String())
	var principal PrincipalInfo
	require.NoError(decodeJSONBody(me, &principal))
	assert.Equal(PrincipalInfo{Kind: authz.PrincipalUser, Name: "Alice", Email: "alice@example.com", Role: authz.RoleMember}, principal)
	assert.Equal(http.StatusOK, performSessionRequest(t, f.srv, http.MethodGet, "/api/v1/messages/11", nil, acting, false).Code)
	assert.Equal(http.StatusNotFound, performSessionRequest(t, f.srv, http.MethodGet, "/api/v1/messages/22", nil, acting, false).Code)
	assert.Equal(http.StatusForbidden, performSessionRequest(t, f.srv, http.MethodPost, "/api/v1/query", []byte(`{}`), acting, false).Code,
		"the acting user's role applies, not the key's")

	assert.Equal(http.StatusUnauthorized, performSessionRequest(t, f.srv, http.MethodGet, "/api/v1/me", nil,
		withKey("admin-secret-value", authz.ActingUserHeader, "alice@example.com"), false).Code, "only on_behalf_of keys may act")
	assert.Equal(http.StatusUnauthorized, performSessionRequest(t, f.srv, http.MethodGet, "/api/v1/me", nil,
		withKey("sidecar-secret-value", authz.ActingUserHeader, "nobody@example.com"), false).Code, "an unknown acting user is refused")
}

func TestUserAdministrationChangesVisibility(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newVisibilityFixture(t)
	admin := withKey("admin-secret-value")

	list := performSessionRequest(t, f.srv, http.MethodGet, "/api/v1/users", nil, admin, false)
	require.Equal(http.StatusOK, list.Code, list.Body.String())
	var users UserListResponse
	require.NoError(decodeJSONBody(list, &users))
	require.Len(users.Users, 1)
	assert.Equal("alice@example.com", users.Users[0].Email)
	assert.Equal([]int64{f.one}, users.Users[0].SourceIDs)
	assert.Equal(http.StatusForbidden, performSessionRequest(t, f.srv, http.MethodGet, "/api/v1/users", nil, withKey("alice-secret-value"), false).Code)

	path := "/api/v1/users/" + itoa(f.alice.ID)
	moved := performSessionRequest(t, f.srv, http.MethodPut, path+"/sources", []byte(`{"source_ids":[`+itoa(f.two)+`]}`), admin, false)
	require.Equal(http.StatusOK, moved.Code, moved.Body.String())
	assert.Equal(http.StatusNotFound, performSessionRequest(t, f.srv, http.MethodGet, "/api/v1/messages/11", nil, withKey("alice-secret-value"), false).Code)
	assert.Equal(http.StatusOK, performSessionRequest(t, f.srv, http.MethodGet, "/api/v1/messages/22", nil, withKey("alice-secret-value"), false).Code,
		"a binding change reaches a live key immediately")

	unknown := performSessionRequest(t, f.srv, http.MethodPut, path+"/sources", []byte(`{"source_ids":[999]}`), admin, false)
	assert.Equal(http.StatusBadRequest, unknown.Code, unknown.Body.String())

	disabled := performSessionRequest(t, f.srv, http.MethodPatch, path, []byte(`{"disabled":true}`), admin, false)
	require.Equal(http.StatusOK, disabled.Code, disabled.Body.String())
	assert.Equal(http.StatusUnauthorized, performSessionRequest(t, f.srv, http.MethodGet, "/api/v1/me", nil, withKey("alice-secret-value"), false).Code,
		"a disabled user's key stops working")
	assert.Equal(http.StatusNotFound, performSessionRequest(t, f.srv, http.MethodPatch, "/api/v1/users/999", []byte(`{"disabled":true}`), admin, false).Code)
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

func identityHeader(subject, name string, role authz.Role) string {
	return authz.ActingIdentity{Issuer: "https://idp.example", Subject: subject, Name: name, Role: role}.HeaderValue()
}

func TestOnBehalfOfIdentityCreatesAndRefreshesTheUser(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newVisibilityFixture(t)
	me := func(headers http.Header) (int, PrincipalInfo) {
		resp := performSessionRequest(t, f.srv, http.MethodGet, "/api/v1/me", nil, headers, false)
		var principal PrincipalInfo
		if resp.Code == http.StatusOK {
			require.NoError(decodeJSONBody(resp, &principal))
		}
		return resp.Code, principal
	}
	asCarol := func(extra ...string) http.Header {
		return withKey("sidecar-secret-value", append([]string{authz.ActingUserHeader, "carol@example.com"}, extra...)...)
	}

	_, err := f.st.GetUserByEmail(t.Context(), "carol@example.com")
	require.ErrorIs(err, store.ErrUserNotFound)

	code, principal := me(asCarol(authz.ActingIdentityHeader, identityHeader("carol", "Carol Example", authz.RoleViewer)))
	require.Equal(http.StatusOK, code, "a trusted sidecar's assertion creates the user on first use")
	assert.Equal(PrincipalInfo{Kind: authz.PrincipalUser, Name: "Carol Example", Email: "carol@example.com", Role: authz.RoleViewer}, principal)
	carol, err := f.st.GetUserByEmail(t.Context(), "carol@example.com")
	require.NoError(err)
	assert.Equal("viewer", carol.Role)
	assert.Equal("Carol Example", carol.DisplayName)
	bound, err := f.st.GetUserByIdentity(t.Context(), "https://idp.example", "carol")
	require.NoError(err, "the provider account is bound like a browser sign-in")
	assert.Equal(carol.ID, bound.ID)
	assert.Equal(http.StatusNotFound, performSessionRequest(t, f.srv, http.MethodGet, "/api/v1/messages/11", nil,
		asCarol(authz.ActingIdentityHeader, identityHeader("carol", "Carol Example", authz.RoleViewer)), false).Code,
		"a new user sees no source until an administrator binds one")

	code, principal = me(asCarol(authz.ActingIdentityHeader, identityHeader("carol", "", authz.RoleMember)))
	require.Equal(http.StatusOK, code)
	assert.Equal(authz.RoleMember, principal.Role, "a role the provider changed is refreshed, as at a web sign-in")
	assert.Equal("Carol Example", principal.Name, "a provider that sends no name keeps the stored one")
	carol, err = f.st.GetUserByEmail(t.Context(), "carol@example.com")
	require.NoError(err)
	assert.Equal("member", carol.Role)
	assert.Equal("Carol Example", carol.DisplayName)

	code, principal = me(asCarol())
	require.Equal(http.StatusOK, code, "an older sidecar without the assertion still acts as an existing user")
	assert.Equal(authz.RoleMember, principal.Role)
}

func TestOnBehalfOfIdentityIsHonouredOnlyFromTrustedKeys(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newVisibilityFixture(t)
	get := func(headers http.Header) int {
		return performSessionRequest(t, f.srv, http.MethodGet, "/api/v1/me", nil, headers, false).Code
	}
	noUser := func(email string) {
		t.Helper()
		_, err := f.st.GetUserByEmail(t.Context(), email)
		assert.ErrorIs(err, store.ErrUserNotFound, "%s must not have been created", email)
	}

	assert.Equal(http.StatusUnauthorized, get(withKey("admin-secret-value",
		authz.ActingUserHeader, "dave@example.com", authz.ActingIdentityHeader, identityHeader("dave", "Dave", authz.RoleAdmin))),
		"the administrator key is not marked on_behalf_of, so its assertion is worthless")
	noUser("dave@example.com")

	assert.Equal(http.StatusUnauthorized, get(withKey("alice-secret-value",
		authz.ActingUserHeader, "dave@example.com", authz.ActingIdentityHeader, identityHeader("dave", "Dave", authz.RoleAdmin))),
		"a user-bound key cannot mint users either")
	noUser("dave@example.com")

	for name, value := range map[string]string{
		"malformed":   "not json",
		"no account":  `{"role":"viewer"}`,
		"bad role":    `{"issuer":"https://idp.example","subject":"erin","role":"owner"}`,
		"escalation?": `{"issuer":"https://idp.example","subject":"erin","role":"superuser"}`,
	} {
		assert.Equal(http.StatusUnauthorized, get(withKey("sidecar-secret-value",
			authz.ActingUserHeader, "erin@example.com", authz.ActingIdentityHeader, value)),
			"%s: an assertion the daemon cannot trust fails closed", name)
	}
	noUser("erin@example.com")

	assert.Equal(http.StatusUnauthorized, get(withKey("sidecar-secret-value", authz.ActingUserHeader, "erin@example.com")),
		"without an assertion an unknown user is still refused")
	noUser("erin@example.com")

	// A disabled user stays out, whatever role the sidecar asserts.
	require.NoError(f.st.SetUserDisabled(t.Context(), f.alice.ID, true))
	assert.Equal(http.StatusUnauthorized, get(withKey("sidecar-secret-value",
		authz.ActingUserHeader, "alice@example.com", authz.ActingIdentityHeader, identityHeader("alice", "Alice", authz.RoleAdmin))))
	assert.Equal(http.StatusUnauthorized, get(withKey("sidecar-secret-value", authz.ActingUserHeader, "alice@example.com")))
	alice, err := f.st.GetUserByEmail(t.Context(), "alice@example.com")
	require.NoError(err)
	assert.Equal("member", alice.Role, "a refused assertion changes nothing")
}

func TestOnBehalfOfIdentityConcurrentFirstUse(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newVisibilityFixture(t)
	const callers = 6
	codes := make([]int, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			codes[i] = performSessionRequest(t, f.srv, http.MethodGet, "/api/v1/me", nil, withKey("sidecar-secret-value",
				authz.ActingUserHeader, "frank@example.com", authz.ActingIdentityHeader, identityHeader("frank", "Frank", authz.RoleViewer)), false).Code
		})
	}
	wg.Wait()
	for i, code := range codes {
		assert.Equal(http.StatusOK, code, "caller %d", i)
	}
	users, err := f.st.ListUsers(t.Context())
	require.NoError(err)
	created := 0
	for _, user := range users {
		if user.Email == "frank@example.com" {
			created++
		}
	}
	assert.Equal(1, created, "parallel first requests create one user")
}
