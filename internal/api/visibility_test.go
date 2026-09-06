package api

import (
	"context"
	"net/http"
	"strconv"
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
