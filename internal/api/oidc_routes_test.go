package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/authn/oidc"
	"go.kenn.io/msgvault/internal/authn/oidc/oidctest"
	"go.kenn.io/msgvault/internal/authz"
	"go.kenn.io/msgvault/internal/config"
	"go.kenn.io/msgvault/internal/testutil"
)

const oidcTestResource = "https://vault.example"

func newOIDCTestServer(t *testing.T, idp *oidctest.Server, userStore UserStore) *Server {
	t.Helper()
	provider, err := oidc.New(oidc.Config{
		Issuer:            idp.Issuer(),
		ClientID:          idp.ClientID,
		ClientSecret:      idp.ClientSecret,
		PublicURL:         "https://vault.example",
		Resource:          oidcTestResource,
		AdminGroups:       []string{"vault_admin"},
		MemberGroups:      []string{"vault_member"},
		ViewerGroups:      []string{"vault_viewer"},
		ProviderName:      "Test IdP",
		InsecureAllowHTTP: true,
	})
	require.NoError(t, err)
	srv := NewServerWithOptions(ServerOptions{
		Config:    &config.Config{Server: config.ServerConfig{APIKey: testSessionAPIKey}},
		OIDC:      provider,
		UserStore: userStore,
		Logger:    testLogger(),
	})
	t.Cleanup(func() {
		require.NoError(t, srv.Shutdown(context.Background()))
	})
	return srv
}

// browserLogin drives start → provider → callback for the signed-in subject
// and returns the callback response.
func browserLogin(t *testing.T, srv *Server, idp *oidctest.Server, subject string, cookieBinding func(string) string) (int, http.Header) {
	t.Helper()
	require := require.New(t)
	start := performSessionRequest(t, srv, http.MethodGet, sessionOIDCStartPath, nil, nil, true)
	require.Equal(http.StatusFound, start.Code, start.Body.String())
	var binding string
	for _, cookie := range start.Result().Cookies() {
		if cookie.Name == oidcLoginCookieName {
			binding = cookie.Value
			assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
			assert.True(t, cookie.HttpOnly)
			assert.True(t, cookie.Secure)
		}
	}
	require.NotEmpty(binding, "the start response binds the browser")

	idp.SignInAs(subject)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(start.Header().Get("Location"))
	require.NoError(err)
	_ = resp.Body.Close()
	require.Equal(http.StatusFound, resp.StatusCode)
	callback, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(err)
	require.Equal(sessionOIDCCallbackPath, callback.Path)

	if cookieBinding != nil {
		binding = cookieBinding(binding)
	}
	headers := http.Header{}
	if binding != "" {
		headers.Set("Cookie", oidcLoginCookieName+"="+binding)
	}
	done := performSessionRequest(t, srv, http.MethodGet, callback.Path+"?"+callback.RawQuery, nil, headers, true)
	return done.Code, done.Header()
}

func sessionCookieFrom(t *testing.T, headers http.Header) string {
	t.Helper()
	for _, line := range headers.Values("Set-Cookie") {
		if strings.HasPrefix(line, sessionCookieName+"=") {
			return strings.SplitN(strings.SplitN(line, ";", 2)[0], "=", 2)[1]
		}
	}
	require.FailNow(t, "session cookie not set", "%v", headers)
	return ""
}

func TestOIDCBrowserLoginCreatesSession(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	idp := oidctest.New(t)
	idp.ClientSecret = "web-secret"
	idp.AddUser(oidctest.User{Subject: "alice", Email: "Alice@Example.com", Name: "Alice", Groups: []string{"vault_member"}})
	st := testutil.NewTestStore(t)
	srv := newOIDCTestServer(t, idp, st)

	bootstrap := decodeSessionStatus(t, performSessionRequest(t, srv, http.MethodGet, sessionPath, nil, nil, true))
	assert.Equal(AuthModeRequired, bootstrap.AuthMode)
	assert.Equal([]string{"api_key", "oidc"}, bootstrap.LoginMethods)
	require.NotNil(bootstrap.OIDC)
	assert.Equal(OIDCLoginInfo{ProviderName: "Test IdP", StartURL: sessionOIDCStartPath}, *bootstrap.OIDC)

	status, headers := browserLogin(t, srv, idp, "alice", nil)
	require.Equal(http.StatusFound, status)
	assert.Equal("/", headers.Get("Location"))
	cookie := sessionCookieFrom(t, headers)

	me := performSessionRequest(t, srv, http.MethodGet, "/api/v1/me", nil, http.Header{"Cookie": []string{sessionCookieName + "=" + cookie}}, true)
	require.Equal(http.StatusOK, me.Code, me.Body.String())
	var principal PrincipalInfo
	require.NoError(decodeJSONBody(me, &principal))
	assert.Equal(PrincipalInfo{Kind: authz.PrincipalUser, Name: "Alice", Email: "alice@example.com", Role: authz.RoleMember}, principal)

	users, err := st.ListUsers(t.Context())
	require.NoError(err)
	require.Len(users, 1)
	assert.Equal("member", users[0].Role)
}

func TestOIDCBrowserLoginRefusals(t *testing.T) {
	assert := assert.New(t)
	idp := oidctest.New(t)
	idp.AddUser(oidctest.User{Subject: "alice", Email: "alice@example.com", Groups: []string{"vault_member"}})
	idp.AddUser(oidctest.User{Subject: "mallory", Email: "mallory@example.com", Groups: []string{"unrelated"}})
	idp.AddUser(oidctest.User{Subject: "dave", Email: "dave@example.com", Groups: []string{"vault_viewer"}})
	st := testutil.NewTestStore(t)
	srv := newOIDCTestServer(t, idp, st)

	status, _ := browserLogin(t, srv, idp, "alice", func(string) string { return "another-browser" })
	assert.Equal(http.StatusBadRequest, status, "a callback from another browser is refused")
	status, _ = browserLogin(t, srv, idp, "alice", func(string) string { return "" })
	assert.Equal(http.StatusBadRequest, status, "a callback without the binding cookie is refused")
	status, _ = browserLogin(t, srv, idp, "mallory", nil)
	assert.Equal(http.StatusForbidden, status, "no matching group means no session")

	status, _ = browserLogin(t, srv, idp, "dave", nil)
	assert.Equal(http.StatusFound, status)
	users, err := st.ListUsers(t.Context())
	require.NoError(t, err)
	for _, user := range users {
		if user.Email == "dave@example.com" {
			require.NoError(t, st.SetUserDisabled(t.Context(), user.ID, true))
		}
	}
	status, _ = browserLogin(t, srv, idp, "dave", nil)
	assert.Equal(http.StatusForbidden, status, "a disabled user cannot sign in")

	callback := performSessionRequest(t, srv, http.MethodGet, sessionOIDCCallbackPath+"?error=access_denied&error_description=<script>", nil, nil, true)
	assert.Equal(http.StatusBadRequest, callback.Code)
	assert.Contains(callback.Header().Get("Content-Type"), "text/html")
	assert.NotContains(callback.Body.String(), "<script>")

	plain := NewServer(&config.Config{Server: config.ServerConfig{APIKey: testSessionAPIKey}}, nil, nil, testLogger())
	t.Cleanup(func() { _ = plain.Shutdown(context.Background()) })
	assert.Equal(http.StatusNotFound, performSessionRequest(t, plain, http.MethodGet, sessionOIDCStartPath, nil, nil, true).Code)
	assert.Nil(decodeSessionStatus(t, performSessionRequest(t, plain, http.MethodGet, sessionPath, nil, nil, true)).OIDC)
}

func TestOIDCAccessTokensAuthenticateAPIRequests(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	idp := oidctest.New(t)
	idp.AddUser(oidctest.User{Subject: "carol", Email: "carol@example.com", Name: "Carol", Groups: []string{"vault_admin"}})
	idp.AddUser(oidctest.User{Subject: "mallory", Email: "mallory@example.com", Groups: []string{"unrelated"}})
	srv := newOIDCTestServer(t, idp, nil)
	bearer := func(token string) http.Header { return http.Header{"Authorization": []string{"Bearer " + token}} }

	readOnly := idp.MintAccessToken(t, "carol", oidcTestResource, []string{oidc.ScopeRead}, time.Hour)
	me := performSessionRequest(t, srv, http.MethodGet, "/api/v1/me", nil, bearer(readOnly), true)
	require.Equal(http.StatusOK, me.Code, me.Body.String())
	var principal PrincipalInfo
	require.NoError(decodeJSONBody(me, &principal))
	assert.Equal(PrincipalInfo{Kind: authz.PrincipalUser, Name: "Carol", Email: "carol@example.com", Role: authz.RoleAdmin}, principal)
	bootstrap := decodeSessionStatus(t, performSessionRequest(t, srv, http.MethodGet, sessionPath, nil, bearer(readOnly), true))
	assert.Equal(AuthModeToken, bootstrap.AuthMode)

	denied := performSessionRequest(t, srv, http.MethodPost, "/api/v1/saved-views", []byte(`{}`), bearer(readOnly), true)
	assert.Equal(http.StatusForbidden, denied.Code, denied.Body.String())
	assert.Contains(denied.Body.String(), "insufficient_scope")
	assert.Equal(insufficientScopeChallenge, denied.Header().Get("WWW-Authenticate"))

	writable := idp.MintAccessToken(t, "carol", oidcTestResource, []string{oidc.ScopeRead, oidc.ScopeWrite}, time.Hour)
	allowed := performSessionRequest(t, srv, http.MethodPost, "/api/v1/saved-views", []byte(`{}`), bearer(writable), true)
	assert.NotEqual(http.StatusForbidden, allowed.Code, allowed.Body.String())
	assert.NotEqual(http.StatusUnauthorized, allowed.Code, allowed.Body.String())

	for name, token := range map[string]string{
		"wrong audience": idp.MintAccessToken(t, "carol", "https://other.example", []string{oidc.ScopeRead}, time.Hour),
		"no read scope":  idp.MintAccessToken(t, "carol", oidcTestResource, nil, time.Hour),
		"no role":        idp.MintAccessToken(t, "mallory", oidcTestResource, []string{oidc.ScopeRead}, time.Hour),
		"stranger key":   idp.MintTokenSignedByStranger(t, "carol", oidcTestResource),
		"not a token":    "definitely.not.a-jwt",
	} {
		resp := performSessionRequest(t, srv, http.MethodGet, "/api/v1/me", nil, bearer(token), true)
		assert.Equal(http.StatusUnauthorized, resp.Code, name)
	}
}
