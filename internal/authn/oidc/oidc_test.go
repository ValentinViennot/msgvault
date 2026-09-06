package oidc_test

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.kenn.io/msgvault/internal/authn/oidc"
	"go.kenn.io/msgvault/internal/authn/oidc/oidctest"
	"go.kenn.io/msgvault/internal/authz"
)

const testResource = "https://vault.example/mcp"

func newProvider(t *testing.T, idp *oidctest.Server, mutate func(*oidc.Config)) *oidc.Provider {
	t.Helper()
	cfg := oidc.Config{
		Issuer:            idp.Issuer(),
		ClientID:          idp.ClientID,
		ClientSecret:      idp.ClientSecret,
		PublicURL:         "https://vault.example",
		Resource:          testResource,
		AdminGroups:       []string{"vault_admin"},
		MemberGroups:      []string{"vault_member"},
		ViewerGroups:      []string{"vault_viewer"},
		ProviderName:      "Test IdP",
		InsecureAllowHTTP: true,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	provider, err := oidc.New(cfg)
	require.NoError(t, err)
	return provider
}

// followAuthorize drives the browser half of the flow: it opens the
// authorization URL and captures the callback the provider redirects to.
func followAuthorize(t *testing.T, authURL string) url.Values {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(authURL)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	callback, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "https://vault.example/api/session/oidc/callback", callback.Scheme+"://"+callback.Host+callback.Path)
	return callback.Query()
}

func TestBrowserLoginRoundTrip(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	idp := oidctest.New(t)
	idp.ClientSecret = "web-client-secret"
	idp.AddUser(oidctest.User{Subject: "alice", Email: "alice@example.com", Name: "Alice", Groups: []string{"vault_member"}})
	provider := newProvider(t, idp, nil)

	login, err := provider.BeginLogin(t.Context())
	require.NoError(err)
	require.NotEmpty(login.State)
	require.NotEmpty(login.Binding)
	authURL, err := url.Parse(login.AuthURL)
	require.NoError(err)
	assert.Equal("S256", authURL.Query().Get("code_challenge_method"))
	assert.NotEmpty(authURL.Query().Get("nonce"))
	assert.Equal("https://vault.example/api/session/oidc/callback", authURL.Query().Get("redirect_uri"))
	assert.Contains(authURL.Query().Get("scope"), "openid")

	idp.SignInAs("alice")
	callback := followAuthorize(t, login.AuthURL)
	assert.Equal(login.State, callback.Get("state"))

	identity, err := provider.CompleteLogin(t.Context(), callback.Get("state"), login.Binding, callback.Get("code"))
	require.NoError(err)
	assert.Equal("alice", identity.Subject)
	assert.Equal("alice@example.com", identity.Email)
	assert.Equal("Alice", identity.Name)
	assert.Equal([]string{"vault_member"}, identity.Groups)
	assert.Equal(idp.Issuer(), identity.Issuer)

	principal, ok := provider.Principal(identity)
	require.True(ok)
	assert.Equal(authz.Principal{Kind: authz.PrincipalUser, Name: "Alice", Email: "alice@example.com", Role: authz.RoleMember}, principal)

	_, err = provider.CompleteLogin(t.Context(), callback.Get("state"), login.Binding, callback.Get("code"))
	assert.ErrorIs(err, oidc.ErrLoginExpired, "a login completes once")
}

func TestBrowserLoginRejectsForeignBrowserAndUnknownState(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	idp := oidctest.New(t)
	idp.AddUser(oidctest.User{Subject: "alice", Email: "alice@example.com", Groups: []string{"vault_viewer"}})
	provider := newProvider(t, idp, nil)

	login, err := provider.BeginLogin(t.Context())
	require.NoError(err)
	idp.SignInAs("alice")
	callback := followAuthorize(t, login.AuthURL)

	_, err = provider.CompleteLogin(t.Context(), callback.Get("state"), "another-browser", callback.Get("code"))
	assert.ErrorIs(err, oidc.ErrLoginBinding)
	_, err = provider.CompleteLogin(t.Context(), "never-issued", login.Binding, callback.Get("code"))
	assert.ErrorIs(err, oidc.ErrLoginExpired)
}

func TestBrowserLoginFallsBackToUserInfoForGroups(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	idp := oidctest.New(t)
	idp.AddUser(oidctest.User{Subject: "bob", Email: "bob@example.com", Groups: []string{"vault_admin"}, OmitGroupsFromTokens: true})
	provider := newProvider(t, idp, nil)

	login, err := provider.BeginLogin(t.Context())
	require.NoError(err)
	idp.SignInAs("bob")
	callback := followAuthorize(t, login.AuthURL)
	identity, err := provider.CompleteLogin(t.Context(), callback.Get("state"), login.Binding, callback.Get("code"))
	require.NoError(err)
	assert.Equal([]string{"vault_admin"}, identity.Groups)
	role, ok := provider.RoleFor(identity)
	require.True(ok)
	assert.Equal(authz.RoleAdmin, role)
}

func TestVerifyAccessToken(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	idp := oidctest.New(t)
	idp.AddUser(oidctest.User{Subject: "carol", Email: "carol@example.com", Name: "Carol", Groups: []string{"vault_viewer"}})
	idp.AddUser(oidctest.User{Subject: "dave", Email: "dave@example.com", Groups: []string{"vault_member"}, OmitGroupsFromTokens: true})
	provider := newProvider(t, idp, nil)

	token := idp.MintAccessToken(t, "carol", testResource, []string{"msgvault:read", "msgvault:write"}, time.Hour)
	identity, err := provider.VerifyAccessToken(t.Context(), token)
	require.NoError(err)
	assert.Equal("carol@example.com", identity.Email)
	assert.True(identity.HasScope(oidc.ScopeWrite))
	assert.True(identity.HasScope(oidc.ScopeRead))
	assert.Equal([]string{"vault_viewer"}, identity.Groups)

	_, err = provider.VerifyAccessToken(t.Context(), idp.MintAccessToken(t, "carol", "https://other.example/api", nil, time.Hour))
	require.Error(err, "a token minted for another resource is refused")
	_, err = provider.VerifyAccessToken(t.Context(), idp.MintTokenSignedByStranger(t, "carol", testResource))
	require.Error(err, "a token signed by an unknown key is refused")
	_, err = provider.VerifyAccessToken(t.Context(), idp.MintAccessToken(t, "carol", testResource, nil, -time.Minute))
	require.Error(err, "an expired token is refused")

	viaUserInfo, err := provider.VerifyAccessToken(t.Context(), idp.MintAccessToken(t, "dave", testResource, []string{"msgvault:read"}, time.Hour))
	require.NoError(err)
	assert.Equal([]string{"vault_member"}, viaUserInfo.Groups, "groups absent from the token come from userinfo")
	assert.False(viaUserInfo.HasScope(oidc.ScopeWrite))
}

func TestRoleMapping(t *testing.T) {
	assert := assert.New(t)
	idp := oidctest.New(t)
	provider := newProvider(t, idp, func(cfg *oidc.Config) {
		cfg.AllowedEmails = []string{"Guest@Example.com"}
	})
	role, ok := provider.RoleFor(oidc.Identity{Groups: []string{"vault_viewer", "vault_admin"}})
	assert.True(ok)
	assert.Equal(authz.RoleAdmin, role, "the most privileged group wins")
	role, ok = provider.RoleFor(oidc.Identity{Groups: []string{"unrelated"}, Email: "guest@example.com"})
	assert.True(ok)
	assert.Equal(authz.RoleViewer, role, "an allowed email is a viewer")
	_, ok = provider.RoleFor(oidc.Identity{Groups: []string{"unrelated"}, Email: "stranger@example.com"})
	assert.False(ok)
	_, ok = provider.Principal(oidc.Identity{})
	assert.False(ok)
}

func TestConfigValidation(t *testing.T) {
	assert := assert.New(t)
	base := oidc.Config{Issuer: "https://idp.example", ClientID: "c", PublicURL: "https://vault.example", AdminGroups: []string{"a"}}
	assert.NoError(base.Validate())

	cases := map[string]func(*oidc.Config){
		"http issuer":       func(c *oidc.Config) { c.Issuer = "http://idp.example" },
		"relative issuer":   func(c *oidc.Config) { c.Issuer = "idp.example" },
		"no client for web": func(c *oidc.Config) { c.ClientID = "" },
		"nothing enabled":   func(c *oidc.Config) { c.PublicURL = ""; c.Resource = "" },
		"nobody admitted":   func(c *oidc.Config) { c.AdminGroups = nil },
		"bad resource":      func(c *oidc.Config) { c.Resource = "vault.example/mcp" },
		"resource fragment": func(c *oidc.Config) { c.Resource = "https://vault.example/mcp#x" },
	}
	for name, mutate := range cases {
		cfg := base
		mutate(&cfg)
		assert.Error(cfg.Validate(), name)
	}
	_, err := oidc.New(oidc.Config{Issuer: "https://idp.example", Resource: "https://vault.example/mcp", ViewerGroups: []string{"v"}})
	assert.NoError(err, "bearer-only configuration needs no client")
}
