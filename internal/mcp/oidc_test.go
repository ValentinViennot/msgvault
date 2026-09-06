package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/authn/oidc"
	"go.kenn.io/msgvault/internal/authn/oidc/oidctest"
	"go.kenn.io/msgvault/internal/query/querytest"
)

const mcpTestResource = "https://vault-mcp.example/mcp"

func newOIDCHandler(t *testing.T, idp *oidctest.Server, allowWrites bool) http.Handler {
	t.Helper()
	provider, err := oidc.New(oidc.Config{
		Issuer:            idp.Issuer(),
		Resource:          mcpTestResource,
		AdminGroups:       []string{"vault_admin"},
		ViewerGroups:      []string{"vault_viewer"},
		InsecureAllowHTTP: true,
	})
	require.NoError(t, err)
	opts := ServeOptions{Engine: &querytest.MockEngine{}, AttachmentsDir: t.TempDir()}
	return newMCPHTTPServer(opts, HTTPOptions{APIKey: "admin-secret-value", AllowWrites: allowWrites, OIDC: provider}).Handler
}

func TestProtectedResourceMetadata(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	idp := oidctest.New(t)
	handler := newOIDCHandler(t, idp, true)

	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(http.StatusOK, recorder.Code, path)
		assert.Equal("*", recorder.Header().Get("Access-Control-Allow-Origin"))
		var document map[string]any
		require.NoError(json.Unmarshal(recorder.Body.Bytes(), &document))
		assert.Equal(mcpTestResource, document["resource"])
		assert.Equal([]any{idp.Issuer()}, document["authorization_servers"])
		assert.Equal([]any{oidc.ScopeRead, oidc.ScopeWrite}, document["scopes_supported"])
	}

	unauthenticated := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	assert.Equal(http.StatusUnauthorized, unauthenticated.Code)
	assert.Equal(`Bearer resource_metadata="https://vault-mcp.example/.well-known/oauth-protected-resource/mcp", scope="msgvault:read"`,
		unauthenticated.Header().Get("WWW-Authenticate"))

	// Without a provider the listener keeps the bare challenge and no metadata.
	plain := newMCPHTTPServer(ServeOptions{Engine: &querytest.MockEngine{}}, HTTPOptions{APIKey: "admin-secret-value"}).Handler
	recorder := httptest.NewRecorder()
	plain.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	assert.Equal("Bearer", recorder.Header().Get("WWW-Authenticate"))
	recorder = httptest.NewRecorder()
	plain.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil))
	assert.Equal(http.StatusNotFound, recorder.Code)
}

func TestAccessTokensGateToolsByRoleAndScope(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	idp := oidctest.New(t)
	idp.AddUser(oidctest.User{Subject: "admin", Email: "admin@example.com", Groups: []string{"vault_admin"}})
	idp.AddUser(oidctest.User{Subject: "reader", Email: "reader@example.com", Groups: []string{"vault_viewer"}})
	idp.AddUser(oidctest.User{Subject: "outsider", Email: "outsider@example.com", Groups: []string{"unrelated"}})
	handler := newOIDCHandler(t, idp, true)
	mint := func(subject, audience string, scopes ...string) string {
		return idp.MintAccessToken(t, subject, audience, scopes, time.Hour)
	}

	names, status := rawAuthorizedToolNames(t, handler, "Bearer "+mint("admin", mcpTestResource, oidc.ScopeRead, oidc.ScopeWrite))
	require.Equal(http.StatusOK, status)
	assert.Contains(names, ToolStageDeletion, "an admin with the write scope gets the write tools")

	names, status = rawAuthorizedToolNames(t, handler, "Bearer "+mint("admin", mcpTestResource, oidc.ScopeRead))
	require.Equal(http.StatusOK, status)
	assert.Contains(names, ToolGetStats)
	assert.NotContains(names, ToolStageDeletion, "without the write scope even an admin only reads")

	names, status = rawAuthorizedToolNames(t, handler, "Bearer "+mint("reader", mcpTestResource, oidc.ScopeRead, oidc.ScopeWrite))
	require.Equal(http.StatusOK, status)
	assert.Contains(names, ToolGetStats)
	assert.NotContains(names, ToolStageDeletion, "the write scope does not lift the role")

	names, status = rawAuthorizedToolNames(t, handler, "Bearer admin-secret-value")
	require.Equal(http.StatusOK, status)
	assert.Contains(names, ToolStageDeletion, "the static administrator key still works beside the provider")

	_, status = rawAuthorizedToolNames(t, handler, "Bearer "+mint("admin", "https://other.example/mcp", oidc.ScopeRead))
	assert.Equal(http.StatusUnauthorized, status, "a token for another resource is refused")
	_, status = rawAuthorizedToolNames(t, handler, "Bearer "+mint("outsider", mcpTestResource, oidc.ScopeRead))
	assert.Equal(http.StatusUnauthorized, status, "a token without a role is refused")
	_, status = rawAuthorizedToolNames(t, handler, "Bearer "+idp.MintTokenSignedByStranger(t, "admin", mcpTestResource))
	assert.Equal(http.StatusUnauthorized, status)

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+mint("admin", mcpTestResource))
	handler.ServeHTTP(recorder, req)
	assert.Equal(http.StatusForbidden, recorder.Code, "a valid token without the read scope is forbidden, not unauthenticated")
	assert.Contains(recorder.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`)
}
