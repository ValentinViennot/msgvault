package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/api"
	"go.kenn.io/msgvault/internal/authn/oidc"
	"go.kenn.io/msgvault/internal/authn/oidc/oidctest"
	"go.kenn.io/msgvault/internal/authz"
	"go.kenn.io/msgvault/internal/config"
	"go.kenn.io/msgvault/internal/daemonclient"
	"go.kenn.io/msgvault/internal/query/querytest"
	"go.kenn.io/msgvault/internal/store"
	"go.kenn.io/msgvault/internal/testutil"
)

// rawAuthorizedCall performs one JSON-RPC request against the listener with
// the given Authorization header and returns the decoded response.
func rawAuthorizedCall(t *testing.T, handler http.Handler, authorization, method string, params map[string]any) (rawRPCResponse, int) {
	t.Helper()
	params["_meta"] = modernRequestMeta()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", modernProtocolVersion)
	req.Header.Set("Mcp-Method", method)
	if name, _ := params["name"].(string); name != "" {
		req.Header.Set("Mcp-Name", name)
	} else if uri, _ := params["uri"].(string); uri != "" {
		req.Header.Set("Mcp-Name", uri)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	var response rawRPCResponse
	if recorder.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response), recorder.Body.String())
	}
	return response, recorder.Code
}

// toolResultText returns the IsError flag and first text block of a
// tools/call result.
func toolResultText(t *testing.T, result map[string]any) (bool, string) {
	t.Helper()
	isError, _ := result["isError"].(bool)
	content, _ := result["content"].([]any)
	require.NotEmpty(t, content, "result: %#v", result)
	first, ok := content[0].(map[string]any)
	require.True(t, ok)
	text, _ := first["text"].(string)
	return isError, text
}

func newTestOIDCProvider(t *testing.T, idp *oidctest.Server) *oidc.Provider {
	t.Helper()
	provider, err := oidc.New(oidc.Config{
		Issuer:            idp.Issuer(),
		Resource:          mcpTestResource,
		AdminGroups:       []string{"vault_admin"},
		MemberGroups:      []string{"vault_member"},
		ViewerGroups:      []string{"vault_viewer"},
		InsecureAllowHTTP: true,
	})
	require.NoError(t, err)
	return provider
}

func TestBearerAuthHandlerForwardsTheVerifiedIdentity(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	idp := oidctest.New(t)
	idp.AddUser(oidctest.User{Subject: "alice", Email: "alice@example.com", Name: "Alice Example", Groups: []string{"vault_member"}})
	provider := newTestOIDCProvider(t, idp)

	type seen struct {
		acting   string
		identity *authz.ActingIdentity
	}
	var calls []seen
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := seen{acting: authz.ActingUser(r.Context())}
		if identity, ok := authz.ActingIdentityFromContext(r.Context()); ok {
			call.identity = &identity
		}
		calls = append(calls, call)
		w.WriteHeader(http.StatusNoContent)
	})
	keys := []NamedKey{{Name: "bob-key", Key: "bob-secret-value", Role: authz.RoleViewer, User: "bob@example.com"}}
	handler := bearerAuthHandler("admin-secret-value", keys, provider, next)
	for _, authorization := range []string{
		"Bearer " + idp.MintAccessToken(t, "alice", mcpTestResource, []string{oidc.ScopeRead}, time.Hour),
		"Bearer bob-secret-value",
		"Bearer admin-secret-value",
	} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", authorization)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		require.Equal(http.StatusNoContent, recorder.Code, authorization)
	}
	require.Len(calls, 3)

	assert.Equal("alice@example.com", calls[0].acting)
	require.NotNil(calls[0].identity, "a verified token carries the identity the daemon may record")
	assert.Equal(authz.ActingIdentity{Issuer: idp.Issuer(), Subject: "alice", Name: "Alice Example", Role: authz.RoleMember}, *calls[0].identity)
	assert.Equal("bob@example.com", calls[1].acting)
	assert.Nil(calls[1].identity, "a key bound to a user verified nobody, so it asserts no identity")
	assert.Empty(calls[2].acting)
	assert.Nil(calls[2].identity)
}

func TestDaemonRefusalOfTheActingUserTellsThePersonToSignIn(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	// A daemon that does not know the person answers every request the way
	// the real one does for an acting user it cannot resolve.
	daemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized","message":"Invalid or missing API key"}`))
	}))
	t.Cleanup(daemon.Close)
	client, err := daemonclient.New(daemonclient.Config{URL: daemon.URL, APIKey: "sidecar-secret-value", AllowInsecure: true, HTTPClient: daemon.Client()})
	require.NoError(err)
	opts := ServeOptions{Engine: daemonclient.NewEngineAdapter(client), AttachmentReader: client, AttachmentsDir: t.TempDir()}
	handler := newMCPHTTPServer(opts, HTTPOptions{
		APIKey: "admin-secret-value",
		Keys:   []NamedKey{{Name: "alice-key", Key: "alice-secret-value", Role: authz.RoleViewer, User: "alice@example.com"}},
	}).Handler

	response, status := rawAuthorizedCall(t, handler, "Bearer alice-secret-value", "tools/call",
		map[string]any{"name": ToolListMessages, "arguments": map[string]any{}})
	require.Equal(http.StatusOK, status)
	require.Empty(response.Error, "the refusal is a tool result, not a JSON-RPC error")
	isError, text := toolResultText(t, response.Result)
	assert.True(isError)
	assert.Contains(text, "acting_user_refused")
	assert.Contains(text, "alice@example.com")
	assert.Contains(text, "Sign in to the msgvault web UI once")

	response, status = rawAuthorizedCall(t, handler, "Bearer admin-secret-value", "tools/call",
		map[string]any{"name": ToolListMessages, "arguments": map[string]any{}})
	require.Equal(http.StatusOK, status)
	require.NotEmpty(response.Error, "without an acting user the daemon's refusal stays an internal error")
	assert.InDelta(float64(jsonrpc.CodeInternalError), response.Error["code"], 0)
	assert.Equal("internal server error", response.Error["message"])

	response, status = rawAuthorizedCall(t, handler, "Bearer alice-secret-value", "resources/read",
		map[string]any{"uri": "msgvault://attachment/7"})
	require.Equal(http.StatusOK, status)
	require.NotEmpty(response.Error)
	assert.InDelta(float64(actingUserRefusedErrorCode), response.Error["code"], 0)
	assert.Contains(response.Error["message"], "Sign in to the msgvault web UI once")
}

// newDaemonForSidecar starts a real daemon with a real user store. The
// sidecar key may act on behalf of users; the plain key may not.
func newDaemonForSidecar(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	st := testutil.NewTestStore(t)
	cfg := &config.Config{
		Server: config.ServerConfig{APIKey: "admin-secret-value"},
		Auth: config.AuthConfig{APIKeys: []config.APIKeyConfig{
			{Name: "sidecar", Key: "sidecar-secret-value", Role: "admin", OnBehalfOf: true},
			{Name: "plain", Key: "plain-secret-value", Role: "admin"},
		}},
	}
	srv := api.NewServerWithOptions(api.ServerOptions{
		Config: cfg, Engine: &querytest.MockEngine{}, UserStore: st,
		Logger: slog.New(slog.DiscardHandler),
	})
	t.Cleanup(func() { require.NoError(t, srv.Shutdown(context.Background())) })
	daemon := httptest.NewServer(srv.Router())
	t.Cleanup(daemon.Close)
	return daemon, st
}

func TestSidecarProvisionsTheVerifiedUserAtTheDaemon(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	idp := oidctest.New(t)
	idp.AddUser(oidctest.User{Subject: "alice", Email: "alice@example.com", Name: "Alice Example", Groups: []string{"vault_viewer"}})
	provider := newTestOIDCProvider(t, idp)
	daemon, st := newDaemonForSidecar(t)
	token := "Bearer " + idp.MintAccessToken(t, "alice", mcpTestResource, []string{oidc.ScopeRead}, time.Hour)

	sidecar := func(daemonKey string) http.Handler {
		client, err := daemonclient.New(daemonclient.Config{URL: daemon.URL, APIKey: daemonKey, AllowInsecure: true, HTTPClient: daemon.Client()})
		require.NoError(err)
		opts := ServeOptions{Engine: daemonclient.NewEngineAdapter(client), AttachmentsDir: t.TempDir()}
		return newMCPHTTPServer(opts, HTTPOptions{APIKey: "admin-secret-value", OIDC: provider}).Handler
	}

	_, err := st.GetUserByEmail(t.Context(), "alice@example.com")
	require.Error(err, "the daemon has never seen Alice")

	response, status := rawAuthorizedCall(t, sidecar("sidecar-secret-value"), token, "tools/call",
		map[string]any{"name": ToolListMessages, "arguments": map[string]any{}})
	require.Equal(http.StatusOK, status)
	require.Empty(response.Error, "response: %#v", response)
	isError, text := toolResultText(t, response.Result)
	assert.False(isError, "the first MCP call succeeds without a prior web sign-in: %s", text)

	user, err := st.GetUserByEmail(t.Context(), "alice@example.com")
	require.NoError(err, "the daemon created the user from the sidecar's assertion")
	assert.Equal("viewer", user.Role, "the role the sidecar derived from the provider's groups")
	assert.Equal("Alice Example", user.DisplayName)
	assert.NotNil(user.LastLoginAt)
	bound, err := st.GetUserByIdentity(t.Context(), idp.Issuer(), "alice")
	require.NoError(err, "the identity-provider account is bound, so a later web sign-in matches the same user")
	assert.Equal(user.ID, bound.ID)

	// A sidecar whose daemon key may not act on behalf of users still gets a
	// refusal, and the person a clear instruction instead of an internal error.
	response, status = rawAuthorizedCall(t, sidecar("plain-secret-value"), token, "tools/call",
		map[string]any{"name": ToolListMessages, "arguments": map[string]any{}})
	require.Equal(http.StatusOK, status)
	require.Empty(response.Error)
	isError, text = toolResultText(t, response.Result)
	assert.True(isError)
	assert.Contains(text, "Sign in to the msgvault web UI once")
	assert.Contains(text, "on_behalf_of")
}
