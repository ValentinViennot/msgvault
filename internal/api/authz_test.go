package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/authz"
	"go.kenn.io/msgvault/internal/config"
)

func pathOperations(item *huma.PathItem) map[string]*huma.Operation {
	return map[string]*huma.Operation{
		http.MethodGet:    item.Get,
		http.MethodHead:   item.Head,
		http.MethodPost:   item.Post,
		http.MethodPut:    item.Put,
		http.MethodPatch:  item.Patch,
		http.MethodDelete: item.Delete,
	}
}

// TestEveryAPIV1OperationIsClassified pins the authorization policy to the
// routes the daemon actually registers: a new /api/v1 operation must be given
// a role, and a stale policy entry must be removed.
func TestEveryAPIV1OperationIsClassified(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	doc := OpenAPIDocument()
	seen := make(map[string]bool)
	for path, item := range doc.Paths {
		for method, op := range pathOperations(item) {
			if op == nil {
				continue
			}
			require.NotEmpty(op.OperationID, "%s %s has no operation ID", method, path)
			if !strings.HasPrefix(path, "/api/v1/") {
				_, classified := operationMinimumRole[op.OperationID]
				assert.False(classified, "%s %s is public and must not carry a role", method, path)
				continue
			}
			_, classified := operationMinimumRole[op.OperationID]
			assert.True(classified, "%s %s (%s) has no entry in operationMinimumRole", method, path, op.OperationID)
			seen[op.OperationID] = true
		}
	}
	for id := range operationMinimumRole {
		assert.True(seen[id], "policy entry %q matches no registered /api/v1 operation", id)
	}
	assert.Equal(authz.RoleAdmin, minimumRoleForOperation(&huma.Operation{OperationID: "unknownOperation"}),
		"an unclassified operation fails closed")
	assert.Equal(authz.RoleAdmin, minimumRoleForOperation(nil))
}

func newRoleTestServer(t *testing.T) *Server {
	t.Helper()
	cfg := &config.Config{
		Server: config.ServerConfig{APIKey: "admin-secret-value"},
		Auth: config.AuthConfig{APIKeys: []config.APIKeyConfig{
			{Name: "reader", Key: "reader-secret-value", Role: string(authz.RoleViewer)},
			{Name: "curator", Key: "curator-secret-value", Role: string(authz.RoleMember)},
		}},
	}
	srv := NewServer(cfg, nil, nil, testLogger())
	t.Cleanup(func() {
		require.NoError(t, srv.Shutdown(context.Background()))
	})
	return srv
}

func TestRolePolicyOverHTTP(t *testing.T) {
	srv := newRoleTestServer(t)
	bearer := func(key string) http.Header {
		return http.Header{"Authorization": []string{"Bearer " + key}}
	}

	t.Run("me reports the caller", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)
		for key, want := range map[string]PrincipalInfo{
			"admin-secret-value":   {Kind: authz.PrincipalAPIKey, Name: "server", Role: authz.RoleAdmin},
			"reader-secret-value":  {Kind: authz.PrincipalAPIKey, Name: "reader", Role: authz.RoleViewer},
			"curator-secret-value": {Kind: authz.PrincipalAPIKey, Name: "curator", Role: authz.RoleMember},
		} {
			resp := performSessionRequest(t, srv, http.MethodGet, "/api/v1/me", nil, bearer(key), false)
			require.Equal(http.StatusOK, resp.Code, resp.Body.String())
			var got PrincipalInfo
			require.NoError(decodeJSONBody(resp, &got))
			assert.Equal(want, got)
		}
		resp := performSessionRequest(t, srv, http.MethodGet, "/api/v1/me", nil, nil, false)
		assert.Equal(http.StatusUnauthorized, resp.Code)
		resp = performSessionRequest(t, srv, http.MethodGet, "/api/v1/me", nil, bearer("unknown"), false)
		assert.Equal(http.StatusUnauthorized, resp.Code)
	})

	tests := []struct {
		name          string
		key           string
		method, path  string
		wantForbidden bool
	}{
		{"viewer may read", "reader-secret-value", http.MethodGet, "/api/v1/me", false},
		{"viewer may not curate", "reader-secret-value", http.MethodPost, "/api/v1/saved-views", true},
		{"viewer may not run SQL", "reader-secret-value", http.MethodPost, "/api/v1/query", true},
		{"viewer may not change settings", "reader-secret-value", http.MethodPatch, "/api/v1/settings", true},
		{"member may curate", "curator-secret-value", http.MethodPost, "/api/v1/saved-views", false},
		{"member may not run SQL", "curator-secret-value", http.MethodPost, "/api/v1/query", true},
		{"member may not stage deletions", "curator-secret-value", http.MethodPost, "/api/v1/deletions", true},
		{"admin may run SQL", "admin-secret-value", http.MethodPost, "/api/v1/query", false},
		{"admin may change settings", "admin-secret-value", http.MethodPatch, "/api/v1/settings", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			resp := performSessionRequest(t, srv, tt.method, tt.path, []byte(`{}`), bearer(tt.key), false)
			if tt.wantForbidden {
				assert.Equal(http.StatusForbidden, resp.Code, resp.Body.String())
				assert.Contains(resp.Body.String(), `"forbidden"`)
				return
			}
			// The handler may reject the placeholder body or lack a backing
			// store in this fixture; the policy itself must not refuse.
			assert.NotEqual(http.StatusForbidden, resp.Code, resp.Body.String())
			assert.NotEqual(http.StatusUnauthorized, resp.Code, resp.Body.String())
		})
	}
}

func TestNamedKeyCollidingWithServerKeyIsIgnored(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	cfg := &config.Config{
		Server: config.ServerConfig{APIKey: "shared-secret-value"},
		Auth: config.AuthConfig{APIKeys: []config.APIKeyConfig{
			{Name: "reader", Key: "shared-secret-value", Role: string(authz.RoleViewer)},
			{Name: "first", Key: "same-secret-value", Role: string(authz.RoleViewer)},
			{Name: "second", Key: "same-secret-value", Role: string(authz.RoleMember)},
		}},
	}
	srv := NewServer(cfg, nil, nil, testLogger())
	t.Cleanup(func() {
		require.NoError(srv.Shutdown(context.Background()))
	})
	principal, ok := srv.principalForAPIKey("shared-secret-value")
	require.True(ok)
	assert.Equal(authz.RoleAdmin, principal.Role, "the server key keeps its privilege")
	principal, ok = srv.principalForAPIKey("same-secret-value")
	require.True(ok)
	assert.Equal("first", principal.Name, "the first definition of a duplicated secret wins")
	assert.Equal(authz.RoleViewer, principal.Role)
}

func decodeJSONBody(resp *httptest.ResponseRecorder, target any) error {
	return json.NewDecoder(resp.Body).Decode(target)
}
