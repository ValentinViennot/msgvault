package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/authz"
	"go.kenn.io/msgvault/internal/query/querytest"
)

func rawAuthorizedToolNames(t *testing.T, handler http.Handler, authorization string) ([]string, int) {
	t.Helper()
	params := map[string]any{"_meta": modernRequestMeta()}
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": params})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", modernProtocolVersion)
	req.Header.Set("Mcp-Method", "tools/list")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		return nil, recorder.Code
	}
	var response rawRPCResponse
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &response), recorder.Body.String())
	require.Empty(t, response.Error, recorder.Body.String())
	tools, ok := response.Result["tools"].([]any)
	require.True(t, ok, "tools/list result: %#v", response.Result)
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		entry, ok := tool.(map[string]any)
		require.True(t, ok)
		names = append(names, entry["name"].(string))
	}
	return names, recorder.Code
}

func TestHTTPNamedKeysGateToolsByRole(t *testing.T) {
	opts := ServeOptions{Engine: &querytest.MockEngine{}, AttachmentsDir: t.TempDir()}
	handler := newMCPHTTPServer(opts, HTTPOptions{
		APIKey:      "admin-secret-value",
		AllowWrites: true,
		Keys: []NamedKey{
			{Name: "reader", Key: "reader-secret-value", Role: authz.RoleViewer},
			{Name: "curator", Key: "curator-secret-value", Role: authz.RoleMember},
		},
	}).Handler

	_, status := rawAuthorizedToolNames(t, handler, "")
	assert.Equal(t, http.StatusUnauthorized, status)
	_, status = rawAuthorizedToolNames(t, handler, "Bearer unknown-secret-value")
	assert.Equal(t, http.StatusUnauthorized, status)

	admin, status := rawAuthorizedToolNames(t, handler, "Bearer admin-secret-value")
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, admin, ToolStageDeletion)
	assert.Contains(t, admin, ToolExportAttachment)
	assert.Contains(t, admin, ToolGetStats)

	for _, key := range []string{"reader-secret-value", "curator-secret-value"} {
		names, status := rawAuthorizedToolNames(t, handler, "Bearer "+key)
		require.Equal(t, http.StatusOK, status)
		assert.Contains(t, names, ToolGetStats, key)
		assert.Contains(t, names, ToolSearchMetadata, key)
		assert.NotContains(t, names, ToolStageDeletion, "%s must not stage deletions", key)
		assert.NotContains(t, names, ToolExportAttachment, "%s must not write to the server filesystem", key)
	}
}

func TestOpenListenerAndStdioServeTheAdministrator(t *testing.T) {
	opts := ServeOptions{Engine: &querytest.MockEngine{}, AttachmentsDir: t.TempDir()}
	handler := newMCPHTTPServer(opts, HTTPOptions{AllowWrites: true}).Handler
	names, status := rawAuthorizedToolNames(t, handler, "")
	require.Equal(t, http.StatusOK, status)
	assert.Contains(t, names, ToolStageDeletion, "a listener without credentials keeps today's behaviour")
	assert.Equal(t, authz.ServerKey(), principalFromContext(t.Context()))
}
