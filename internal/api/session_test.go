package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/authz"
	"go.kenn.io/msgvault/internal/config"
)

const testSessionAPIKey = "test-session-api-key"

func TestSessionStoreCreatesOpaqueExpiringSessions(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)
	now := time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
	store := newSessionStore(time.Hour)
	store.now = func() time.Time { return now }

	id, session, err := store.create(authz.ServerKey())
	requirements.NoError(err)
	requirements.NotEmpty(id)
	assertions.NotContains(id, testSessionAPIKey)
	rawID, err := base64.RawURLEncoding.DecodeString(id)
	requirements.NoError(err)
	assertions.Len(rawID, 32, "session IDs use 256 bits of randomness")
	assertions.NotEmpty(session.CSRFToken)
	assertions.Equal(now.Add(time.Hour), session.ExpiresAt)

	got, ok := store.lookup(id)
	requirements.True(ok)
	assertions.Equal(session, got)

	now = now.Add(time.Hour)
	_, ok = store.lookup(id)
	assertions.False(ok, "a session expires at its deadline")
}

func TestSessionStoreDeleteAndCloseClearSessions(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)
	store := newSessionStore(time.Hour)
	firstID, _, err := store.create(authz.ServerKey())
	requirements.NoError(err)
	secondID, _, err := store.create(authz.ServerKey())
	requirements.NoError(err)

	store.delete(firstID)
	_, ok := store.lookup(firstID)
	assertions.False(ok)
	_, ok = store.lookup(secondID)
	requirements.True(ok)

	store.Close()
	_, ok = store.lookup(secondID)
	assertions.False(ok)
}

func TestSessionStoreCreatePurgesOnlyBoundedExpiredEntries(t *testing.T) {
	const expectedPurgeScanLimit = 16
	requirements := require.New(t)
	now := time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
	store := newSessionStore(time.Minute)
	store.now = func() time.Time { return now }

	initialSessions := expectedPurgeScanLimit + 5
	for range initialSessions {
		_, _, err := store.create(authz.ServerKey())
		requirements.NoError(err)
	}
	requirements.Len(store.sessions, initialSessions)

	now = now.Add(time.Minute)
	_, _, err := store.create(authz.ServerKey())
	requirements.NoError(err)
	assert.Len(t, store.sessions, initialSessions+1-expectedPurgeScanLimit,
		"one create purges at most the bounded scan quota")
}

func TestConstantTimeAPIKeyEqual(t *testing.T) {
	assert.True(t, constantTimeAPIKeyEqual(testSessionAPIKey, testSessionAPIKey))
	assert.False(t, constantTimeAPIKeyEqual("wrong-session-api-key", testSessionAPIKey))
	assert.False(t, constantTimeAPIKeyEqual("short", testSessionAPIKey))
}

func TestSessionOpenAPIRoutesDoNotReplaceAPIKeySecurity(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)
	doc := OpenAPIDocument()
	requirements.NotNil(doc.Paths[sessionPath])
	assertions.Empty(doc.Paths[sessionPath].Get.Security)
	assertions.Empty(doc.Paths[sessionPath].Delete.Security)
	for _, responseKey := range []string{"429", "default"} {
		logoutError := doc.Paths[sessionPath].Delete.Responses[responseKey]
		requirements.NotNil(logoutError, "logout response %s", responseKey)
		logoutJSONError := logoutError.Content["application/json"]
		requirements.NotNil(logoutJSONError, "logout response %s JSON content", responseKey)
		requirements.NotNil(logoutJSONError.Schema, "logout response %s schema", responseKey)
		assertions.Equal("#/components/schemas/ErrorResponse", logoutJSONError.Schema.Ref,
			"logout response %s schema", responseKey)
	}
	requirements.NotNil(doc.Paths[sessionLoginPath])
	assertions.Empty(doc.Paths[sessionLoginPath].Post.Security)

	health := doc.Paths["/api/v1/health"].Get
	requirements.Len(health.Security, 1)
	assertions.Contains(health.Security[0], apiKeySecurityScheme)
	assertions.Len(doc.Components.SecuritySchemes, 1, "cookie sessions stay additive to the documented API-key scheme")
}

func TestLoginSuccessCreatesOpaqueHostOnlyCookie(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)
	srv := newSessionTestServer(t, testSessionAPIKey)

	resp := performSessionRequest(t, srv, http.MethodPost, sessionLoginPath,
		[]byte(`{"api_key":"`+testSessionAPIKey+`"}`), nil, false)
	requirements.Equal(http.StatusOK, resp.Code, resp.Body.String())
	status := decodeSessionStatus(t, resp)
	assertions.Equal(AuthModeSession, status.AuthMode)
	assertions.NotEmpty(status.CSRFToken)
	assertions.False(status.HTTPS)
	assertions.True(status.PlainHTTPWarning)
	assertions.Equal("no-store", resp.Header().Get("Cache-Control"))

	cookie := requireSessionCookie(t, resp)
	assertions.NotContains(cookie.Value, testSessionAPIKey)
	rawID, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	requirements.NoError(err)
	assertions.Len(rawID, 32)
	assertions.Empty(cookie.Domain, "the session cookie must remain host-only")
	assertions.Equal("/", cookie.Path)
	assertions.True(cookie.HttpOnly)
	assertions.Equal(http.SameSiteStrictMode, cookie.SameSite)
	assertions.False(cookie.Secure)
}

func TestLoginFailureDoesNotCreateCookie(t *testing.T) {
	srv := newSessionTestServer(t, testSessionAPIKey)

	resp := performSessionRequest(t, srv, http.MethodPost, sessionLoginPath,
		[]byte(`{"api_key":"wrong-key"}`), nil, false)
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
	assert.Empty(t, resp.Result().Cookies())
	assert.Equal(t, "no-store", resp.Header().Get("Cache-Control"))
}

func TestLoginOverDirectTLSUsesSecureCookie(t *testing.T) {
	assertions := assert.New(t)
	srv := newSessionTestServer(t, testSessionAPIKey)

	resp := performSessionRequest(t, srv, http.MethodPost, sessionLoginPath,
		[]byte(`{"api_key":"`+testSessionAPIKey+`"}`), nil, true)
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	status := decodeSessionStatus(t, resp)
	assertions.True(status.HTTPS)
	assertions.False(status.PlainHTTPWarning)
	assertions.True(requireSessionCookie(t, resp).Secure)
}

func TestSessionBootstrapModes(t *testing.T) {
	t.Run("loopback", func(t *testing.T) {
		assertions := assert.New(t)
		srv := newSessionTestServer(t, "")
		resp := performSessionRequest(t, srv, http.MethodGet, sessionPath, nil, nil, false)
		require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
		status := decodeSessionStatus(t, resp)
		assertions.Equal(AuthModeLoopback, status.AuthMode)
		assertions.Empty(status.CSRFToken)
		assertions.Equal("no-store", resp.Header().Get("Cache-Control"))
	})

	t.Run("trusted API key", func(t *testing.T) {
		srv := newSessionTestServer(t, testSessionAPIKey)
		headers := http.Header{"X-Api-Key": []string{testSessionAPIKey}}
		resp := performSessionRequest(t, srv, http.MethodGet, sessionPath, nil, headers, false)
		require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
		status := decodeSessionStatus(t, resp)
		assert.Equal(t, AuthModeAPIKey, status.AuthMode)
		assert.Empty(t, status.CSRFToken)
	})

	t.Run("browser session", func(t *testing.T) {
		assertions := assert.New(t)
		requirements := require.New(t)
		srv := newSessionTestServer(t, testSessionAPIKey)
		login := performSessionRequest(t, srv, http.MethodPost, sessionLoginPath,
			[]byte(`{"api_key":"`+testSessionAPIKey+`"}`), nil, false)
		requirements.Equal(http.StatusOK, login.Code, login.Body.String())
		loginStatus := decodeSessionStatus(t, login)
		cookie := requireSessionCookie(t, login)

		headers := http.Header{"Cookie": []string{cookie.String()}}
		resp := performSessionRequest(t, srv, http.MethodGet, sessionPath, nil, headers, false)
		requirements.Equal(http.StatusOK, resp.Code, resp.Body.String())
		status := decodeSessionStatus(t, resp)
		assertions.Equal(AuthModeSession, status.AuthMode)
		assertions.Equal(loginStatus.CSRFToken, status.CSRFToken)

		health := performSessionRequest(t, srv, http.MethodGet, "/api/v1/health", nil, headers, false)
		assertions.Equal(http.StatusOK, health.Code, health.Body.String())
	})

	t.Run("API key wins over browser session", func(t *testing.T) {
		assertions := assert.New(t)
		requirements := require.New(t)
		srv := newSessionTestServer(t, testSessionAPIKey)
		login := performSessionRequest(t, srv, http.MethodPost, sessionLoginPath,
			[]byte(`{"api_key":"`+testSessionAPIKey+`"}`), nil, false)
		requirements.Equal(http.StatusOK, login.Code, login.Body.String())
		cookie := requireSessionCookie(t, login)

		headers := http.Header{
			"Cookie":    []string{cookie.String()},
			"X-Api-Key": []string{testSessionAPIKey},
		}
		resp := performSessionRequest(t, srv, http.MethodGet, sessionPath, nil, headers, false)
		requirements.Equal(http.StatusOK, resp.Code, resp.Body.String())
		status := decodeSessionStatus(t, resp)
		assertions.Equal(AuthModeAPIKey, status.AuthMode)
		assertions.Empty(status.CSRFToken)
	})

	t.Run("unauthenticated remote", func(t *testing.T) {
		srv := newSessionTestServer(t, testSessionAPIKey)
		resp := performSessionRequest(t, srv, http.MethodGet, sessionPath, nil, nil, false)
		require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
		status := decodeSessionStatus(t, resp)
		assert.Equal(t, AuthModeRequired, status.AuthMode)
		assert.Empty(t, status.CSRFToken)
	})
}

func TestLoginIgnoresUntrustedForwardedHTTPS(t *testing.T) {
	assertions := assert.New(t)
	srv := newSessionTestServer(t, testSessionAPIKey)
	headers := http.Header{"X-Forwarded-Proto": []string{"https"}}

	resp := performSessionRequest(t, srv, http.MethodPost, sessionLoginPath,
		[]byte(`{"api_key":"`+testSessionAPIKey+`"}`), headers, false)
	require.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	status := decodeSessionStatus(t, resp)
	assertions.False(status.HTTPS)
	assertions.True(status.PlainHTTPWarning)
	assertions.False(requireSessionCookie(t, resp).Secure)
}

func TestSessionExpiryRevokesCookieAuthentication(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)
	srv := newSessionTestServer(t, testSessionAPIKey)
	now := time.Date(2026, time.July, 18, 12, 0, 0, 0, time.UTC)
	srv.sessions.now = func() time.Time { return now }
	srv.sessions.ttl = time.Minute

	login := performSessionRequest(t, srv, http.MethodPost, sessionLoginPath,
		[]byte(`{"api_key":"`+testSessionAPIKey+`"}`), nil, false)
	requirements.Equal(http.StatusOK, login.Code, login.Body.String())
	cookie := requireSessionCookie(t, login)

	now = now.Add(time.Minute)
	headers := http.Header{"Cookie": []string{cookie.String()}}
	resp := performSessionRequest(t, srv, http.MethodGet, sessionPath, nil, headers, false)
	requirements.Equal(http.StatusOK, resp.Code, resp.Body.String())
	assertions.Equal(AuthModeRequired, decodeSessionStatus(t, resp).AuthMode)

	health := performSessionRequest(t, srv, http.MethodGet, "/api/v1/health", nil, headers, false)
	assertions.Equal(http.StatusUnauthorized, health.Code)
}

func TestSessionLogoutInvalidatesCookie(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)
	srv := newSessionTestServer(t, testSessionAPIKey)
	login := performSessionRequest(t, srv, http.MethodPost, sessionLoginPath,
		[]byte(`{"api_key":"`+testSessionAPIKey+`"}`), nil, false)
	requirements.Equal(http.StatusOK, login.Code, login.Body.String())
	loginStatus := decodeSessionStatus(t, login)
	cookie := requireSessionCookie(t, login)

	headers := http.Header{
		"Cookie":       []string{cookie.String()},
		"Origin":       []string{"http://example.com"},
		csrfHeaderName: []string{loginStatus.CSRFToken},
	}
	logout := performSessionRequest(t, srv, http.MethodDelete, sessionPath, nil, headers, false)
	assertions.Equal(http.StatusNoContent, logout.Code, logout.Body.String())
	assertions.Equal("no-store", logout.Header().Get("Cache-Control"))
	cleared := requireSessionCookie(t, logout)
	assertions.Empty(cleared.Value)
	assertions.Negative(cleared.MaxAge)

	bootstrap := performSessionRequest(t, srv, http.MethodGet, sessionPath, nil, headers, false)
	requirements.Equal(http.StatusOK, bootstrap.Code, bootstrap.Body.String())
	assertions.Equal(AuthModeRequired, decodeSessionStatus(t, bootstrap).AuthMode)
}

func TestSessionMutationsBypassHeldArchiveOperationGate(t *testing.T) {
	oldLimit := operationGateWaitLimit
	operationGateWaitLimit = 20 * time.Millisecond
	t.Cleanup(func() { operationGateWaitLimit = oldLimit })

	gate := NewSerialOperationGate()
	srv := NewServerWithOptions(ServerOptions{
		Config:        &config.Config{Server: config.ServerConfig{APIKey: testSessionAPIKey}},
		Logger:        testLogger(),
		OperationGate: gate,
	})
	t.Cleanup(func() {
		require.NoError(t, srv.Shutdown(context.Background()))
	})

	login := performSessionRequest(t, srv, http.MethodPost, sessionLoginPath,
		[]byte(`{"api_key":"`+testSessionAPIKey+`"}`), nil, false)
	require.Equal(t, http.StatusOK, login.Code, login.Body.String())
	loginStatus := decodeSessionStatus(t, login)
	cookie := requireSessionCookie(t, login)

	releaseGate, ok := gate.BeginLabeledWorkContext(context.Background(), "archive sync")
	require.True(t, ok)
	defer releaseGate()

	t.Run("logout with ambient session", func(t *testing.T) {
		headers := http.Header{
			"Cookie":       []string{cookie.String()},
			"Origin":       []string{"http://example.com"},
			csrfHeaderName: []string{loginStatus.CSRFToken},
		}
		resp := performSessionRequest(t, srv, http.MethodDelete, sessionPath, nil, headers, false)
		assert.Equal(t, http.StatusNoContent, resp.Code, resp.Body.String())
	})

	t.Run("login with ambient API key", func(t *testing.T) {
		headers := http.Header{"X-Api-Key": []string{testSessionAPIKey}}
		resp := performSessionRequest(t, srv, http.MethodPost, sessionLoginPath,
			[]byte(`{"api_key":"`+testSessionAPIKey+`"}`), headers, false)
		assert.Equal(t, http.StatusOK, resp.Code, resp.Body.String())
	})
}

func TestSessionRestartInvalidatesCookie(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)
	first := newSessionTestServer(t, testSessionAPIKey)
	login := performSessionRequest(t, first, http.MethodPost, sessionLoginPath,
		[]byte(`{"api_key":"`+testSessionAPIKey+`"}`), nil, false)
	requirements.Equal(http.StatusOK, login.Code, login.Body.String())
	cookie := requireSessionCookie(t, login)

	second := newSessionTestServer(t, testSessionAPIKey)
	headers := http.Header{"Cookie": []string{cookie.String()}}
	bootstrap := performSessionRequest(t, second, http.MethodGet, sessionPath, nil, headers, false)
	requirements.Equal(http.StatusOK, bootstrap.Code, bootstrap.Body.String())
	assertions.Equal(AuthModeRequired, decodeSessionStatus(t, bootstrap).AuthMode)
}

func TestLoginAlwaysRateLimitedOnLoopback(t *testing.T) {
	tests := []struct {
		name        string
		body        []byte
		headers     http.Header
		firstStatus int
	}{
		{
			name:        "wrong key",
			body:        []byte(`{"api_key":"wrong-key"}`),
			firstStatus: http.StatusUnauthorized,
		},
		{
			name:        "ambient API key authentication",
			body:        []byte(`{"api_key":"` + testSessionAPIKey + `"}`),
			headers:     http.Header{"X-Api-Key": []string{testSessionAPIKey}},
			firstStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newSessionTestServer(t, testSessionAPIKey)
			// Remove token replenishment so the assertion is deterministic even on a
			// slow or heavily instrumented test runner.
			srv.rateLimiter.rate = 0
			srv.rateLimiter.burst = 1

			first := performSessionRequest(t, srv, http.MethodPost, sessionLoginPath,
				tt.body, tt.headers, false)
			assert.Equal(t, tt.firstStatus, first.Code, first.Body.String())

			second := performSessionRequest(t, srv, http.MethodPost, sessionLoginPath,
				tt.body, tt.headers, false)
			assert.Equal(t, http.StatusTooManyRequests, second.Code, second.Body.String())
			assert.Equal(t, "no-store", second.Header().Get("Cache-Control"))
		})
	}
}

func newSessionTestServer(t *testing.T, apiKey string) *Server {
	t.Helper()
	srv := NewServer(&config.Config{Server: config.ServerConfig{APIKey: apiKey}}, nil, nil, testLogger())
	t.Cleanup(func() {
		require.NoError(t, srv.Shutdown(context.Background()))
	})
	return srv
}

func performSessionRequest(
	t *testing.T,
	srv *Server,
	method string,
	path string,
	body []byte,
	headers http.Header,
	tlsConnection bool,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.RemoteAddr = "127.0.0.1:4242"
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	if tlsConnection {
		req.TLS = &tls.ConnectionState{}
	}
	resp := httptest.NewRecorder()
	srv.Router().ServeHTTP(resp, req)
	return resp
}

func decodeSessionStatus(t *testing.T, resp *httptest.ResponseRecorder) SessionStatus {
	t.Helper()
	var status SessionStatus
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&status))
	return status
}

func requireSessionCookie(t *testing.T, resp *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range resp.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			return cookie
		}
	}
	require.FailNow(t, "session cookie not found")
	return nil
}

func TestLoginWithNamedKeyCreatesRoleBoundSession(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	cfg := &config.Config{
		Server: config.ServerConfig{APIKey: testSessionAPIKey},
		Auth: config.AuthConfig{APIKeys: []config.APIKeyConfig{
			{Name: "reader", Key: "reader-secret-value", Role: string(authz.RoleViewer)},
		}},
	}
	srv := NewServer(cfg, nil, nil, testLogger())
	t.Cleanup(func() {
		require.NoError(srv.Shutdown(context.Background()))
	})

	resp := performSessionRequest(t, srv, http.MethodPost, sessionLoginPath,
		[]byte(`{"api_key":"reader-secret-value"}`), nil, false)
	require.Equal(http.StatusOK, resp.Code, resp.Body.String())
	status := decodeSessionStatus(t, resp)
	assert.Equal(AuthModeSession, status.AuthMode)
	assert.Equal([]string{"api_key"}, status.LoginMethods)
	require.NotNil(status.Principal)
	assert.Equal(PrincipalInfo{Kind: authz.PrincipalAPIKey, Name: "reader", Role: authz.RoleViewer}, *status.Principal)
	cookie := requireSessionCookie(t, resp)

	headers := http.Header{"Cookie": []string{cookie.Name + "=" + cookie.Value}}
	me := performSessionRequest(t, srv, http.MethodGet, "/api/v1/me", nil, headers, false)
	require.Equal(http.StatusOK, me.Code, me.Body.String())
	var principal PrincipalInfo
	require.NoError(decodeJSONBody(me, &principal))
	assert.Equal(authz.RoleViewer, principal.Role)

	headers.Set(csrfHeaderName, status.CSRFToken)
	headers.Set("Origin", "http://example.com")
	forbidden := performSessionRequest(t, srv, http.MethodPost, "/api/v1/saved-views", []byte(`{}`), headers, false)
	assert.Equal(http.StatusForbidden, forbidden.Code, forbidden.Body.String())
	assert.Contains(forbidden.Body.String(), `"forbidden"`)

	bootstrap := performSessionRequest(t, srv, http.MethodGet, sessionPath, nil, headers, false)
	require.Equal(http.StatusOK, bootstrap.Code)
	bootstrapStatus := decodeSessionStatus(t, bootstrap)
	require.NotNil(bootstrapStatus.Principal)
	assert.Equal("reader", bootstrapStatus.Principal.Name)
}

func TestAPIKeyLoginCanBeDisabled(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	disabled := false
	cfg := &config.Config{
		Server: config.ServerConfig{APIKey: testSessionAPIKey},
		Auth:   config.AuthConfig{APIKeyLogin: &disabled},
	}
	srv := NewServer(cfg, nil, nil, testLogger())
	t.Cleanup(func() {
		require.NoError(srv.Shutdown(context.Background()))
	})

	resp := performSessionRequest(t, srv, http.MethodPost, sessionLoginPath,
		[]byte(`{"api_key":"`+testSessionAPIKey+`"}`), nil, false)
	assert.Equal(http.StatusForbidden, resp.Code, resp.Body.String())
	assert.Contains(resp.Body.String(), "api_key_login_disabled")

	bootstrap := performSessionRequest(t, srv, http.MethodGet, sessionPath, nil, nil, false)
	require.Equal(http.StatusOK, bootstrap.Code)
	status := decodeSessionStatus(t, bootstrap)
	assert.Equal(AuthModeRequired, status.AuthMode)
	assert.Empty(status.LoginMethods)
	assert.Nil(status.Principal)

	// The key itself still authenticates API clients.
	me := performSessionRequest(t, srv, http.MethodGet, "/api/v1/me", nil,
		http.Header{"Authorization": []string{"Bearer " + testSessionAPIKey}}, false)
	assert.Equal(http.StatusOK, me.Code, me.Body.String())
}
