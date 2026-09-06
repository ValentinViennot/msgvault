package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"go.kenn.io/msgvault/internal/authz"
)

const (
	sessionPath       = "/api/session"
	sessionLoginPath  = "/api/session/login"
	sessionCookieName = "msgvault_session"
)

// AuthMode describes why the current request may access protected API routes.
type AuthMode string

const (
	AuthModeLoopback AuthMode = "loopback"
	AuthModeAPIKey   AuthMode = "api_key"
	AuthModeSession  AuthMode = "session"
	// AuthModeToken is a bearer access token issued by the configured
	// identity provider.
	AuthModeToken    AuthMode = "token"
	AuthModeRequired AuthMode = "required"
)

// SessionLoginRequest exchanges the active daemon API key for an in-memory
// browser session.
type SessionLoginRequest struct {
	APIKey string `json:"api_key"`
}

// SessionStatus reports the request's effective authentication mode. The CSRF
// token is returned only for a valid browser session so mutation middleware
// can enforce session-bound requests without exposing it to other auth modes.
type SessionStatus struct {
	AuthMode         AuthMode `json:"auth_mode" enum:"loopback,api_key,session,token,required"`
	CSRFToken        string   `json:"csrf_token,omitempty"`
	HTTPS            bool     `json:"https"`
	PlainHTTPWarning bool     `json:"plain_http_warning"`
	// Principal identifies the authenticated caller; absent when login is
	// required.
	Principal *PrincipalInfo `json:"principal,omitempty"`
	// LoginMethods lists how a browser may establish a session on this daemon.
	LoginMethods []string `json:"login_methods" doc:"Available login methods: api_key, oidc"`
	// OIDC describes the identity-provider login when one is configured.
	OIDC *OIDCLoginInfo `json:"oidc,omitempty"`
}

// OIDCLoginInfo tells the browser how to start an identity-provider login.
type OIDCLoginInfo struct {
	ProviderName string `json:"provider_name"`
	StartURL     string `json:"start_url"`
}

// PrincipalInfo is the public projection of the authenticated caller.
type PrincipalInfo struct {
	Kind  authz.PrincipalKind `json:"kind" enum:"loopback,api_key,user"`
	Name  string              `json:"name,omitempty"`
	Email string              `json:"email,omitempty"`
	Role  authz.Role          `json:"role" enum:"viewer,member,admin"`
}

func principalInfo(principal authz.Principal) *PrincipalInfo {
	if principal.IsZero() {
		return nil
	}
	return &PrincipalInfo{
		Kind:  principal.Kind,
		Name:  principal.Name,
		Email: principal.Email,
		Role:  principal.Role,
	}
}

const (
	loginMethodAPIKey = "api_key"
	loginMethodOIDC   = "oidc"
)

func (s *Server) loginMethods() []string {
	methods := make([]string, 0, 2)
	if s.cfg.Server.APIKey != "" && s.cfg.Auth.APIKeyLoginEnabled() {
		methods = append(methods, loginMethodAPIKey)
	}
	if s.oidcLoginEnabled() {
		methods = append(methods, loginMethodOIDC)
	}
	return methods
}

func (s *Server) registerSessionRoutes(api huma.API) {
	s.registerOIDCSessionRoutes(api)
	login := huma.Operation{
		OperationID: "loginSession",
		Method:      http.MethodPost,
		Path:        sessionLoginPath,
		Tags:        []string{"Session"},
		Summary:     "Create an in-memory browser session",
		Errors:      []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusInternalServerError},
		RequestBody: jsonRequestBodyFor[SessionLoginRequest](api),
		Responses:   jsonResponsesFor[SessionStatus](api),
	}
	registerRawHumaRoute(api, login, s.handleSessionLogin)

	bootstrap := huma.Operation{
		OperationID: "getSession",
		Method:      http.MethodGet,
		Path:        sessionPath,
		Tags:        []string{"Session"},
		Summary:     "Get browser authentication status",
		Responses:   jsonResponsesFor[SessionStatus](api),
	}
	registerRawHumaRoute(api, bootstrap, s.handleSessionBootstrap)

	logout := huma.Operation{
		OperationID: "logoutSession",
		Method:      http.MethodDelete,
		Path:        sessionPath,
		Tags:        []string{"Session"},
		Summary:     "Delete the current browser session",
		Errors:      []int{http.StatusTooManyRequests},
		Responses: map[string]*huma.Response{
			httpStatusKey(http.StatusNoContent):       {Description: http.StatusText(http.StatusNoContent)},
			httpStatusKey(http.StatusTooManyRequests): errorResponseFor(api),
			"default": errorResponseFor(api),
		},
	}
	registerRawHumaRoute(api, logout, s.handleSessionLogout)
}

func (s *Server) handleSessionLogin(w http.ResponseWriter, r *http.Request) {
	var input SessionLoginRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Invalid session login request")
		return
	}
	if !requireSingleJSONValue(w, decoder, "bad_request") {
		return
	}
	if !s.cfg.Auth.APIKeyLoginEnabled() {
		writeError(w, http.StatusForbidden, "api_key_login_disabled", "API-key login is disabled on this daemon")
		return
	}
	principal, ok := s.principalForAPIKey(input.APIKey)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid API key")
		return
	}

	session, err := s.issueSession(w, r, principal)
	if err != nil {
		s.logger.Error("create browser session", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "Could not create browser session")
		return
	}
	writeJSON(w, http.StatusOK, s.sessionStatus(AuthModeSession, session.CSRFToken, principal, requestUsesHTTPS(r)))
}

// issueSession creates a browser session for principal and sets its cookie.
// Secure follows the verified connection scheme; plain HTTP support is an
// explicit deployment mode surfaced by PlainHTTPWarning.
func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, principal authz.Principal) (browserSession, error) {
	id, session, err := s.sessions.create(principal)
	if err != nil {
		return browserSession{}, err
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure follows the verified request scheme; plain HTTP is an explicit supported mode.
		Name:     sessionCookieName,
		Value:    id,
		Path:     "/",
		Expires:  session.ExpiresAt,
		MaxAge:   max(1, int(s.sessions.ttl/time.Second)),
		HttpOnly: true,
		Secure:   requestUsesHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
	return session, nil
}

func (s *Server) handleSessionBootstrap(w http.ResponseWriter, r *http.Request) {
	auth := s.requestAuthentication(r)
	csrfToken := ""
	if auth.Mode == AuthModeSession {
		csrfToken = auth.Session.CSRFToken
	}
	writeJSON(w, http.StatusOK, s.sessionStatus(auth.Mode, csrfToken, auth.Principal, requestUsesHTTPS(r)))
}

// handleMe returns the calling principal. It answers only for authenticated
// callers because it is registered under /api/v1.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	info := principalInfo(s.requestAuthentication(r).Principal)
	if info == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing API key")
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleSessionLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.sessions.delete(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure follows the verified request scheme; plain HTTP is an explicit supported mode.
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   requestUsesHTTPS(r),
		SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) sessionStatus(mode AuthMode, csrfToken string, principal authz.Principal, https bool) SessionStatus {
	return SessionStatus{
		AuthMode:         mode,
		CSRFToken:        csrfToken,
		HTTPS:            https,
		PlainHTTPWarning: !https,
		Principal:        principalInfo(principal),
		LoginMethods:     s.loginMethods(),
		OIDC:             s.oidcLoginInfo(),
	}
}

func requestUsesHTTPS(r *http.Request) bool {
	if security, ok := securityFromRequest(r); ok {
		return security.scheme == schemeHTTPS
	}
	return r.TLS != nil
}
