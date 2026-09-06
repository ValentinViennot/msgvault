package api

import (
	"errors"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"go.kenn.io/msgvault/internal/authn/oidc"
	"go.kenn.io/msgvault/internal/authz"
	"go.kenn.io/msgvault/internal/store"
)

const (
	sessionOIDCPathPrefix   = "/api/session/oidc/"
	sessionOIDCStartPath    = "/api/session/oidc/start"
	sessionOIDCCallbackPath = "/api/session/oidc/callback"
	// oidcLoginCookieName binds an in-flight login to the browser that started
	// it. Lax, not Strict: the provider's redirect back is a cross-site
	// top-level navigation and must carry it.
	oidcLoginCookieName = "msgvault_oidc_login"
	oidcLoginCookieTTL  = 10 * time.Minute

	insufficientScopeChallenge = `Bearer error="insufficient_scope", scope="` + oidc.ScopeWrite + `"`
)

func (s *Server) oidcLoginEnabled() bool {
	return s.oidc != nil && s.oidc.Config().LoginEnabled()
}

func (s *Server) oidcLoginInfo() *OIDCLoginInfo {
	if !s.oidcLoginEnabled() {
		return nil
	}
	return &OIDCLoginInfo{ProviderName: s.oidc.Name(), StartURL: sessionOIDCStartPath}
}

func (s *Server) registerOIDCSessionRoutes(api huma.API) {
	registerRawHumaRoute(api, huma.Operation{
		OperationID: "startOIDCLogin",
		Method:      http.MethodGet,
		Path:        sessionOIDCStartPath,
		Tags:        []string{"Session"},
		Summary:     "Redirect the browser to the identity provider",
		Errors:      []int{http.StatusNotFound, http.StatusBadGateway, http.StatusTooManyRequests},
		Responses:   rawHumaResponses(http.StatusFound),
	}, s.handleOIDCStart)
	registerRawHumaRoute(api, huma.Operation{
		OperationID: "completeOIDCLogin",
		Method:      http.MethodGet,
		Path:        sessionOIDCCallbackPath,
		Tags:        []string{"Session"},
		Summary:     "Complete an identity-provider login and create a browser session",
		Errors:      []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusBadGateway, http.StatusTooManyRequests},
		Responses:   rawHumaResponses(http.StatusFound),
	}, s.handleOIDCCallback)
}

func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if !s.oidcLoginEnabled() {
		writeError(w, http.StatusNotFound, "oidc_disabled", "Identity-provider login is not configured")
		return
	}
	login, err := s.oidc.BeginLogin(r.Context())
	if err != nil {
		s.logger.Warn("begin identity-provider login", "error", err)
		writeError(w, http.StatusBadGateway, "identity_provider_unavailable", "The identity provider could not be reached")
		return
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure follows the verified request scheme; plain HTTP is an explicit supported mode.
		Name:     oidcLoginCookieName,
		Value:    login.Binding,
		Path:     sessionOIDCPathPrefix,
		MaxAge:   int(oidcLoginCookieTTL / time.Second),
		HttpOnly: true,
		Secure:   requestUsesHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, login.AuthURL, http.StatusFound)
}

func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if !s.oidcLoginEnabled() {
		writeError(w, http.StatusNotFound, "oidc_disabled", "Identity-provider login is not configured")
		return
	}
	query := r.URL.Query()
	if providerError := query.Get("error"); providerError != "" {
		s.logger.Warn("identity-provider login refused", "error", providerError, "description", query.Get("error_description"))
		writeLoginPage(w, http.StatusBadRequest, "Sign-in was not completed",
			"The identity provider reported: "+providerError+".")
		return
	}
	code, state := query.Get("code"), query.Get("state")
	if code == "" || state == "" {
		writeLoginPage(w, http.StatusBadRequest, "Sign-in was not completed", "The callback is missing its code or state.")
		return
	}
	binding := ""
	if cookie, err := r.Cookie(oidcLoginCookieName); err == nil {
		binding = cookie.Value
	}
	identity, err := s.oidc.CompleteLogin(r.Context(), state, binding, code)
	switch {
	case errors.Is(err, oidc.ErrLoginExpired), errors.Is(err, oidc.ErrLoginBinding):
		writeLoginPage(w, http.StatusBadRequest, "Sign-in expired", "Start the sign-in again from this browser.")
		return
	case err != nil:
		s.logger.Warn("complete identity-provider login", "error", err)
		writeLoginPage(w, http.StatusBadGateway, "Sign-in failed", "The identity provider did not complete the sign-in.")
		return
	}
	principal, ok := s.oidc.Principal(identity)
	if !ok {
		s.logger.Warn("identity-provider login without a role", "email", identity.Email, "subject", identity.Subject)
		writeLoginPage(w, http.StatusForbidden, "Not allowed", "Your account is not allowed on this archive.")
		return
	}
	if s.userStore != nil {
		user, err := s.userStore.RecordUserLogin(r.Context(), store.UserLogin{
			Issuer: identity.Issuer, Subject: identity.Subject, Email: identity.Email,
			DisplayName: identity.Name, Role: string(principal.Role),
		})
		if err != nil {
			s.logger.Error("record identity-provider login", "error", err)
			writeLoginPage(w, http.StatusInternalServerError, "Sign-in failed", "The sign-in could not be recorded.")
			return
		}
		if user.Disabled {
			s.logger.Warn("disabled user signed in", "email", user.Email)
			writeLoginPage(w, http.StatusForbidden, "Not allowed", "Your account is disabled on this archive.")
			return
		}
		principal.Email = user.Email
		principal.UserID = user.ID
	}
	principal.IdentityIssuer, principal.IdentitySubject = identity.Issuer, identity.Subject
	clearCookie(w, oidcLoginCookieName, sessionOIDCPathPrefix, requestUsesHTTPS(r))
	if _, err := s.issueSession(w, r, principal); err != nil {
		s.logger.Error("create browser session", "error", err)
		writeLoginPage(w, http.StatusInternalServerError, "Sign-in failed", "The browser session could not be created.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/", http.StatusFound)
}

// classifyAccessToken authenticates a bearer access token from the
// configured identity provider. Only JWT-shaped credentials are tried, and
// only after the API keys did not match, so key lookups stay cheap.
func (s *Server) classifyAccessToken(r *http.Request, credential string) (requestAuthentication, bool) {
	if s.oidc == nil || !s.oidc.Config().BearerEnabled() || strings.Count(credential, ".") != 2 {
		return requestAuthentication{}, false
	}
	identity, err := s.oidc.VerifyAccessToken(r.Context(), credential)
	if err != nil {
		s.logger.Debug("access token rejected", "error", err)
		return requestAuthentication{}, false
	}
	principal, ok := s.oidc.Principal(identity)
	if !ok {
		s.logger.Warn("access token without a role", "email", identity.Email, "subject", identity.Subject)
		return requestAuthentication{}, false
	}
	if !identity.HasScope(oidc.ScopeRead) {
		s.logger.Warn("access token without the read scope", "email", identity.Email)
		return requestAuthentication{}, false
	}
	principal.IdentityIssuer, principal.IdentitySubject = identity.Issuer, identity.Subject
	return requestAuthentication{
		Mode:                  AuthModeToken,
		Principal:             principal,
		WriteDenied:           !identity.HasScope(oidc.ScopeWrite),
		trustedForCLIDuration: principal.Role == authz.RoleAdmin,
	}, true
}

func clearCookie(w http.ResponseWriter, name, path string, secure bool) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure follows the verified request scheme; plain HTTP is an explicit supported mode.
		Name: name, Value: "", Path: path, Expires: time.Unix(1, 0), MaxAge: -1,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

// writeLoginPage renders a small self-contained page for the browser-facing
// callback, where JSON would be shown raw. Everything dynamic is escaped.
func writeLoginPage(w http.ResponseWriter, status int, title, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>%[1]s · msgvault</title>`+
		`<style>body{font-family:system-ui,sans-serif;margin:4rem auto;max-width:32rem;padding:0 1rem;color:#222}a{color:#0a58ca}</style>`+
		`</head><body><p>msgvault</p><h1>%[1]s</h1><p>%[2]s</p><p><a href="/">Back to msgvault</a></p></body></html>`,
		html.EscapeString(title), html.EscapeString(message))
}
