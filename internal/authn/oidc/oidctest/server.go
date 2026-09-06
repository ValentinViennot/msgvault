// Package oidctest is a small OpenID Connect provider for tests: discovery,
// JWKS, an authorization endpoint that redirects straight back with a code,
// a PKCE-checking token endpoint, and userinfo.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

// User is a person the fake provider can sign in.
type User struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
	// OmitGroupsFromTokens keeps groups out of ID and access tokens so
	// callers must consult userinfo, as some providers do.
	OmitGroupsFromTokens bool
}

// Server is the running fake provider.
type Server struct {
	*httptest.Server
	Key      *rsa.PrivateKey
	ClientID string
	// ClientSecret, when set, must be presented at the token endpoint.
	ClientSecret string
	// AccessTokenAudience is the aud of access tokens the token endpoint
	// mints; it mirrors an API resource configured at the provider.
	AccessTokenAudience string
	// AccessTokenScopes are granted to every token minted by the flow.
	AccessTokenScopes []string
	Now               func() time.Time

	mu      sync.Mutex
	users   map[string]User
	codes   map[string]authorization
	pending map[string]string // access token digest -> subject
	// AuthorizeRequests records every authorization request's query.
	AuthorizeRequests []url.Values
}

type authorization struct {
	subject   string
	nonce     string
	challenge string
	redirect  string
}

// New starts a provider whose issuer is the server URL.
func New(t *testing.T) *Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	s := &Server{
		Key:               key,
		ClientID:          "msgvault-test",
		AccessTokenScopes: []string{"openid", "msgvault:read"},
		Now:               time.Now,
		users:             make(map[string]User),
		codes:             make(map[string]authorization),
		pending:           make(map[string]string),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("/jwks", s.handleJWKS)
	mux.HandleFunc("/authorize", s.handleAuthorize)
	mux.HandleFunc("/token", s.handleToken)
	mux.HandleFunc("/userinfo", s.handleUserInfo)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// AddUser registers a person who can sign in.
func (s *Server) AddUser(user User) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.Subject] = user
}

// SignInAs makes the next authorization request sign in this subject.
func (s *Server) SignInAs(subject string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending["next"] = subject
}

// Issuer is the provider's issuer identifier.
func (s *Server) Issuer() string { return s.URL }

// MintAccessToken signs an access token for subject with the given audience
// and scopes, as an external client would obtain one.
func (s *Server) MintAccessToken(t *testing.T, subject, audience string, scopes []string, expiry time.Duration) string {
	t.Helper()
	s.mu.Lock()
	user, ok := s.users[subject]
	s.mu.Unlock()
	require.True(t, ok, "unknown subject %q", subject)
	claims := s.baseClaims(user, audience, expiry)
	claims["scope"] = strings.Join(scopes, " ")
	return s.sign(t, claims)
}

// MintTokenSignedByStranger signs a token with a key the provider does not
// publish, so verification must fail.
func (s *Server) MintTokenSignedByStranger(t *testing.T, subject, audience string) string {
	t.Helper()
	stranger, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	claims := map[string]any{
		"iss": s.URL, "sub": subject, "aud": audience,
		"exp": s.Now().Add(time.Hour).Unix(), "iat": s.Now().Unix(),
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: stranger}, (&jose.SignerOptions{}).WithHeader("kid", "stranger"))
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	object, err := signer.Sign(payload)
	require.NoError(t, err)
	serialized, err := object.CompactSerialize()
	require.NoError(t, err)
	return serialized
}

func (s *Server) baseClaims(user User, audience string, expiry time.Duration) map[string]any {
	now := s.Now()
	claims := map[string]any{
		"iss":            s.URL,
		"sub":            user.Subject,
		"aud":            audience,
		"exp":            now.Add(expiry).Unix(),
		"iat":            now.Unix(),
		"email":          user.Email,
		"email_verified": true,
		"name":           user.Name,
	}
	if !user.OmitGroupsFromTokens {
		claims["groups"] = user.Groups
	}
	return claims
}

func (s *Server) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: s.Key}, (&jose.SignerOptions{}).WithHeader("kid", "test-key"))
	require.NoError(t, err)
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	object, err := signer.Sign(payload)
	require.NoError(t, err)
	serialized, err := object.CompactSerialize()
	require.NoError(t, err)
	return serialized
}

func (s *Server) signRaw(claims map[string]any) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: s.Key}, (&jose.SignerOptions{}).WithHeader("kid", "test-key"))
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	object, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return object.CompactSerialize()
}

func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.URL,
		"authorization_endpoint":                s.URL + "/authorize",
		"token_endpoint":                        s.URL + "/token",
		"userinfo_endpoint":                     s.URL + "/userinfo",
		"jwks_uri":                              s.URL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &s.Key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}}}
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	s.mu.Lock()
	s.AuthorizeRequests = append(s.AuthorizeRequests, query)
	subject := s.pending["next"]
	delete(s.pending, "next")
	s.mu.Unlock()
	if query.Get("client_id") != s.ClientID || query.Get("response_type") != "code" ||
		query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	if subject == "" {
		http.Error(w, "no user signed in; call SignInAs first", http.StatusUnauthorized)
		return
	}
	code := randomString()
	s.mu.Lock()
	s.codes[code] = authorization{
		subject:   subject,
		nonce:     query.Get("nonce"),
		challenge: query.Get("code_challenge"),
		redirect:  query.Get("redirect_uri"),
	}
	s.mu.Unlock()
	redirect, err := url.Parse(query.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	values := redirect.Query()
	values.Set("code", code)
	values.Set("state", query.Get("state"))
	redirect.RawQuery = values.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	clientID, secret, basic := r.BasicAuth()
	if !basic {
		clientID = r.PostForm.Get("client_id")
		secret = r.PostForm.Get("client_secret")
	}
	if clientID != s.ClientID || secret != s.ClientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	s.mu.Lock()
	auth, ok := s.codes[r.PostForm.Get("code")]
	delete(s.codes, r.PostForm.Get("code"))
	user := s.users[auth.subject]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	verifier := r.PostForm.Get("code_verifier")
	sum := sha256.Sum256([]byte(verifier))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != auth.challenge {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "PKCE verifier mismatch"})
		return
	}
	if auth.redirect != r.PostForm.Get("redirect_uri") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "redirect_uri mismatch"})
		return
	}
	idClaims := s.baseClaims(user, s.ClientID, time.Hour)
	if auth.nonce != "" {
		idClaims["nonce"] = auth.nonce
	}
	idToken, err := s.signRaw(idClaims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	audience := s.AccessTokenAudience
	if audience == "" {
		audience = s.ClientID
	}
	accessClaims := s.baseClaims(user, audience, time.Hour)
	accessClaims["scope"] = strings.Join(s.AccessTokenScopes, " ")
	accessToken, err := s.signRaw(accessClaims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	object, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	payload, err := object.Verify(&s.Key.PublicKey)
	if err != nil {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		http.Error(w, "invalid claims", http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	user, ok := s.users[claims.Subject]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "unknown subject", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":            user.Subject,
		"email":          user.Email,
		"email_verified": true,
		"name":           user.Name,
		"groups":         user.Groups,
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func randomString() string {
	buffer := make([]byte, 16)
	_, _ = rand.Read(buffer)
	return base64.RawURLEncoding.EncodeToString(buffer)
}
