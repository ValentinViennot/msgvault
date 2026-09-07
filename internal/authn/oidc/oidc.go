// Package oidc signs people in through an OpenID Connect provider and
// validates that provider's access tokens for API and MCP callers. It maps
// the provider's group claims to msgvault roles and never stores tokens.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	goidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"go.kenn.io/msgvault/internal/authz"
)

const (
	// ScopeRead and ScopeWrite are the permissions an access token may carry
	// for this resource. Readers get the read tools; writers additionally get
	// the write-class tools their role covers.
	ScopeRead  = "msgvault:read"
	ScopeWrite = "msgvault:write"

	defaultGroupsClaim = "groups"
	defaultPendingTTL  = 10 * time.Minute
	userInfoCacheLimit = 256
)

// DefaultScopes is requested when the configuration names none.
var DefaultScopes = []string{goidc.ScopeOpenID, "profile", "email", "groups"}

// Config describes the provider and how its claims map to msgvault roles.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// PublicURL is the origin browsers use for this daemon; the login
	// callback is {PublicURL}/api/session/oidc/callback.
	PublicURL string
	// Resource is the RFC 8707 resource identifier this process accepts as
	// the audience of bearer access tokens. Empty disables bearer tokens.
	Resource      string
	Scopes        []string
	GroupsClaim   string
	AdminGroups   []string
	MemberGroups  []string
	ViewerGroups  []string
	AllowedEmails []string
	ProviderName  string
	// InsecureAllowHTTP permits an http:// issuer. Tests only.
	InsecureAllowHTTP bool
	// HTTPClient overrides the client used for discovery, token exchange,
	// and userinfo. Tests only.
	HTTPClient *http.Client
	Now        func() time.Time
}

// Validate checks the static parts of the configuration.
func (c Config) Validate() error {
	issuer, err := url.Parse(c.Issuer)
	if err != nil || issuer.Host == "" {
		return fmt.Errorf("issuer %q is not an absolute URL", c.Issuer)
	}
	if issuer.Scheme != "https" && (!c.InsecureAllowHTTP || issuer.Scheme != "http") {
		return fmt.Errorf("issuer %q must use https", c.Issuer)
	}
	if c.PublicURL != "" {
		public, err := url.Parse(c.PublicURL)
		if err != nil || public.Host == "" || (public.Scheme != "https" && public.Scheme != "http") {
			return fmt.Errorf("public_url %q is not an absolute http(s) URL", c.PublicURL)
		}
		if c.ClientID == "" {
			return errors.New("client_id is required for browser login")
		}
	}
	if c.Resource != "" {
		resource, err := url.Parse(c.Resource)
		if err != nil || resource.Host == "" || resource.Fragment != "" {
			return fmt.Errorf("resource %q is not an absolute URL without a fragment", c.Resource)
		}
	}
	if c.PublicURL == "" && c.Resource == "" {
		return errors.New("set public_url for browser login, resource for bearer tokens, or both")
	}
	if len(c.AdminGroups)+len(c.MemberGroups)+len(c.ViewerGroups)+len(c.AllowedEmails) == 0 {
		return errors.New("no admin_groups, member_groups, viewer_groups, or allowed_emails: nobody could sign in")
	}
	return nil
}

// LoginEnabled reports whether the browser login flow is configured.
func (c Config) LoginEnabled() bool { return c.PublicURL != "" }

// BearerEnabled reports whether bearer access tokens are accepted.
func (c Config) BearerEnabled() bool { return c.Resource != "" }

// Identity is what the provider asserted about a caller.
type Identity struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Groups        []string
	// Scopes are the permissions carried by an access token; empty for a
	// browser login.
	Scopes []string
	// Expiry is when the asserting token stops being valid.
	Expiry time.Time
}

// HasScope reports whether an access token granted the scope.
func (i Identity) HasScope(scope string) bool { return slices.Contains(i.Scopes, scope) }

// Provider is one configured OpenID Connect provider.
type Provider struct {
	cfg Config
	now func() time.Time

	discoverMu sync.Mutex
	discovered *goidc.Provider

	pending *pendingStore

	userInfoMu    sync.Mutex
	userInfoCache map[[sha256.Size]byte]cachedIdentity
}

type cachedIdentity struct {
	identity Identity
	expires  time.Time
}

// New validates cfg and returns a provider. Discovery happens on first use so
// a daemon still starts while the identity provider is down.
func New(cfg Config) (*Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("[auth.oidc]: %w", err)
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = slices.Clone(DefaultScopes)
	}
	if !slices.Contains(cfg.Scopes, goidc.ScopeOpenID) {
		cfg.Scopes = append([]string{goidc.ScopeOpenID}, cfg.Scopes...)
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = defaultGroupsClaim
	}
	if cfg.ProviderName == "" {
		cfg.ProviderName = "single sign-on"
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Provider{
		cfg:           cfg,
		now:           now,
		pending:       newPendingStore(defaultPendingTTL, now),
		userInfoCache: make(map[[sha256.Size]byte]cachedIdentity),
	}, nil
}

// Name is the label the login button shows.
func (p *Provider) Name() string { return p.cfg.ProviderName }

// Config returns the validated configuration.
func (p *Provider) Config() Config { return p.cfg }

// BearerScopes lists what an MCP client should request: the configured
// identity scopes first, because providers answer userinfo only for tokens
// granted openid and the resource server resolves the person through it when
// the access token carries no email or groups, then the API permissions.
func (p *Provider) BearerScopes() []string {
	scopes := slices.Clone(p.cfg.Scopes)
	for _, scope := range []string{ScopeRead, ScopeWrite} {
		if !slices.Contains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	return scopes
}

// CallbackURL is the redirect URI registered with the provider.
func (p *Provider) CallbackURL() string {
	return strings.TrimRight(p.cfg.PublicURL, "/") + "/api/session/oidc/callback"
}

func (p *Provider) clientContext(ctx context.Context) context.Context {
	if p.cfg.HTTPClient != nil {
		return goidc.ClientContext(ctx, p.cfg.HTTPClient)
	}
	return ctx
}

func (p *Provider) discover(ctx context.Context) (*goidc.Provider, error) {
	p.discoverMu.Lock()
	defer p.discoverMu.Unlock()
	if p.discovered != nil {
		return p.discovered, nil
	}
	provider, err := goidc.NewProvider(p.clientContext(ctx), p.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover %s: %w", p.cfg.Issuer, err)
	}
	p.discovered = provider
	return provider, nil
}

func (p *Provider) oauthConfig(provider *goidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.cfg.ClientID,
		ClientSecret: p.cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  p.CallbackURL(),
		Scopes:       p.cfg.Scopes,
	}
}

// Login is one browser sign-in in progress. State goes to the provider and
// back; Binding is set as a cookie so only the browser that started the
// flow can finish it.
type Login struct {
	AuthURL string
	State   string
	Binding string
}

// BeginLogin prepares the authorization request with PKCE and a nonce.
func (p *Provider) BeginLogin(ctx context.Context) (Login, error) {
	if !p.cfg.LoginEnabled() {
		return Login{}, errors.New("browser login is not configured")
	}
	provider, err := p.discover(ctx)
	if err != nil {
		return Login{}, err
	}
	state, err := randomToken()
	if err != nil {
		return Login{}, err
	}
	binding, err := randomToken()
	if err != nil {
		return Login{}, err
	}
	nonce, err := randomToken()
	if err != nil {
		return Login{}, err
	}
	verifier := oauth2.GenerateVerifier()
	p.pending.put(state, pendingLogin{binding: binding, nonce: nonce, verifier: verifier})
	authURL := p.oauthConfig(provider).AuthCodeURL(state,
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", nonce),
	)
	return Login{AuthURL: authURL, State: state, Binding: binding}, nil
}

// ErrLoginExpired is returned when the callback names no pending login: the
// flow timed out, was used already, or was started elsewhere.
var ErrLoginExpired = errors.New("login expired or unknown; start again")

// ErrLoginBinding is returned when the browser finishing the flow is not the
// one that started it.
var ErrLoginBinding = errors.New("login was started by another browser")

// CompleteLogin exchanges the authorization code and returns the verified
// identity. Each pending login can be completed once.
func (p *Provider) CompleteLogin(ctx context.Context, state, binding, code string) (Identity, error) {
	pending, ok := p.pending.take(state)
	if !ok {
		return Identity{}, ErrLoginExpired
	}
	if pending.binding == "" || binding == "" || pending.binding != binding {
		return Identity{}, ErrLoginBinding
	}
	provider, err := p.discover(ctx)
	if err != nil {
		return Identity{}, err
	}
	token, err := p.oauthConfig(provider).Exchange(p.clientContext(ctx), code, oauth2.VerifierOption(pending.verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("exchange authorization code: %w", err)
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		return Identity{}, errors.New("token response carries no id_token")
	}
	idToken, err := provider.VerifierContext(p.clientContext(ctx), &goidc.Config{ClientID: p.cfg.ClientID, Now: p.now}).Verify(ctx, rawIDToken)
	if err != nil {
		return Identity{}, fmt.Errorf("verify id_token: %w", err)
	}
	if idToken.Nonce != pending.nonce {
		return Identity{}, errors.New("id_token nonce mismatch")
	}
	identity, err := p.identityFromClaims(idToken.Claims, idToken.Subject, idToken.Expiry)
	if err != nil {
		return Identity{}, err
	}
	if identity.Email == "" || !p.hasGroupsClaim(identity) {
		// Some providers keep email and groups out of the ID token; the
		// userinfo endpoint is authoritative for both.
		info, infoErr := provider.UserInfo(p.clientContext(ctx), oauth2.StaticTokenSource(token))
		if infoErr == nil {
			var extra Identity
			if claimsErr := p.fillIdentity(&extra, info.Claims, info.Subject, identity.Expiry); claimsErr == nil {
				identity = mergeIdentity(identity, extra)
			}
		}
	}
	return identity, nil
}

// VerifyAccessToken validates a bearer access token minted for this
// resource: signature, issuer, expiry, and audience are checked by the
// verifier; groups are read from the token or, failing that, userinfo.
func (p *Provider) VerifyAccessToken(ctx context.Context, raw string) (Identity, error) {
	if !p.cfg.BearerEnabled() {
		return Identity{}, errors.New("bearer tokens are not configured")
	}
	digest := sha256.Sum256([]byte(raw))
	if identity, ok := p.cachedUserInfo(digest); ok {
		return identity, nil
	}
	provider, err := p.discover(ctx)
	if err != nil {
		return Identity{}, err
	}
	token, err := provider.VerifierContext(p.clientContext(ctx), &goidc.Config{ClientID: p.cfg.Resource, Now: p.now}).Verify(ctx, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("verify access token: %w", err)
	}
	identity, err := p.identityFromClaims(token.Claims, token.Subject, token.Expiry)
	if err != nil {
		return Identity{}, err
	}
	if identity.Email == "" || !p.hasGroupsClaim(identity) {
		info, infoErr := provider.UserInfo(p.clientContext(ctx), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: raw, TokenType: "Bearer"}))
		if infoErr != nil {
			return Identity{}, fmt.Errorf("userinfo: %w", infoErr)
		}
		var extra Identity
		if claimsErr := p.fillIdentity(&extra, info.Claims, info.Subject, identity.Expiry); claimsErr != nil {
			return Identity{}, claimsErr
		}
		identity = mergeIdentity(identity, extra)
	}
	p.storeUserInfo(digest, identity)
	return identity, nil
}

// RoleFor maps an identity's groups to a role. The most privileged matching
// group wins; an email on the allow list is a viewer.
func (p *Provider) RoleFor(identity Identity) (authz.Role, bool) {
	switch {
	case intersects(identity.Groups, p.cfg.AdminGroups):
		return authz.RoleAdmin, true
	case intersects(identity.Groups, p.cfg.MemberGroups):
		return authz.RoleMember, true
	case intersects(identity.Groups, p.cfg.ViewerGroups):
		return authz.RoleViewer, true
	}
	folded := strings.ToLower(strings.TrimSpace(identity.Email))
	for _, allowed := range p.cfg.AllowedEmails {
		if folded != "" && folded == strings.ToLower(strings.TrimSpace(allowed)) {
			return authz.RoleViewer, true
		}
	}
	return "", false
}

// Principal builds the request principal for an identity. ok is false when
// the identity maps to no role.
func (p *Provider) Principal(identity Identity) (authz.Principal, bool) {
	role, ok := p.RoleFor(identity)
	if !ok {
		return authz.Principal{}, false
	}
	name := identity.Name
	if name == "" {
		name = identity.Email
	}
	return authz.Principal{Kind: authz.PrincipalUser, Name: name, Email: identity.Email, Role: role}, true
}

type rawClaims struct {
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Scope             string `json:"scope"`
	Scp               any    `json:"scp"`
}

func (p *Provider) identityFromClaims(claims func(any) error, subject string, expiry time.Time) (Identity, error) {
	var identity Identity
	if err := p.fillIdentity(&identity, claims, subject, expiry); err != nil {
		return Identity{}, err
	}
	return identity, nil
}

func (p *Provider) fillIdentity(identity *Identity, claims func(any) error, subject string, expiry time.Time) error {
	var raw rawClaims
	if err := claims(&raw); err != nil {
		return fmt.Errorf("decode claims: %w", err)
	}
	groups, err := groupsClaim(claims, p.cfg.GroupsClaim)
	if err != nil {
		return err
	}
	identity.Issuer = p.cfg.Issuer
	identity.Subject = subject
	identity.Email = strings.TrimSpace(raw.Email)
	identity.EmailVerified = raw.EmailVerified
	identity.Name = strings.TrimSpace(raw.Name)
	if identity.Name == "" {
		identity.Name = strings.TrimSpace(raw.PreferredUsername)
	}
	identity.Groups = groups
	identity.Scopes = scopes(raw)
	identity.Expiry = expiry
	return nil
}

func (p *Provider) hasGroupsClaim(identity Identity) bool { return identity.Groups != nil }

func groupsClaim(claims func(any) error, name string) ([]string, error) {
	var all map[string]any
	if err := claims(&all); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	value, ok := all[name]
	if !ok {
		return nil, nil
	}
	switch typed := value.(type) {
	case []any:
		groups := make([]string, 0, len(typed))
		for _, entry := range typed {
			if text, ok := entry.(string); ok {
				groups = append(groups, text)
			}
		}
		return groups, nil
	case string:
		return strings.Fields(typed), nil
	case nil:
		return []string{}, nil
	}
	return nil, fmt.Errorf("claim %q is neither a list nor a string", name)
}

func scopes(raw rawClaims) []string {
	var out []string
	out = append(out, strings.Fields(raw.Scope)...)
	switch typed := raw.Scp.(type) {
	case []any:
		for _, entry := range typed {
			if text, ok := entry.(string); ok {
				out = append(out, text)
			}
		}
	case string:
		out = append(out, strings.Fields(typed)...)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func mergeIdentity(base, extra Identity) Identity {
	if base.Email == "" {
		base.Email = extra.Email
		base.EmailVerified = extra.EmailVerified
	}
	if base.Name == "" {
		base.Name = extra.Name
	}
	if base.Groups == nil {
		base.Groups = extra.Groups
	}
	if base.Subject == "" {
		base.Subject = extra.Subject
	}
	return base
}

func intersects(have, want []string) bool {
	for _, group := range have {
		if slices.Contains(want, group) {
			return true
		}
	}
	return false
}

func (p *Provider) cachedUserInfo(digest [sha256.Size]byte) (Identity, bool) {
	p.userInfoMu.Lock()
	defer p.userInfoMu.Unlock()
	entry, ok := p.userInfoCache[digest]
	if !ok {
		return Identity{}, false
	}
	if !p.now().Before(entry.expires) {
		delete(p.userInfoCache, digest)
		return Identity{}, false
	}
	return entry.identity, true
}

func (p *Provider) storeUserInfo(digest [sha256.Size]byte, identity Identity) {
	p.userInfoMu.Lock()
	defer p.userInfoMu.Unlock()
	now := p.now()
	if len(p.userInfoCache) >= userInfoCacheLimit {
		for key, entry := range p.userInfoCache {
			if !now.Before(entry.expires) {
				delete(p.userInfoCache, key)
			}
		}
		if len(p.userInfoCache) >= userInfoCacheLimit {
			return
		}
	}
	expires := identity.Expiry
	if expires.IsZero() || expires.After(now.Add(time.Hour)) {
		expires = now.Add(time.Hour)
	}
	p.userInfoCache[digest] = cachedIdentity{identity: identity, expires: expires}
}

func randomToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
