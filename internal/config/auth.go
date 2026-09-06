package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"go.kenn.io/msgvault/internal/authz"
)

// AuthConfig is the opt-in caller model: named API keys with roles, and
// whether the browser login form accepts API keys. Without an [auth] section
// the single-key behaviour is unchanged: [server].api_key is the only
// credential and it is an administrator.
type AuthConfig struct {
	// APIKeyLogin controls the Web UI's API-key login form. Nil means enabled.
	APIKeyLogin *bool          `toml:"api_key_login"`
	APIKeys     []APIKeyConfig `toml:"api_keys"`
	// OIDC signs people in through an OpenID Connect provider and accepts
	// that provider's access tokens. An empty issuer leaves it disabled.
	OIDC OIDCConfig `toml:"oidc"`
}

// OIDCConfig is the [auth.oidc] section. Every key can also come from the
// environment as MSGVAULT_AUTH_OIDC_<KEY> so deployments keep the daemon's
// config.toml free of provider details.
type OIDCConfig struct {
	Issuer          string   `toml:"issuer"`
	ClientID        string   `toml:"client_id"`
	ClientSecret    string   `toml:"client_secret"`
	ClientSecretEnv string   `toml:"client_secret_env"`
	PublicURL       string   `toml:"public_url"`
	Resource        string   `toml:"resource"`
	Scopes          []string `toml:"scopes"`
	GroupsClaim     string   `toml:"groups_claim"`
	AdminGroups     []string `toml:"admin_groups"`
	MemberGroups    []string `toml:"member_groups"`
	ViewerGroups    []string `toml:"viewer_groups"`
	AllowedEmails   []string `toml:"allowed_emails"`
	ProviderName    string   `toml:"provider_name"`
}

// Enabled reports whether an identity provider is configured.
func (o *OIDCConfig) Enabled() bool { return strings.TrimSpace(o.Issuer) != "" }

// ResolveClientSecret returns the client secret from config or, when
// client_secret_env names a variable, from the environment.
func (o *OIDCConfig) ResolveClientSecret(lookupEnv func(string) string) string {
	if o.ClientSecretEnv != "" {
		if lookupEnv == nil {
			lookupEnv = os.Getenv
		}
		return lookupEnv(o.ClientSecretEnv)
	}
	return o.ClientSecret
}

// oidcEnvOverrides maps environment variables onto [auth.oidc] keys. Lists
// are comma-separated.
var oidcEnvOverrides = []struct {
	name  string
	apply func(*OIDCConfig, string)
}{
	{"MSGVAULT_AUTH_OIDC_ISSUER", func(o *OIDCConfig, v string) { o.Issuer = v }},
	{"MSGVAULT_AUTH_OIDC_CLIENT_ID", func(o *OIDCConfig, v string) { o.ClientID = v }},
	{"MSGVAULT_AUTH_OIDC_CLIENT_SECRET", func(o *OIDCConfig, v string) { o.ClientSecret = v; o.ClientSecretEnv = "" }},
	{"MSGVAULT_AUTH_OIDC_CLIENT_SECRET_ENV", func(o *OIDCConfig, v string) { o.ClientSecretEnv = v }},
	{"MSGVAULT_AUTH_OIDC_PUBLIC_URL", func(o *OIDCConfig, v string) { o.PublicURL = v }},
	{"MSGVAULT_AUTH_OIDC_RESOURCE", func(o *OIDCConfig, v string) { o.Resource = v }},
	{"MSGVAULT_AUTH_OIDC_SCOPES", func(o *OIDCConfig, v string) { o.Scopes = splitList(v) }},
	{"MSGVAULT_AUTH_OIDC_GROUPS_CLAIM", func(o *OIDCConfig, v string) { o.GroupsClaim = v }},
	{"MSGVAULT_AUTH_OIDC_ADMIN_GROUPS", func(o *OIDCConfig, v string) { o.AdminGroups = splitList(v) }},
	{"MSGVAULT_AUTH_OIDC_MEMBER_GROUPS", func(o *OIDCConfig, v string) { o.MemberGroups = splitList(v) }},
	{"MSGVAULT_AUTH_OIDC_VIEWER_GROUPS", func(o *OIDCConfig, v string) { o.ViewerGroups = splitList(v) }},
	{"MSGVAULT_AUTH_OIDC_ALLOWED_EMAILS", func(o *OIDCConfig, v string) { o.AllowedEmails = splitList(v) }},
	{"MSGVAULT_AUTH_OIDC_PROVIDER_NAME", func(o *OIDCConfig, v string) { o.ProviderName = v }},
}

// AuthEnvOverrideNames lists every environment variable applyAuthEnvOverrides
// honours, for documentation and tests.
func AuthEnvOverrideNames() []string {
	names := []string{"MSGVAULT_AUTH_API_KEY_LOGIN", "MSGVAULT_SERVER_TRUSTED_PROXIES"}
	for _, override := range oidcEnvOverrides {
		names = append(names, override.name)
	}
	return names
}

// applyAuthEnvOverrides lets a deployment supply the caller model and the
// trusted proxy list through the environment, where a container manager can
// own them, instead of editing the archive's config.toml.
func (c *Config) applyAuthEnvOverrides(lookupEnv func(string) string) {
	if lookupEnv == nil {
		lookupEnv = os.Getenv
	}
	for _, override := range oidcEnvOverrides {
		if value := strings.TrimSpace(lookupEnv(override.name)); value != "" {
			override.apply(&c.Auth.OIDC, value)
		}
	}
	if value := strings.TrimSpace(lookupEnv("MSGVAULT_AUTH_API_KEY_LOGIN")); value != "" {
		enabled := !strings.EqualFold(value, "false") && value != "0"
		c.Auth.APIKeyLogin = &enabled
	}
	if value := strings.TrimSpace(lookupEnv("MSGVAULT_SERVER_TRUSTED_PROXIES")); value != "" {
		c.Server.TrustedProxies = splitList(value)
	}
}

func splitList(value string) []string {
	var out []string
	for entry := range strings.SplitSeq(value, ",") {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// APIKeyConfig is one named bearer credential. Exactly one of Key or KeyEnv
// supplies the secret; KeyEnv names an environment variable so the secret can
// stay out of config.toml.
type APIKeyConfig struct {
	Name   string `toml:"name"`
	Key    string `toml:"key"`
	KeyEnv string `toml:"key_env"`
	Role   string `toml:"role"`
	// User binds the key to a user's address: the key then sees that user's
	// sources. A key without a user and without the admin role sees none.
	User string `toml:"user"`
	// OnBehalfOf lets an admin key act for a user named in the
	// X-Msgvault-On-Behalf-Of header; only the MCP sidecar needs it.
	OnBehalfOf bool `toml:"on_behalf_of"`
}

// ApplyDefaults trims names and gives keys without a role the least privilege.
func (a *AuthConfig) ApplyDefaults() {
	a.OIDC.Issuer = strings.TrimSpace(a.OIDC.Issuer)
	a.OIDC.ClientSecretEnv = strings.TrimSpace(a.OIDC.ClientSecretEnv)
	for i := range a.APIKeys {
		a.APIKeys[i].Name = strings.TrimSpace(a.APIKeys[i].Name)
		a.APIKeys[i].KeyEnv = strings.TrimSpace(a.APIKeys[i].KeyEnv)
		a.APIKeys[i].Role = strings.ToLower(strings.TrimSpace(a.APIKeys[i].Role))
		a.APIKeys[i].User = strings.ToLower(strings.TrimSpace(a.APIKeys[i].User))
		if a.APIKeys[i].Role == "" {
			a.APIKeys[i].Role = string(authz.RoleViewer)
		}
	}
}

// Validate checks the structural rules of [[auth.api_keys]]. Secrets read
// from the environment are resolved later by ResolveAPIKeys so that a config
// file shared by several processes still loads where a variable is absent.
func (a *AuthConfig) Validate() error {
	seen := make(map[string]struct{}, len(a.APIKeys))
	for i, key := range a.APIKeys {
		if key.Name == "" {
			return fmt.Errorf("[[auth.api_keys]] entry %d: name is required", i+1)
		}
		label := fmt.Sprintf("[[auth.api_keys]] %q", key.Name)
		folded := strings.ToLower(key.Name)
		if _, dup := seen[folded]; dup {
			return fmt.Errorf("%s: duplicate name", label)
		}
		seen[folded] = struct{}{}
		switch {
		case key.Key != "" && key.KeyEnv != "":
			return fmt.Errorf("%s: set key or key_env, not both", label)
		case key.Key == "" && key.KeyEnv == "":
			return fmt.Errorf("%s: key or key_env is required", label)
		}
		if _, err := authz.ParseRole(key.Role); err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		if key.OnBehalfOf && key.Role != string(authz.RoleAdmin) {
			return fmt.Errorf("%s: on_behalf_of requires role = \"admin\"", label)
		}
		if key.OnBehalfOf && key.User != "" {
			return fmt.Errorf("%s: on_behalf_of and user are mutually exclusive", label)
		}
	}
	if a.OIDC.Enabled() {
		if a.OIDC.ClientSecret != "" && a.OIDC.ClientSecretEnv != "" {
			return errors.New("[auth.oidc]: set client_secret or client_secret_env, not both")
		}
		if a.OIDC.PublicURL == "" && a.OIDC.Resource == "" {
			return errors.New("[auth.oidc]: set public_url for browser login, resource for bearer tokens, or both")
		}
		if a.OIDC.PublicURL != "" && a.OIDC.ClientID == "" {
			return errors.New("[auth.oidc]: client_id is required for browser login")
		}
	}
	return nil
}

// APIKeyLoginEnabled reports whether the Web UI may exchange an API key for a
// browser session.
func (a *AuthConfig) APIKeyLoginEnabled() bool {
	return a.APIKeyLogin == nil || *a.APIKeyLogin
}

// ResolvedAPIKey is a named key whose secret has been read from config or the
// environment.
type ResolvedAPIKey struct {
	Name       string
	Key        string
	Role       authz.Role
	User       string
	OnBehalfOf bool
}

// ResolveAPIKeys returns the usable named keys. An entry whose key_env is
// unset is skipped and reported as a warning instead of failing the load.
func (a *AuthConfig) ResolveAPIKeys(lookupEnv func(string) string) ([]ResolvedAPIKey, []string) {
	if lookupEnv == nil {
		lookupEnv = os.Getenv
	}
	var resolved []ResolvedAPIKey
	var warnings []string
	for _, key := range a.APIKeys {
		secret := key.Key
		if key.KeyEnv != "" {
			secret = lookupEnv(key.KeyEnv)
			if secret == "" {
				warnings = append(warnings, fmt.Sprintf(
					"[[auth.api_keys]] %q: environment variable %s is not set; the key is disabled",
					key.Name, key.KeyEnv))
				continue
			}
		}
		role, err := authz.ParseRole(key.Role)
		if err != nil {
			role = authz.RoleViewer
		}
		resolved = append(resolved, ResolvedAPIKey{Name: key.Name, Key: secret, Role: role, User: key.User, OnBehalfOf: key.OnBehalfOf})
	}
	return resolved, warnings
}
