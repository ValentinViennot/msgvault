package config

import (
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
}

// APIKeyConfig is one named bearer credential. Exactly one of Key or KeyEnv
// supplies the secret; KeyEnv names an environment variable so the secret can
// stay out of config.toml.
type APIKeyConfig struct {
	Name   string `toml:"name"`
	Key    string `toml:"key"`
	KeyEnv string `toml:"key_env"`
	Role   string `toml:"role"`
}

// ApplyDefaults trims names and gives keys without a role the least privilege.
func (a *AuthConfig) ApplyDefaults() {
	for i := range a.APIKeys {
		a.APIKeys[i].Name = strings.TrimSpace(a.APIKeys[i].Name)
		a.APIKeys[i].KeyEnv = strings.TrimSpace(a.APIKeys[i].KeyEnv)
		a.APIKeys[i].Role = strings.ToLower(strings.TrimSpace(a.APIKeys[i].Role))
		if a.APIKeys[i].Role == "" {
			a.APIKeys[i].Role = string(authz.RoleViewer)
		}
	}
}

// Validate checks the structural rules of [[auth.api_keys]]. Secrets read
// from the environment are resolved later by ResolveAPIKeys so that a config
// file shared by several processes still loads where a variable is absent.
func (a AuthConfig) Validate() error {
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
	}
	return nil
}

// APIKeyLoginEnabled reports whether the Web UI may exchange an API key for a
// browser session.
func (a AuthConfig) APIKeyLoginEnabled() bool {
	return a.APIKeyLogin == nil || *a.APIKeyLogin
}

// ResolvedAPIKey is a named key whose secret has been read from config or the
// environment.
type ResolvedAPIKey struct {
	Name string
	Key  string
	Role authz.Role
}

// ResolveAPIKeys returns the usable named keys. An entry whose key_env is
// unset is skipped and reported as a warning instead of failing the load.
func (a AuthConfig) ResolveAPIKeys(lookupEnv func(string) string) ([]ResolvedAPIKey, []string) {
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
		resolved = append(resolved, ResolvedAPIKey{Name: key.Name, Key: secret, Role: role})
	}
	return resolved, warnings
}
