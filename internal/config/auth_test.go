package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/authz"
)

func loadAuthConfig(t *testing.T, content string) (*Config, error) {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0o644))
	return Load(configPath, "")
}

func TestLoadAuthAPIKeys(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	cfg, err := loadAuthConfig(t, `
[server]
api_key = "admin-secret-value"

[auth]
api_key_login = false

[[auth.api_keys]]
name = " reader "
key = "reader-secret-value"

[[auth.api_keys]]
name = "curator"
key_env = "MSGVAULT_TEST_CURATOR_KEY"
role = "Member"
`)
	require.NoError(err)
	require.Len(cfg.Auth.APIKeys, 2)
	assert.Equal("reader", cfg.Auth.APIKeys[0].Name)
	assert.Equal("viewer", cfg.Auth.APIKeys[0].Role, "the default role is the least privileged")
	assert.Equal("member", cfg.Auth.APIKeys[1].Role, "roles are case-folded")
	assert.False(cfg.Auth.APIKeyLoginEnabled())

	resolved, warnings := cfg.Auth.ResolveAPIKeys(func(string) string { return "" })
	require.Len(resolved, 1, "an unset key_env disables only that key")
	assert.Equal(ResolvedAPIKey{Name: "reader", Key: "reader-secret-value", Role: authz.RoleViewer}, resolved[0])
	require.Len(warnings, 1)
	assert.Contains(warnings[0], "MSGVAULT_TEST_CURATOR_KEY")

	resolved, warnings = cfg.Auth.ResolveAPIKeys(func(name string) string {
		if name == "MSGVAULT_TEST_CURATOR_KEY" {
			return "curator-secret-value"
		}
		return ""
	})
	require.Empty(warnings)
	require.Len(resolved, 2)
	assert.Equal(ResolvedAPIKey{Name: "curator", Key: "curator-secret-value", Role: authz.RoleMember}, resolved[1])
}

func TestAuthDefaultsWithoutSection(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	cfg, err := loadAuthConfig(t, "[server]\napi_key = \"admin-secret-value\"\n")
	require.NoError(err)
	assert.True(cfg.Auth.APIKeyLoginEnabled())
	assert.Empty(cfg.Auth.APIKeys)
	resolved, warnings := cfg.Auth.ResolveAPIKeys(nil)
	assert.Empty(resolved)
	assert.Empty(warnings)
}

func TestLoadAuthAPIKeysRejectsInvalidEntries(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "missing name",
			content: "[[auth.api_keys]]\nkey = \"x\"\n",
			want:    "name is required",
		},
		{
			name:    "duplicate name",
			content: "[[auth.api_keys]]\nname = \"reader\"\nkey = \"x\"\n[[auth.api_keys]]\nname = \"Reader\"\nkey = \"y\"\n",
			want:    "duplicate name",
		},
		{
			name:    "key and key_env",
			content: "[[auth.api_keys]]\nname = \"reader\"\nkey = \"x\"\nkey_env = \"Y\"\n",
			want:    "not both",
		},
		{
			name:    "no secret",
			content: "[[auth.api_keys]]\nname = \"reader\"\n",
			want:    "key or key_env is required",
		},
		{
			name:    "unknown role",
			content: "[[auth.api_keys]]\nname = \"reader\"\nkey = \"x\"\nrole = \"owner\"\n",
			want:    "unknown role",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadAuthConfig(t, tt.content)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestLoadAuthOIDC(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	cfg, err := loadAuthConfig(t, `
[server]
api_key = "admin-secret-value"

[auth.oidc]
issuer = "https://idp.example"
client_id = "vault"
client_secret_env = "MSGVAULT_TEST_OIDC_SECRET"
public_url = "https://vault.example"
resource = "https://vault.example/mcp"
admin_groups = ["vault_admin"]
provider_name = "Example ID"
`)
	require.NoError(err)
	assert.True(cfg.Auth.OIDC.Enabled())
	assert.Equal("vault", cfg.Auth.OIDC.ClientID)
	assert.Empty(cfg.Auth.OIDC.ResolveClientSecret(func(string) string { return "" }))
	assert.Equal("s3cret", cfg.Auth.OIDC.ResolveClientSecret(func(name string) string {
		if name == "MSGVAULT_TEST_OIDC_SECRET" {
			return "s3cret"
		}
		return ""
	}))
}

func TestLoadAuthOIDCRejectsIncompleteSections(t *testing.T) {
	tests := map[string]string{
		"both secrets":   "[auth.oidc]\nissuer = \"https://idp.example\"\nclient_id = \"c\"\nclient_secret = \"x\"\nclient_secret_env = \"Y\"\npublic_url = \"https://v.example\"\n",
		"nothing served": "[auth.oidc]\nissuer = \"https://idp.example\"\nclient_id = \"c\"\n",
		"no client":      "[auth.oidc]\nissuer = \"https://idp.example\"\npublic_url = \"https://v.example\"\n",
	}
	for name, content := range tests {
		_, err := loadAuthConfig(t, content)
		require.Error(t, err, name)
	}
	_, err := loadAuthConfig(t, "[auth.oidc]\nissuer = \"https://idp.example\"\nresource = \"https://v.example/mcp\"\n")
	require.NoError(t, err, "bearer-only configuration needs no client")
}

func TestAuthEnvOverrides(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	for _, name := range AuthEnvOverrideNames() {
		t.Setenv(name, "")
	}
	t.Setenv("MSGVAULT_AUTH_OIDC_ISSUER", "https://idp.example")
	t.Setenv("MSGVAULT_AUTH_OIDC_CLIENT_ID", "vault")
	t.Setenv("MSGVAULT_AUTH_OIDC_CLIENT_SECRET", "from-env")
	t.Setenv("MSGVAULT_AUTH_OIDC_PUBLIC_URL", "https://vault.example")
	t.Setenv("MSGVAULT_AUTH_OIDC_RESOURCE", "https://vault.example/mcp")
	t.Setenv("MSGVAULT_AUTH_OIDC_ADMIN_GROUPS", "vault_admin, ops")
	t.Setenv("MSGVAULT_AUTH_OIDC_VIEWER_GROUPS", "vault_viewer")
	t.Setenv("MSGVAULT_AUTH_API_KEY_LOGIN", "false")
	t.Setenv("MSGVAULT_SERVER_TRUSTED_PROXIES", "172.19.0.0/16,10.0.0.1")

	// A config file without an [auth] section still picks the values up.
	cfg, err := loadAuthConfig(t, "[server]\napi_key = \"admin-secret-value\"\n")
	require.NoError(err)
	assert.Equal("https://idp.example", cfg.Auth.OIDC.Issuer)
	assert.Equal("from-env", cfg.Auth.OIDC.ResolveClientSecret(nil))
	assert.Equal([]string{"vault_admin", "ops"}, cfg.Auth.OIDC.AdminGroups)
	assert.Equal([]string{"vault_viewer"}, cfg.Auth.OIDC.ViewerGroups)
	assert.False(cfg.Auth.APIKeyLoginEnabled())
	assert.Equal([]string{"172.19.0.0/16", "10.0.0.1"}, cfg.Server.TrustedProxies)

	// So does a missing config file.
	missing, err := Load("", t.TempDir())
	require.NoError(err)
	assert.Equal("vault", missing.Auth.OIDC.ClientID)
	assert.Equal([]string{"172.19.0.0/16", "10.0.0.1"}, missing.Server.TrustedProxies)

	t.Setenv("MSGVAULT_SERVER_TRUSTED_PROXIES", "not-an-address")
	_, err = loadAuthConfig(t, "[server]\napi_key = \"admin-secret-value\"\n")
	require.Error(err, "overrides go through the same validation as the file")
}

func TestAuthEnvOverridesDeclareKeysAndRemote(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	for _, name := range AuthEnvOverrideNames() {
		t.Setenv(name, "")
	}
	t.Setenv("MSGVAULT_AUTH_API_KEYS", `[{"name":"sidecar","key_env":"MSGVAULT_TEST_SIDECAR_KEY","role":"admin"},{"name":"reader","key":"reader-secret-value"}]`)
	t.Setenv("MSGVAULT_TEST_SIDECAR_KEY", "sidecar-secret-value")
	t.Setenv("MSGVAULT_REMOTE_URL", "http://daemon:8080")
	t.Setenv("MSGVAULT_REMOTE_API_KEY", "remote-secret-value")
	t.Setenv("MSGVAULT_REMOTE_ALLOW_INSECURE", "true")

	cfg, err := loadAuthConfig(t, "[server]\napi_key = \"admin-secret-value\"\n[[auth.api_keys]]\nname = \"file\"\nkey = \"file-secret-value\"\n")
	require.NoError(err)
	require.Len(cfg.Auth.APIKeys, 3, "environment keys are appended to the file's")
	resolved, warnings := cfg.Auth.ResolveAPIKeys(nil)
	require.Empty(warnings)
	assert.Equal("sidecar", resolved[1].Name)
	assert.Equal("sidecar-secret-value", resolved[1].Key)
	assert.Equal(authz.RoleAdmin, resolved[1].Role)
	assert.Equal(authz.RoleViewer, resolved[2].Role, "the default role applies to environment keys too")
	assert.Equal("http://daemon:8080", cfg.Remote.URL)
	assert.Equal("remote-secret-value", cfg.Remote.APIKey)
	assert.True(cfg.Remote.AllowInsecure)

	t.Setenv("MSGVAULT_AUTH_API_KEYS", `[{"name":"file","key":"x"}]`)
	_, err = loadAuthConfig(t, "[[auth.api_keys]]\nname = \"file\"\nkey = \"file-secret-value\"\n")
	require.Error(err, "a name used in both the file and the environment is a duplicate")
	t.Setenv("MSGVAULT_AUTH_API_KEYS", `{"name":"x"}`)
	_, err = loadAuthConfig(t, "")
	require.ErrorIs(err, ErrAuthEnvAPIKeys)
	t.Setenv("MSGVAULT_AUTH_API_KEYS", `[{"name":"x","key":"y","surprise":1}]`)
	_, err = loadAuthConfig(t, "")
	require.ErrorIs(err, ErrAuthEnvAPIKeys)
}
