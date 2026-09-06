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
	require.NoError(t, err)
	require.Len(t, cfg.Auth.APIKeys, 2)
	assert.Equal(t, "reader", cfg.Auth.APIKeys[0].Name)
	assert.Equal(t, "viewer", cfg.Auth.APIKeys[0].Role, "the default role is the least privileged")
	assert.Equal(t, "member", cfg.Auth.APIKeys[1].Role, "roles are case-folded")
	assert.False(t, cfg.Auth.APIKeyLoginEnabled())

	resolved, warnings := cfg.Auth.ResolveAPIKeys(func(string) string { return "" })
	require.Len(t, resolved, 1, "an unset key_env disables only that key")
	assert.Equal(t, ResolvedAPIKey{Name: "reader", Key: "reader-secret-value", Role: authz.RoleViewer}, resolved[0])
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "MSGVAULT_TEST_CURATOR_KEY")

	resolved, warnings = cfg.Auth.ResolveAPIKeys(func(name string) string {
		if name == "MSGVAULT_TEST_CURATOR_KEY" {
			return "curator-secret-value"
		}
		return ""
	})
	require.Empty(t, warnings)
	require.Len(t, resolved, 2)
	assert.Equal(t, ResolvedAPIKey{Name: "curator", Key: "curator-secret-value", Role: authz.RoleMember}, resolved[1])
}

func TestAuthDefaultsWithoutSection(t *testing.T) {
	cfg, err := loadAuthConfig(t, "[server]\napi_key = \"admin-secret-value\"\n")
	require.NoError(t, err)
	assert.True(t, cfg.Auth.APIKeyLoginEnabled())
	assert.Empty(t, cfg.Auth.APIKeys)
	resolved, warnings := cfg.Auth.ResolveAPIKeys(nil)
	assert.Empty(t, resolved)
	assert.Empty(t, warnings)
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
