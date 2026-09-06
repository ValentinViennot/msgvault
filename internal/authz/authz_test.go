package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoleOrdering(t *testing.T) {
	tests := []struct {
		role, required Role
		want           bool
	}{
		{RoleViewer, RoleViewer, true},
		{RoleViewer, RoleMember, false},
		{RoleViewer, RoleAdmin, false},
		{RoleMember, RoleViewer, true},
		{RoleMember, RoleMember, true},
		{RoleMember, RoleAdmin, false},
		{RoleAdmin, RoleViewer, true},
		{RoleAdmin, RoleAdmin, true},
		{"", RoleViewer, false},
		{RoleAdmin, "", false},
		{"owner", RoleViewer, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.role.AtLeast(tt.required), "%q at least %q", tt.role, tt.required)
	}
}

func TestParseRole(t *testing.T) {
	for _, role := range Roles {
		parsed, err := ParseRole(string(role))
		require.NoError(t, err)
		assert.Equal(t, role, parsed)
	}
	_, err := ParseRole("Admin")
	assert.Error(t, err, "roles are case-sensitive after config normalisation")
	_, err = ParseRole("")
	assert.Error(t, err)
}

func TestPrincipalCan(t *testing.T) {
	assert.True(t, ServerKey().Can(RoleAdmin))
	assert.True(t, Loopback().Can(RoleAdmin))
	assert.False(t, Principal{}.Can(RoleViewer), "a zero principal grants nothing")
	assert.True(t, Principal{}.IsZero())
	assert.False(t, ServerKey().IsZero())
}
