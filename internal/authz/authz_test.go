package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoleOrdering(t *testing.T) {
	assert := assert.New(t)
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
		assert.Equal(tt.want, tt.role.AtLeast(tt.required), "%q at least %q", tt.role, tt.required)
	}
}

func TestParseRole(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	for _, role := range Roles {
		parsed, err := ParseRole(string(role))
		require.NoError(err)
		assert.Equal(role, parsed)
	}
	_, err := ParseRole("Admin")
	require.Error(err, "roles are case-sensitive after config normalisation")
	_, err = ParseRole("")
	require.Error(err)
}

func TestPrincipalCan(t *testing.T) {
	assert := assert.New(t)
	assert.True(ServerKey().Can(RoleAdmin))
	assert.True(Loopback().Can(RoleAdmin))
	assert.False(Principal{}.Can(RoleViewer), "a zero principal grants nothing")
	assert.True(Principal{}.IsZero())
	assert.False(ServerKey().IsZero())
}
