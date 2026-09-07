package authz

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActingIdentityHeaderRoundTrips(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	identity := ActingIdentity{
		Issuer: "https://idp.example", Subject: "u-123",
		Name: "Zoë Straße 🙂 <admin&co>", Role: RoleMember,
	}

	value := identity.HeaderValue()
	for _, r := range value {
		assert.True(r >= 0x20 && r < 0x7f, "header must be printable ASCII, got %q", r)
	}
	assert.Contains(value, `\u00eb`, "non-ASCII is escaped")
	assert.Contains(value, `\ud83d\ude42`, "astral characters use surrogate pairs")

	parsed, err := ParseActingIdentity(value)
	require.NoError(err)
	assert.Equal(identity, parsed)

	parsed, err = ParseActingIdentity(`{"issuer":"https://idp.example","subject":"u-9","role":"viewer","future":"ignored"}`)
	require.NoError(err, "unknown fields are ignored for newer services")
	assert.Equal(ActingIdentity{Issuer: "https://idp.example", Subject: "u-9", Role: RoleViewer}, parsed)

	parsed, err = ParseActingIdentity(`{"issuer":"https://idp.example","subject":"u-9","name":"  Alice  ","role":"admin"}`)
	require.NoError(err)
	assert.Equal("Alice", parsed.Name, "the display name is trimmed")
}

func TestParseActingIdentityRefusesWhatADaemonCannotTrust(t *testing.T) {
	assert := assert.New(t)
	long := strings.Repeat("x", 600)
	control := string(rune(1))
	tests := []struct {
		name, value string
	}{
		{"empty", "   "},
		{"not json", "issuer=https://idp.example"},
		{"trailing data", `{"issuer":"a","subject":"b","role":"viewer"} extra`},
		{"missing subject", `{"issuer":"https://idp.example","subject":" ","role":"viewer"}`},
		{"missing issuer", `{"subject":"u-1","role":"viewer"}`},
		{"unknown role", `{"issuer":"https://idp.example","subject":"u-1","role":"owner"}`},
		{"role case", `{"issuer":"https://idp.example","subject":"u-1","role":"Admin"}`},
		{"missing role", `{"issuer":"https://idp.example","subject":"u-1"}`},
		{"control character in name", `{"issuer":"https://idp.example","subject":"u-1","name":"a` + control + `b","role":"viewer"}`},
		{"control character in subject", `{"issuer":"https://idp.example","subject":"u` + control + `1","role":"viewer"}`},
		{"oversized subject", `{"issuer":"https://idp.example","subject":"` + long + `","role":"viewer"}`},
		{"oversized name", `{"issuer":"https://idp.example","subject":"u-1","name":"` + long + `","role":"viewer"}`},
		{"oversized header", `{"issuer":"https://idp.example","subject":"u-1","role":"viewer","pad":"` + strings.Repeat("p", 5000) + `"}`},
	}
	for _, tt := range tests {
		_, err := ParseActingIdentity(tt.value)
		require.ErrorIs(t, err, ErrActingIdentityInvalid, tt.name)
	}

	// A control character in a Go value is escaped on the wire and refused on
	// the way back, so a misbehaving provider cannot smuggle one through.
	value := ActingIdentity{Issuer: "https://idp.example", Subject: "u-1", Name: "a" + control + "b", Role: RoleViewer}.HeaderValue()
	assert.NotContains(value, control)
	_, err := ParseActingIdentity(value)
	assert.ErrorIs(err, ErrActingIdentityInvalid)
}

func TestActingIdentityContext(t *testing.T) {
	assert := assert.New(t)
	ctx := t.Context()
	_, ok := ActingIdentityFromContext(ctx)
	assert.False(ok)
	assert.Empty(ActingUser(ctx))

	identity := ActingIdentity{Issuer: "https://idp.example", Subject: "u-1", Role: RoleViewer}
	ctx = WithActingIdentity(WithActingUser(ctx, "alice@example.com"), identity)
	got, ok := ActingIdentityFromContext(ctx)
	assert.True(ok)
	assert.Equal(identity, got)
	assert.Equal("alice@example.com", ActingUser(ctx))
}
