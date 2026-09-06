package store_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/store"
	"go.kenn.io/msgvault/internal/testutil"
)

func TestRecordUserLoginCreatesBindsAndRefreshes(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	st := testutil.NewTestStore(t)
	ctx := t.Context()

	first, err := st.RecordUserLogin(ctx, store.UserLogin{
		Issuer: "https://idp.example", Subject: "alice-sub", Email: " Alice@Example.com ", DisplayName: "Alice", Role: "member",
	})
	require.NoError(err)
	assert.Equal("alice@example.com", first.Email, "addresses are case-folded")
	assert.Equal("member", first.Role)
	assert.False(first.Disabled)
	require.NotNil(first.LastLoginAt)

	// The same subject with a new role and address keeps the account.
	second, err := st.RecordUserLogin(ctx, store.UserLogin{
		Issuer: "https://idp.example", Subject: "alice-sub", Email: "alice@new.example", DisplayName: "Alice N.", Role: "admin",
	})
	require.NoError(err)
	assert.Equal(first.ID, second.ID)
	assert.Equal("alice@new.example", second.Email)
	assert.Equal("admin", second.Role)
	assert.Equal("Alice N.", second.DisplayName)

	// A new subject for a known address binds to the existing user.
	third, err := st.RecordUserLogin(ctx, store.UserLogin{
		Issuer: "https://other.example", Subject: "alice-other", Email: "ALICE@new.example", Role: "viewer",
	})
	require.NoError(err)
	assert.Equal(first.ID, third.ID)
	assert.Equal("viewer", third.Role, "the role follows the latest login")

	users, err := st.ListUsers(ctx)
	require.NoError(err)
	require.Len(users, 1)

	_, err = st.RecordUserLogin(ctx, store.UserLogin{Issuer: "https://idp.example", Subject: "x"})
	assert.ErrorIs(err, store.ErrUserEmailRequired)
	_, err = st.RecordUserLogin(ctx, store.UserLogin{Email: "x@example.com"})
	assert.ErrorIs(err, store.ErrUserIdentityRequired)
}

func TestRecordUserLoginKeepsAddressOwnedByAnotherUser(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	st := testutil.NewTestStore(t)
	ctx := t.Context()
	alice, err := st.RecordUserLogin(ctx, store.UserLogin{Issuer: "i", Subject: "alice", Email: "alice@example.com", Role: "viewer"})
	require.NoError(err)
	bob, err := st.RecordUserLogin(ctx, store.UserLogin{Issuer: "i", Subject: "bob", Email: "bob@example.com", Role: "viewer"})
	require.NoError(err)

	// Bob's provider now claims Alice's address; Bob stays Bob.
	again, err := st.RecordUserLogin(ctx, store.UserLogin{Issuer: "i", Subject: "bob", Email: "alice@example.com", Role: "viewer"})
	require.NoError(err)
	assert.Equal(bob.ID, again.ID)
	assert.Equal("bob@example.com", again.Email)
	stillAlice, err := st.GetUser(ctx, alice.ID)
	require.NoError(err)
	assert.Equal("alice@example.com", stillAlice.Email)
}

func TestSetUserDisabledAndGetUser(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	st := testutil.NewTestStore(t)
	ctx := t.Context()
	user, err := st.RecordUserLogin(ctx, store.UserLogin{Issuer: "i", Subject: "carol", Email: "carol@example.com", Role: "member"})
	require.NoError(err)

	require.NoError(st.SetUserDisabled(ctx, user.ID, true))
	disabled, err := st.RecordUserLogin(ctx, store.UserLogin{Issuer: "i", Subject: "carol", Email: "carol@example.com", Role: "member"})
	require.NoError(err)
	assert.True(disabled.Disabled, "a login does not re-enable a disabled user")

	_, err = st.GetUser(ctx, 424242)
	assert.ErrorIs(err, store.ErrUserNotFound)
	assert.ErrorIs(st.SetUserDisabled(ctx, 424242, false), store.ErrUserNotFound)
}
