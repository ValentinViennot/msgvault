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
	require.ErrorIs(err, store.ErrUserEmailRequired)
	_, err = st.RecordUserLogin(ctx, store.UserLogin{Email: "x@example.com"})
	require.ErrorIs(err, store.ErrUserIdentityRequired)
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
	require.ErrorIs(err, store.ErrUserNotFound)
	require.ErrorIs(st.SetUserDisabled(ctx, 424242, false), store.ErrUserNotFound)
}

func TestUserSourcesBinding(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	st := testutil.NewTestStore(t)
	ctx := t.Context()
	one, err := st.GetOrCreateSource("gmail", "one@example.com")
	require.NoError(err)
	two, err := st.GetOrCreateSource("gmail", "two@example.com")
	require.NoError(err)
	alice, err := st.RecordUserLogin(ctx, store.UserLogin{Issuer: "i", Subject: "alice", Email: "alice@example.com", Role: "member"})
	require.NoError(err)

	none, err := st.ListUserSourceIDs(ctx, alice.ID)
	require.NoError(err)
	assert.NotNil(none, "an unbound user gets an empty, fail-closed scope")
	assert.Empty(none)

	require.NoError(st.SetUserSources(ctx, alice.ID, []int64{two.ID, one.ID, one.ID}))
	bound, err := st.ListUserSourceIDs(ctx, alice.ID)
	require.NoError(err)
	assert.Equal([]int64{one.ID, two.ID}, bound, "bindings are unique and ordered")

	require.ErrorIs(st.SetUserSources(ctx, alice.ID, []int64{one.ID, 424242}), store.ErrSourceNotFound)
	still, err := st.ListUserSourceIDs(ctx, alice.ID)
	require.NoError(err)
	assert.Equal([]int64{one.ID, two.ID}, still, "a failed replacement leaves the bindings untouched")

	require.NoError(st.SetUserSources(ctx, alice.ID, nil))
	cleared, err := st.ListUserSourceIDs(ctx, alice.ID)
	require.NoError(err)
	assert.Empty(cleared)
	require.ErrorIs(st.SetUserSources(ctx, 424242, nil), store.ErrUserNotFound)

	byEmail, err := st.GetUserByEmail(ctx, "ALICE@example.com")
	require.NoError(err)
	assert.Equal(alice.ID, byEmail.ID)
	byIdentity, err := st.GetUserByIdentity(ctx, "i", "alice")
	require.NoError(err)
	assert.Equal(alice.ID, byIdentity.ID)
	_, err = st.GetUserByIdentity(ctx, "i", "nobody")
	require.ErrorIs(err, store.ErrUserNotFound)
}
