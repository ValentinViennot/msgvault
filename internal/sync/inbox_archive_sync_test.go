package sync

import (
	"context"
	"testing"

	imapv2 "github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/inboxarchive"
	"go.kenn.io/msgvault/internal/store"
	"go.kenn.io/msgvault/internal/testutil"
)

// countMessages reports how many message rows exist, which is the number these
// tests actually care about: archiving must not leave a second copy behind.
func countMessages(t *testing.T, st *store.Store) int {
	t.Helper()
	var count int
	require.NoError(t, st.DB().QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&count))
	return count
}

func imapSourceMessageID(t *testing.T, st *store.Store) string {
	t.Helper()
	var id string
	require.NoError(t, st.DB().QueryRow(
		`SELECT source_message_id FROM messages LIMIT 1`).Scan(&id))
	return id
}

// TestIMAPArchiveFromInboxConvergesToOneRowOnResync is the round trip that
// proves the archive and the mailbox stay in step on IMAP.
//
// Archiving moves the message between mailboxes, and a message's IMAP
// source_message_id is "mailbox|uid", so the move changes its key. Nothing in
// the archive path rewrites that key: sync owns it, and rejoins the moved
// message to its existing row by RFC822 Message-ID. If that hand-off did not
// work, the second full sync would file the message as a new one and the
// archive would quietly hold two copies of it.
func TestIMAPArchiveFromInboxConvergesToOneRowOnResync(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	env := newTestEnv(t)
	opts := DefaultOptions()
	opts.SourceType = sourceTypeIMAP

	const messageID = "archived-from-inbox@example.com"
	addr, user := testutil.StartIMAPMemServerWithSpecialUse(t,
		map[string]int{"INBOX": 0, "Archive": 0},
		map[string][]imapv2.MailboxAttr{"Archive": {imapv2.MailboxAttrArchive}})
	testutil.AppendIMAPMessageWithMessageID(t, user, "INBOX", messageID)

	firstClient := newSyncTestIMAPClient(t, addr)
	env.Syncer = New(firstClient, env.Store, opts)
	assertSummary(t, runFullSync(t, env), WantSummary{Added: new(int64(1))})
	assertMessageHasLabel(t, env.Store, "INBOX|1", "INBOX")

	source, err := env.Store.GetOrCreateSource(sourceTypeIMAP, testEmail)
	require.NoError(err)

	// Archive through the production archiver rather than the raw client, so
	// the local INBOX-label write is exercised alongside the provider move.
	result, err := inboxarchive.New(firstClient, env.Store).
		Archive(env.Context, source, []string{"INBOX|1"})
	require.NoError(err)
	assert.Equal(1, result.Archived)
	assertMessageNotHasLabel(t, env.Store, "INBOX|1", "INBOX")
	require.NoError(firstClient.Close())

	secondClient := newSyncTestIMAPClient(t, addr)
	env.Syncer = New(secondClient, env.Store, opts)
	assertSummary(t, runFullSync(t, env), WantSummary{Added: new(int64(0))})

	assert.Equal(1, countMessages(t, env.Store),
		"the moved message must rejoin its row, not create a second one")
	sourceMessageID := imapSourceMessageID(t, env.Store)
	assert.Equal("Archive|1", sourceMessageID, "sync re-keys the moved message")
	assertMessageHasLabel(t, env.Store, sourceMessageID, "Archive")
	assertMessageNotHasLabel(t, env.Store, sourceMessageID, "INBOX")
}

// TestIMAPArchiveWithoutMessageIDWouldDuplicate documents why the archive path
// refuses IMAP messages that carry no Message-ID header, instead of asserting
// the exclusion against a fixture that could never have failed.
//
// The rejoin in the test above works by matching RFC822 Message-ID. With no
// such header there is nothing to match on, so the same sequence leaves the
// archive holding the message twice. That is the outcome the planner's
// exclusion exists to prevent.
func TestIMAPArchiveWithoutMessageIDWouldDuplicate(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	env := newTestEnv(t)
	opts := DefaultOptions()
	opts.SourceType = sourceTypeIMAP

	addr, user := testutil.StartIMAPMemServerWithSpecialUse(t,
		map[string]int{"INBOX": 0, "Archive": 0},
		map[string][]imapv2.MailboxAttr{"Archive": {imapv2.MailboxAttrArchive}})
	testutil.AppendIMAPMessageWithoutMessageID(t, user, "INBOX",
		"From: sender@example.com\r\nSubject: No Message-ID\r\n\r\nbody\r\n")

	firstClient := newSyncTestIMAPClient(t, addr)
	env.Syncer = New(firstClient, env.Store, opts)
	assertSummary(t, runFullSync(t, env), WantSummary{Added: new(int64(1))})

	source, err := env.Store.GetOrCreateSource(sourceTypeIMAP, testEmail)
	require.NoError(err)

	// The store reports this message as unarchivable, and the daemon excludes
	// it on exactly this basis.
	unarchivable, err := env.Store.SourceMessageIDsMissingRFC822ID(
		source.ID, []string{"INBOX|1"})
	require.NoError(err)
	assert.Equal([]string{"INBOX|1"}, unarchivable,
		"a message with no Message-ID header must be reported as unarchivable")

	// Archive it anyway, to show what the exclusion is protecting against.
	_, err = inboxarchive.New(firstClient, env.Store).
		Archive(env.Context, source, []string{"INBOX|1"})
	require.NoError(err)
	require.NoError(firstClient.Close())

	secondClient := newSyncTestIMAPClient(t, addr)
	env.Syncer = New(secondClient, env.Store, opts)
	assertSummary(t, runFullSync(t, env), WantSummary{Added: new(int64(1))})

	assert.Equal(2, countMessages(t, env.Store),
		"without a Message-ID sync cannot rejoin the moved message, so it duplicates")
}

// TestGmailArchiveThenIncrementalSyncIsNoOp is the Gmail half of the round
// trip. Archiving removes the INBOX label locally straight away so the vault is
// right immediately; the provider then reports the same change as a history
// LabelsRemoved record. The two paths must land on the same state, and applying
// the record afterwards must not resurrect the label, count as new work, or add
// a row.
func TestGmailArchiveThenIncrementalSyncIsNoOp(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	env := newTestEnv(t)
	env.Mock.Profile.MessagesTotal = 1
	env.Mock.Profile.HistoryID = 12340
	env.Mock.AddMessage("msg1", testMIME(), []string{"INBOX", "STARRED"})

	runFullSync(t, env)
	assertMessageHasLabel(t, env.Store, "msg1", "INBOX")

	source, err := env.Store.GetOrCreateSource("gmail", testEmail)
	require.NoError(err)

	result, err := inboxarchive.New(&stubGmailInboxArchiver{}, env.Store).
		Archive(env.Context, source, []string{"msg1"})
	require.NoError(err)
	assert.Equal(1, result.Archived)
	assertMessageNotHasLabel(t, env.Store, "msg1", "INBOX")
	assertMessageHasLabel(t, env.Store, "msg1", "STARRED")

	// The provider now reports the archive it just performed.
	env.SetHistory(12350, historyLabelRemoved("msg1", "INBOX"))
	runIncrementalSync(t, env)

	assertMessageNotHasLabel(t, env.Store, "msg1", "INBOX")
	assertMessageHasLabel(t, env.Store, "msg1", "STARRED")
	assert.Equal(1, countMessages(t, env.Store))
}

// TestGmailRemoteArchiveConvergesLocally is the other direction: the user
// archives in Gmail and sync alone brings the vault into line.
func TestGmailRemoteArchiveConvergesLocally(t *testing.T) {
	assert := assert.New(t)

	env := newTestEnv(t)
	env.Mock.Profile.MessagesTotal = 1
	env.Mock.Profile.HistoryID = 12340
	env.Mock.AddMessage("msg1", testMIME(), []string{"INBOX", "STARRED"})

	runFullSync(t, env)
	assertMessageHasLabel(t, env.Store, "msg1", "INBOX")

	env.SetHistory(12350, historyLabelRemoved("msg1", "INBOX"))
	runIncrementalSync(t, env)

	assertMessageNotHasLabel(t, env.Store, "msg1", "INBOX")
	assertMessageHasLabel(t, env.Store, "msg1", "STARRED")
	assert.Equal(1, countMessages(t, env.Store))
}

// stubGmailInboxArchiver stands in for the Gmail API. What these tests are
// about is the convergence between the archive path's local write and sync's
// own handling of the same change, so the provider call itself is the only
// thing faked.
type stubGmailInboxArchiver struct{ calls [][]string }

func (s *stubGmailInboxArchiver) ArchiveFromInbox(
	_ context.Context, ids []string,
) (map[string]error, error) {
	s.calls = append(s.calls, append([]string(nil), ids...))
	return map[string]error{}, nil
}
