package imap

import (
	"context"
	"testing"
	"time"

	imapv2 "github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/testutil"
)

func archiveTargetFor(
	t *testing.T,
	mailboxes map[string]int,
	specialUse map[string][]imapv2.MailboxAttr,
) (string, bool, error) {
	t.Helper()
	addr, _ := testutil.StartIMAPMemServerWithSpecialUse(t, mailboxes, specialUse)
	client := newTestClient(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return client.InboxArchiveTarget(ctx)
}

// TestInboxArchiveTargetPrefersSpecialUse checks that \Archive wins over any
// conventionally named folder, so a server that tells us where its archive is
// is believed rather than guessed at.
func TestInboxArchiveTargetPrefersSpecialUse(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	mailbox, ok, err := archiveTargetFor(t,
		map[string]int{"INBOX": 1, "Archive": 0, "Long Term": 0},
		map[string][]imapv2.MailboxAttr{
			"Long Term": {imapv2.MailboxAttrArchive},
		})

	require.NoError(err)
	assert.True(ok)
	assert.Equal("Long Term", mailbox)
}

// TestInboxArchiveTargetFallsBackToConventionalName covers servers that do not
// advertise special-use at all, mirroring the existing Trash/Junk fallbacks.
func TestInboxArchiveTargetFallsBackToConventionalName(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	mailbox, ok, err := archiveTargetFor(t,
		map[string]int{"INBOX": 1, "Archive": 0}, nil)

	require.NoError(err)
	assert.True(ok)
	assert.Equal("Archive", mailbox)
}

// TestInboxArchiveTargetWithoutAnyArchiveMailbox: nowhere to move the message
// to is a refusal, not a guess.
func TestInboxArchiveTargetWithoutAnyArchiveMailbox(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	mailbox, ok, err := archiveTargetFor(t, map[string]int{"INBOX": 1}, nil)

	require.NoError(err)
	assert.False(ok)
	assert.Empty(mailbox)
}

// TestInboxArchiveTargetRefusesGmailLayout is the important one. For a Gmail
// IMAP account, enumeration covers All Mail, Trash and Junk but never INBOX, so
// no stored source_message_id addresses the inbox copy and there is nothing to
// MOVE. The refusal must hold even when a conventionally named "Archive" folder
// exists, which is why this fixture supplies one.
func TestInboxArchiveTargetRefusesGmailLayout(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	mailbox, ok, err := archiveTargetFor(t,
		map[string]int{"INBOX": 1, "[Gmail]/All Mail": 1, "Archive": 0},
		map[string][]imapv2.MailboxAttr{
			"[Gmail]/All Mail": {imapv2.MailboxAttrAll},
		})

	require.NoError(err)
	assert.False(ok, "Gmail-over-IMAP must be refused, not archived")
	assert.Empty(mailbox)
}

// TestIsGmailAllMailLayoutAfterDiscovery pins the detection itself, which the
// planner also needs in order to explain the refusal.
func TestIsGmailAllMailLayoutAfterDiscovery(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	addr, _ := testutil.StartIMAPMemServerWithSpecialUse(t,
		map[string]int{"INBOX": 1, "[Gmail]/All Mail": 1},
		map[string][]imapv2.MailboxAttr{
			"[Gmail]/All Mail": {imapv2.MailboxAttrAll},
		})
	client := newTestClient(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, _, err := client.InboxArchiveTarget(ctx)
	require.NoError(err)

	assert.True(client.IsGmailAllMailLayout())
}
