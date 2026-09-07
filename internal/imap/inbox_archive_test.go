package imap

import (
	"context"
	"fmt"
	"testing"
	"time"

	imapv2 "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
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

// mailboxUIDs lists the UIDs currently present in one mailbox, by asking the
// server rather than by trusting anything the client cached.
func mailboxUIDs(t *testing.T, addr, mailbox string) []imapv2.UID {
	t.Helper()
	client := newTestClient(t, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var uids []imapv2.UID
	require.NoError(t, client.withConn(ctx, func(conn *imapclient.Client) error {
		if err := client.selectMailbox(mailbox); err != nil {
			return err
		}
		criteria := &imapv2.SearchCriteria{UID: []imapv2.UIDSet{{{Start: 1, Stop: 0}}}}
		data, err := conn.UIDSearch(criteria, nil).Wait()
		if err != nil {
			return fmt.Errorf("UID SEARCH in %q: %w", mailbox, err)
		}
		uids = data.AllUIDs()
		return nil
	}))
	return uids
}

func TestArchiveFromInboxMovesMessageOutOfTheInbox(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	addr, _ := testutil.StartIMAPMemServerWithSpecialUse(t,
		map[string]int{"INBOX": 2, "Archive": 0},
		map[string][]imapv2.MailboxAttr{"Archive": {imapv2.MailboxAttrArchive}})
	client := newTestClient(t, addr)

	before := mailboxUIDs(t, addr, "INBOX")
	require.Len(before, 2)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	failures, err := client.ArchiveFromInbox(ctx,
		[]string{compositeID("INBOX", before[0])})
	require.NoError(err)
	assert.Empty(failures)

	assert.Equal([]imapv2.UID{before[1]}, mailboxUIDs(t, addr, "INBOX"),
		"only the archived message leaves the inbox")
	assert.Len(mailboxUIDs(t, addr, "Archive"), 1,
		"the message must arrive in the archive mailbox, not vanish")
}

// TestArchiveFromInboxIsIdempotent: a message already in the destination is at
// the end state the caller asked for, so repeating a partly-completed batch
// must not fail.
func TestArchiveFromInboxIsIdempotent(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	addr, _ := testutil.StartIMAPMemServerWithSpecialUse(t,
		map[string]int{"INBOX": 1, "Archive": 1},
		map[string][]imapv2.MailboxAttr{"Archive": {imapv2.MailboxAttrArchive}})
	client := newTestClient(t, addr)

	archived := mailboxUIDs(t, addr, "Archive")
	require.Len(archived, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	failures, err := client.ArchiveFromInbox(ctx,
		[]string{compositeID("Archive", archived[0])})

	require.NoError(err)
	assert.Empty(failures)
	assert.Len(mailboxUIDs(t, addr, "Archive"), 1, "no self-move, no duplicate")
}

// TestArchiveFromInboxReportsPerMessageFailures: one bad id must not abandon
// the rest of the batch, and must not be reported as archived.
func TestArchiveFromInboxReportsPerMessageFailures(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	addr, _ := testutil.StartIMAPMemServerWithSpecialUse(t,
		map[string]int{"INBOX": 1, "Archive": 0},
		map[string][]imapv2.MailboxAttr{"Archive": {imapv2.MailboxAttrArchive}})
	client := newTestClient(t, addr)

	inbox := mailboxUIDs(t, addr, "INBOX")
	require.Len(inbox, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	failures, err := client.ArchiveFromInbox(ctx, []string{
		"not-a-composite-id",
		compositeID("INBOX", inbox[0]),
	})

	require.NoError(err)
	require.Len(failures, 1)
	assert.Contains(failures, "not-a-composite-id")
	assert.Empty(mailboxUIDs(t, addr, "INBOX"),
		"the valid message is still archived")
}

func TestArchiveFromInboxRefusesWithoutAnArchiveMailbox(t *testing.T) {
	assert := assert.New(t)

	addr, _ := testutil.StartIMAPMemServerWithSpecialUse(t,
		map[string]int{"INBOX": 1}, nil)
	client := newTestClient(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := client.ArchiveFromInbox(ctx, []string{"INBOX|1"})

	assert.ErrorIs(err, ErrNoArchiveMailbox)
}

// TestArchiveFromInboxRefusesGmailLayoutBeforeMoving is the safety property:
// zero MOVE commands are issued for a Gmail-over-IMAP account, because the
// stored ids address All Mail rather than the inbox copy.
func TestArchiveFromInboxRefusesGmailLayoutBeforeMoving(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	addr, _ := testutil.StartIMAPMemServerWithSpecialUse(t,
		map[string]int{"INBOX": 1, "[Gmail]/All Mail": 1, "Archive": 0},
		map[string][]imapv2.MailboxAttr{"[Gmail]/All Mail": {imapv2.MailboxAttrAll}})
	client := newTestClient(t, addr)

	allMail := mailboxUIDs(t, addr, "[Gmail]/All Mail")
	require.Len(allMail, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := client.ArchiveFromInbox(ctx,
		[]string{compositeID("[Gmail]/All Mail", allMail[0])})

	require.ErrorIs(err, ErrNoArchiveMailbox)
	assert.Len(mailboxUIDs(t, addr, "[Gmail]/All Mail"), 1, "nothing may have moved")
	assert.Len(mailboxUIDs(t, addr, "INBOX"), 1)
}

// TestArchiveFromInboxRefusesDestinationOutsideFolderFilter: moving a message
// into an excluded folder would drop it out of every future sync's view, which
// reads as the message having disappeared from the archive.
func TestArchiveFromInboxRefusesDestinationOutsideFolderFilter(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	addr, _ := testutil.StartIMAPMemServerWithSpecialUse(t,
		map[string]int{"INBOX": 1, "Archive": 0},
		map[string][]imapv2.MailboxAttr{"Archive": {imapv2.MailboxAttrArchive}})
	client := newTestClient(t, addr, WithFolderFilter(nil, []string{"Archive"}))

	inbox := mailboxUIDs(t, addr, "INBOX")
	require.Len(inbox, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := client.ArchiveFromInbox(ctx, []string{compositeID("INBOX", inbox[0])})

	require.ErrorIs(err, ErrNoArchiveMailbox)
	assert.Len(mailboxUIDs(t, addr, "INBOX"), 1, "nothing may have moved")
}
