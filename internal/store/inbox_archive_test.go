package store_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/store"
	"go.kenn.io/msgvault/internal/testutil"
)

type labelFixture struct {
	t       *testing.T
	store   *store.Store
	source  *store.Source
	other   *store.Source
	inbox   int64
	work    int64
	rowByID map[string]int64
}

func newLabelFixture(t *testing.T) *labelFixture {
	t.Helper()
	require := require.New(t)
	st := testutil.NewTestStore(t)

	source, err := st.GetOrCreateSource("gmail", "alice@example.com")
	require.NoError(err)
	other, err := st.GetOrCreateSource("gmail", "bob@example.com")
	require.NoError(err)
	conv, err := st.EnsureConversation(source.ID, "thread-a", "Thread A")
	require.NoError(err)
	otherConv, err := st.EnsureConversation(other.ID, "thread-b", "Thread B")
	require.NoError(err)

	inbox, err := st.EnsureLabel(source.ID, "INBOX", "INBOX", "system")
	require.NoError(err)
	work, err := st.EnsureLabel(source.ID, "Label_1", "Work", "user")
	require.NoError(err)

	f := &labelFixture{
		t: t, store: st, source: source, other: other,
		inbox: inbox, work: work, rowByID: map[string]int64{},
	}

	// Three of alice's messages are in the inbox, one of them also tagged Work.
	// A fourth was never in the inbox at all.
	f.add("msg-1", source.ID, conv, inbox)
	f.add("msg-2", source.ID, conv, inbox, work)
	f.add("msg-3", source.ID, conv, inbox)
	f.add("msg-4", source.ID, conv, work)

	// Bob has a message with the same source_message_id, to prove scoping.
	bobInbox, err := st.EnsureLabel(other.ID, "INBOX", "INBOX", "system")
	require.NoError(err)
	f.add("msg-1", other.ID, otherConv, bobInbox)

	return f
}

func (f *labelFixture) add(sourceMessageID string, sourceID, convID int64, labelIDs ...int64) {
	f.t.Helper()
	id, err := f.store.UpsertMessage(&store.Message{
		ConversationID:  convID,
		SourceID:        sourceID,
		SourceMessageID: sourceMessageID,
		MessageType:     "email",
		SizeEstimate:    1024,
	})
	require.NoError(f.t, err)
	require.NoError(f.t, f.store.AddMessageLabels(id, labelIDs))
	if sourceID == f.source.ID {
		f.rowByID[sourceMessageID] = id
	}
}

// labels reads the label names still linked to one of alice's messages.
func (f *labelFixture) labels(sourceMessageID string) []string {
	f.t.Helper()
	rows, err := f.store.DB().Query(f.store.Rebind(`
		SELECT l.name FROM message_labels ml
		JOIN labels l ON l.id = ml.label_id
		WHERE ml.message_id = ?
		ORDER BY l.name
	`), f.rowByID[sourceMessageID])
	require.NoError(f.t, err)
	defer func() { require.NoError(f.t, rows.Close()) }()

	var names []string
	for rows.Next() {
		var name string
		require.NoError(f.t, rows.Scan(&name))
		names = append(names, name)
	}
	require.NoError(f.t, rows.Err())
	return names
}

func TestRemoveLabelBySourceMessageIDs(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newLabelFixture(t)

	removed, err := f.store.RemoveLabelBySourceMessageIDs(
		f.source.ID, "INBOX", []string{"msg-1", "msg-2", "msg-4"})
	require.NoError(err)

	// msg-4 never had INBOX, so only two links go.
	assert.Equal(int64(2), removed)
	assert.Empty(f.labels("msg-1"))
	assert.Equal([]string{"Work"}, f.labels("msg-2"), "other labels survive")
	assert.Equal([]string{"INBOX"}, f.labels("msg-3"), "untargeted message untouched")
	assert.Equal([]string{"Work"}, f.labels("msg-4"))
}

// TestRemoveLabelBySourceMessageIDsIsScopedToSource: source_message_id is only
// unique within a source, so an unscoped delete would archive another account's
// mail. msg-1 exists under both accounts here.
func TestRemoveLabelBySourceMessageIDsIsScopedToSource(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newLabelFixture(t)

	_, err := f.store.RemoveLabelBySourceMessageIDs(
		f.source.ID, "INBOX", []string{"msg-1"})
	require.NoError(err)

	removed, err := f.store.RemoveLabelBySourceMessageIDs(
		f.other.ID, "INBOX", []string{"msg-1"})
	require.NoError(err)
	assert.Equal(int64(1), removed, "bob's copy was still labelled after alice's removal")
}

// TestRemoveLabelBySourceMessageIDsIsIdempotent underpins interrupted runs:
// re-archiving a batch that partly succeeded must not error.
func TestRemoveLabelBySourceMessageIDsIsIdempotent(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	f := newLabelFixture(t)

	ids := []string{"msg-1", "msg-2", "msg-3"}
	first, err := f.store.RemoveLabelBySourceMessageIDs(f.source.ID, "INBOX", ids)
	require.NoError(err)
	assert.Equal(int64(3), first)

	second, err := f.store.RemoveLabelBySourceMessageIDs(f.source.ID, "INBOX", ids)
	require.NoError(err)
	assert.Zero(second, "second pass has nothing left to remove")
}

func TestRemoveLabelBySourceMessageIDsRejectsUnscopedCalls(t *testing.T) {
	assert := assert.New(t)
	f := newLabelFixture(t)

	_, err := f.store.RemoveLabelBySourceMessageIDs(0, "INBOX", []string{"msg-1"})
	assert.Error(err, "an unscoped removal could touch another account")

	_, err = f.store.RemoveLabelBySourceMessageIDs(f.source.ID, "", []string{"msg-1"})
	assert.Error(err)

	removed, err := f.store.RemoveLabelBySourceMessageIDs(f.source.ID, "INBOX", nil)
	assert.NoError(err)
	assert.Zero(removed)
}
