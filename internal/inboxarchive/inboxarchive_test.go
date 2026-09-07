package inboxarchive_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/inboxarchive"
	"go.kenn.io/msgvault/internal/store"
	"go.kenn.io/msgvault/internal/testutil"
)

// fakeProvider stands in for the mail provider only. The store, the label
// writes and the Archiver itself are real, so what these tests exercise is the
// production convergence path.
type fakeProvider struct {
	calls     [][]string
	failures  map[string]error
	fatalOn   int // 1-based index of the call that fails outright; 0 = never
	fatalErr  error
	callCount int
}

func (f *fakeProvider) ArchiveFromInbox(
	_ context.Context, ids []string,
) (map[string]error, error) {
	f.callCount++
	f.calls = append(f.calls, append([]string(nil), ids...))
	if f.fatalOn == f.callCount {
		err := f.fatalErr
		if err == nil {
			err = errors.New("provider refused the batch")
		}
		return nil, err
	}
	if len(f.failures) == 0 {
		return nil, nil
	}
	out := map[string]error{}
	for _, id := range ids {
		if err, ok := f.failures[id]; ok {
			out[id] = err
		}
	}
	return out, nil
}

type fixture struct {
	t      *testing.T
	store  *store.Store
	source *store.Source
	inbox  int64
	rows   map[string]int64
}

func newFixture(t *testing.T, sourceMessageIDs ...string) *fixture {
	t.Helper()
	require := require.New(t)
	st := testutil.NewTestStore(t)

	source, err := st.GetOrCreateSource("gmail", "alice@example.com")
	require.NoError(err)
	conv, err := st.EnsureConversation(source.ID, "thread-a", "Thread A")
	require.NoError(err)
	inbox, err := st.EnsureLabel(source.ID, "INBOX", "INBOX", "system")
	require.NoError(err)

	f := &fixture{t: t, store: st, source: source, inbox: inbox, rows: map[string]int64{}}
	for _, id := range sourceMessageIDs {
		rowID, err := st.UpsertMessage(&store.Message{
			ConversationID:  conv,
			SourceID:        source.ID,
			SourceMessageID: id,
			MessageType:     "email",
			SizeEstimate:    1024,
		})
		require.NoError(err)
		require.NoError(st.AddMessageLabels(rowID, []int64{inbox}))
		f.rows[id] = rowID
	}
	return f
}

// stillInInbox reports which of the fixture's messages still carry INBOX.
func (f *fixture) stillInInbox() []string {
	f.t.Helper()
	var out []string
	for id, rowID := range f.rows {
		var count int
		err := f.store.DB().QueryRow(f.store.Rebind(`
			SELECT COUNT(*) FROM message_labels ml
			JOIN labels l ON l.id = ml.label_id
			WHERE ml.message_id = ? AND l.name = 'INBOX'
		`), rowID).Scan(&count)
		require.NoError(f.t, err)
		if count > 0 {
			out = append(out, id)
		}
	}
	return out
}

func TestArchiveDropsLocalInboxLabel(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	f := newFixture(t, "msg-1", "msg-2", "msg-3")
	provider := &fakeProvider{}

	result, err := inboxarchive.New(provider, f.store).
		Archive(context.Background(), f.source, []string{"msg-1", "msg-2"})
	require.NoError(err)

	assert.Equal(2, result.Requested)
	assert.Equal(2, result.Archived)
	assert.Zero(result.Failed)
	assert.Equal([]string{"msg-1", "msg-2"}, result.ArchivedIDs)
	assert.Equal([]string{"msg-3"}, f.stillInInbox(),
		"only the requested messages leave the inbox")
}

// TestArchiveConvergesEachChunkBeforeTheNext is the property that makes an
// interrupted run safe to repeat: when a later chunk fails, the earlier ones
// must already have lost the label locally, so re-running the same
// inbox-scoped selection continues rather than starting over.
func TestArchiveConvergesEachChunkBeforeTheNext(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	f := newFixture(t, "msg-1", "msg-2", "msg-3", "msg-4", "msg-5")
	provider := &fakeProvider{fatalOn: 3}

	result, err := inboxarchive.New(provider, f.store).
		WithChunkSize(2).
		Archive(context.Background(), f.source,
			[]string{"msg-1", "msg-2", "msg-3", "msg-4", "msg-5"})

	require.Error(err, "the third chunk was refused")
	assert.Equal(4, result.Archived)
	assert.Equal(1, result.Remaining)
	assert.ElementsMatch([]string{"msg-5"}, f.stillInInbox())
	assert.Len(provider.calls, 3)
	assert.Equal([]string{"msg-1", "msg-2"}, provider.calls[0])
	assert.Equal([]string{"msg-5"}, provider.calls[2])
}

func TestArchiveIsIdempotent(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	f := newFixture(t, "msg-1", "msg-2")
	provider := &fakeProvider{}
	archiver := inboxarchive.New(provider, f.store)
	ids := []string{"msg-1", "msg-2"}

	_, err := archiver.Archive(context.Background(), f.source, ids)
	require.NoError(err)

	second, err := archiver.Archive(context.Background(), f.source, ids)
	require.NoError(err, "re-archiving an already archived message is not an error")
	assert.Equal(2, second.Archived)
	assert.Empty(f.stillInInbox())
}

func TestArchiveReportsPerMessageFailures(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	f := newFixture(t, "msg-1", "msg-2", "msg-3")
	provider := &fakeProvider{
		failures: map[string]error{"msg-2": errors.New("no such message")},
	}

	result, err := inboxarchive.New(provider, f.store).
		Archive(context.Background(), f.source, []string{"msg-1", "msg-2", "msg-3"})
	require.NoError(err)

	assert.Equal(2, result.Archived)
	assert.Equal(1, result.Failed)
	assert.Equal([]string{"msg-2"}, result.FailedIDs)
	assert.Equal([]string{"msg-2"}, f.stillInInbox(),
		"a message the provider refused must keep its local label")
}

// TestArchiveYieldsBetweenChunks: a long run must be able to step aside for a
// waiting request instead of holding the daemon's serial operation gate. What
// it archived stays archived, and Remaining tells the caller to come back.
func TestArchiveYieldsBetweenChunks(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	f := newFixture(t, "msg-1", "msg-2", "msg-3", "msg-4")
	provider := &fakeProvider{}

	checks := 0
	result, err := inboxarchive.New(provider, f.store).
		WithChunkSize(2).
		WithYieldCheck(func() bool {
			checks++
			return true
		}).
		Archive(context.Background(), f.source,
			[]string{"msg-1", "msg-2", "msg-3", "msg-4"})

	require.NoError(err, "yielding is not a failure")
	assert.True(result.Yielded)
	assert.Equal(2, result.Archived)
	assert.Equal(2, result.Remaining)
	assert.Len(provider.calls, 1, "no further provider calls after yielding")
	assert.Equal(1, checks, "the check runs between chunks, not before the first")
	assert.ElementsMatch([]string{"msg-3", "msg-4"}, f.stillInInbox())
}

func TestArchiveHonoursContextCancellation(t *testing.T) {
	assert := assert.New(t)

	f := newFixture(t, "msg-1", "msg-2")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	provider := &fakeProvider{}
	_, err := inboxarchive.New(provider, f.store).
		Archive(ctx, f.source, []string{"msg-1", "msg-2"})

	assert.ErrorIs(err, context.Canceled)
	assert.Empty(provider.calls)
}

// TestForRejectsSourcesThatCannotArchive covers Slack, Teams and every
// imported archive: they reach the same handler and must be refused by name,
// not by a nil dereference.
func TestForRejectsSourcesThatCannotArchive(t *testing.T) {
	assert := assert.New(t)

	_, err := inboxarchive.For(struct{}{}, nil)
	assert.ErrorIs(err, inboxarchive.ErrNotSupported)

	archiver, err := inboxarchive.For(&fakeProvider{}, nil)
	assert.NoError(err)
	assert.NotNil(archiver)
}
