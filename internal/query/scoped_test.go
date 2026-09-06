package query

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/search"
)

// knownOptionalInterfaces lists every capability callers detect on an engine
// by type assertion. A wrapper must expose exactly the ones its inner engine
// has, or scoped callers would silently lose (or wrongly gain) features.
var knownOptionalInterfaces = []reflect.Type{
	reflect.TypeFor[Explorer](),
	reflect.TypeFor[PeopleAnalyzer](),
	reflect.TypeFor[PeopleCompleter](),
	reflect.TypeFor[PeopleInboxAnalyzer](),
	reflect.TypeFor[RelationshipAnalyzer](),
	reflect.TypeFor[RelationshipCalendarAnalyzer](),
	reflect.TypeFor[RelationshipCanonicalResolver](),
	reflect.TypeFor[FileSearcher](),
	reflect.TypeFor[FileGrouper](),
	reflect.TypeFor[MessageBodySearcher](),
	reflect.TypeFor[DeletionTargetSearchResolver](),
	reflect.TypeFor[DeletionTargetAggregateSearchResolver](),
	reflect.TypeFor[TextEngine](),
	reflect.TypeFor[TextSnapshotReader](),
	reflect.TypeFor[SQLQuerier](),
	reflect.TypeFor[SemanticMessageSearcher](),
}

// TestScopedEngineParity pins the wrapper to the production engines: every
// optional interface an engine implements must survive wrapping, and every
// exported method of the engine must exist on the wrapper so a new query path
// cannot bypass the scope.
func TestScopedEngineParity(t *testing.T) {
	for name, inner := range map[string]Engine{
		"duckdb": (*DuckDBEngine)(nil),
		"sqlite": (*SQLiteEngine)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			wrapped := NewScopedEngine(inner, []int64{1})
			innerType, wrappedType := reflect.TypeOf(inner), reflect.TypeOf(wrapped)
			for _, iface := range knownOptionalInterfaces {
				assert.Equal(t, innerType.Implements(iface), wrappedType.Implements(iface),
					"%s: wrapper must implement %s exactly when the engine does", name, iface)
			}
			for method := range innerType.Methods() {
				_, ok := wrappedType.MethodByName(method.Name)
				assert.True(t, ok, "%s: exported method %s is not scoped by the wrapper", name, method.Name)
			}
		})
	}
}

type recordingEngine struct {
	Engine

	filters   []MessageFilter
	queries   []*search.Query
	stats     []StatsOptions
	aggregate []AggregateOptions
	message   *MessageDetail
}

func (r *recordingEngine) ListMessages(_ context.Context, filter MessageFilter) ([]MessageSummary, error) {
	r.filters = append(r.filters, filter)
	return []MessageSummary{{ID: 1, SourceID: 1}, {ID: 2, SourceID: 2}}, nil
}

func (r *recordingEngine) Search(_ context.Context, q *search.Query, _, _ int) ([]MessageSummary, error) {
	r.queries = append(r.queries, q)
	return nil, nil
}

func (r *recordingEngine) GetTotalStats(_ context.Context, opts StatsOptions) (*TotalStats, error) {
	r.stats = append(r.stats, opts)
	return &TotalStats{}, nil
}

func (r *recordingEngine) Aggregate(_ context.Context, _ ViewType, opts AggregateOptions) ([]AggregateRow, error) {
	r.aggregate = append(r.aggregate, opts)
	return nil, nil
}

func (r *recordingEngine) GetMessage(context.Context, int64) (*MessageDetail, error) {
	return r.message, nil
}

func (r *recordingEngine) GetMessageRaw(context.Context, int64) ([]byte, error) {
	return []byte("raw"), nil
}

func (r *recordingEngine) GetMessageSummariesByIDs(context.Context, []int64) ([]MessageSummary, error) {
	return []MessageSummary{{ID: 1, SourceID: 1}, {ID: 2, SourceID: 2}, {ID: 3, SourceID: 3}}, nil
}

func (r *recordingEngine) ListAccounts(context.Context) ([]AccountInfo, error) {
	return []AccountInfo{{ID: 1}, {ID: 2}, {ID: 3}}, nil
}

func int64Ptr(v int64) *int64 { return new(v) }

func TestScopedEngineRestrictsFilters(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	inner := &recordingEngine{}
	engine := NewScopedEngine(inner, []int64{1, 3})
	ctx := t.Context()

	_, err := engine.ListMessages(ctx, MessageFilter{})
	require.NoError(err)
	_, err = engine.ListMessages(ctx, MessageFilter{SourceID: int64Ptr(3)})
	require.NoError(err)
	_, err = engine.ListMessages(ctx, MessageFilter{SourceIDs: []int64{2, 3, 4}})
	require.NoError(err)
	_, err = engine.ListMessages(ctx, MessageFilter{SourceID: int64Ptr(2)})
	require.NoError(err)
	require.Len(inner.filters, 4)
	assert.Equal([]int64{1, 3}, inner.filters[0].SourceIDs, "no request means the visible set")
	assert.Equal([]int64{3}, inner.filters[1].SourceIDs, "a single visible source is kept")
	assert.Equal([]int64{3}, inner.filters[2].SourceIDs, "invisible sources are dropped")
	assert.Equal([]int64{noVisibleSource}, inner.filters[3].SourceIDs, "an invisible source matches nothing")
	for _, filter := range inner.filters {
		assert.Nil(filter.SourceID)
	}

	_, err = engine.Search(ctx, &search.Query{AccountIDs: []int64{2}}, 10, 0)
	require.NoError(err)
	_, err = engine.Search(ctx, nil, 10, 0)
	require.NoError(err)
	assert.Equal([]int64{noVisibleSource}, inner.queries[0].AccountIDs)
	assert.Equal([]int64{1, 3}, inner.queries[1].AccountIDs)

	_, err = engine.GetTotalStats(ctx, StatsOptions{SourceID: int64Ptr(1)})
	require.NoError(err)
	assert.Equal([]int64{1}, inner.stats[0].SourceIDs)
	_, err = engine.Aggregate(ctx, ViewSenders, AggregateOptions{})
	require.NoError(err)
	assert.Equal([]int64{1, 3}, inner.aggregate[0].SourceIDs)
}

func TestScopedEnginePostFiltersLookups(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	inner := &recordingEngine{message: &MessageDetail{ID: 7, SourceID: 2}}
	engine := NewScopedEngine(inner, []int64{1})
	ctx := t.Context()

	message, err := engine.GetMessage(ctx, 7)
	require.NoError(err)
	assert.Nil(message, "a message from an invisible source is not found")
	raw, err := engine.GetMessageRaw(ctx, 7)
	require.NoError(err)
	assert.Nil(raw)

	inner.message = &MessageDetail{ID: 8, SourceID: 1}
	message, err = engine.GetMessage(ctx, 8)
	require.NoError(err)
	require.NotNil(message)
	raw, err = engine.GetMessageRaw(ctx, 8)
	require.NoError(err)
	assert.Equal([]byte("raw"), raw)

	summaries, err := engine.GetMessageSummariesByIDs(ctx, []int64{1, 2, 3})
	require.NoError(err)
	require.Len(summaries, 1)
	assert.Equal(int64(1), summaries[0].ID)
	accounts, err := engine.ListAccounts(ctx)
	require.NoError(err)
	require.Len(accounts, 1)
	assert.Equal(int64(1), accounts[0].ID)

	empty := NewScopedEngine(inner, nil)
	_, err = empty.ListMessages(ctx, MessageFilter{})
	require.NoError(err)
	assert.Equal([]int64{noVisibleSource}, inner.filters[len(inner.filters)-1].SourceIDs, "no visible source matches nothing")
	assert.NoError(engine.Close(), "closing the wrapper never closes the shared engine")
}

func TestScopedEngineTextViewsNeedOneSource(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)
	single := &scopedEngine{visible: []int64{4}, set: map[int64]struct{}{4: {}}}
	source, err := single.restrictSingle(nil)
	require.NoError(err)
	assert.Equal(int64(4), *source, "one visible source is the default")
	source, err = single.restrictSingle(int64Ptr(9))
	require.NoError(err)
	assert.Equal(noVisibleSource, *source, "an invisible source matches nothing")

	many := &scopedEngine{visible: []int64{4, 5}, set: map[int64]struct{}{4: {}, 5: {}}}
	_, err = many.restrictSingle(nil)
	require.ErrorIs(err, ErrScopeRequiresSource)
	source, err = many.restrictSingle(int64Ptr(5))
	require.NoError(err)
	assert.Equal(int64(5), *source)
}
