package query

import (
	"context"
	"errors"
	"slices"
	"time"

	"go.kenn.io/msgvault/internal/search"
)

// ErrScopeRequiresSource is returned by the text views when a caller who may
// see several sources asks for a view that can only be filtered to one.
var ErrScopeRequiresSource = errors.New("this view covers one source at a time; pass source_id")

// ErrScopedSQL is returned when a scoped caller reaches the raw SQL query
// path, which cannot be confined to a set of sources.
var ErrScopedSQL = errors.New("raw SQL queries are not available to scoped callers")

// noVisibleSource is an ID no source can have. It is substituted for an empty
// scope so every engine runs its normal query and returns a well-formed empty
// result instead of interpreting "no filter" as "every source".
const noVisibleSource int64 = -1

// NewScopedEngine confines every query on inner to the given sources. The
// wrapper exposes exactly the optional interfaces inner implements, so
// capability detection in callers keeps working; TestScopedEngineParity
// enforces that for the production engines.
func NewScopedEngine(inner Engine, visible []int64) Engine {
	base := &scopedEngine{inner: inner, visible: slices.Clone(visible), set: make(map[int64]struct{}, len(visible))}
	for _, id := range visible {
		base.set[id] = struct{}{}
	}
	if _, ok := inner.(Explorer); ok {
		return &scopedAnalyticalEngine{scopedTextEngine: &scopedTextEngine{scopedEngine: base}}
	}
	if _, ok := inner.(TextEngine); ok {
		return &scopedTextEngine{scopedEngine: base}
	}
	return base
}

type scopedEngine struct {
	inner   Engine
	visible []int64
	set     map[int64]struct{}
}

func (s *scopedEngine) sees(id int64) bool {
	_, ok := s.set[id]
	return ok
}

// restrict intersects a requested source set with the visible one. A nil
// request means "everything", which becomes the visible set; an intersection
// with nothing left becomes the impossible source.
func (s *scopedEngine) restrict(requested []int64) []int64 {
	var out []int64
	if requested == nil {
		out = slices.Clone(s.visible)
	} else {
		out = make([]int64, 0, len(requested))
		for _, id := range requested {
			if s.sees(id) {
				out = append(out, id)
			}
		}
	}
	if len(out) == 0 {
		return []int64{noVisibleSource}
	}
	return out
}

func (s *scopedEngine) restrictFilter(filter MessageFilter) MessageFilter {
	requested := filter.SourceIDs
	if requested == nil && filter.SourceID != nil {
		requested = []int64{*filter.SourceID}
	}
	filter.SourceIDs = s.restrict(requested)
	filter.SourceID = nil
	return filter
}

func (s *scopedEngine) restrictAggregate(opts AggregateOptions) AggregateOptions {
	requested := opts.SourceIDs
	if requested == nil && opts.SourceID != nil {
		requested = []int64{*opts.SourceID}
	}
	opts.SourceIDs = s.restrict(requested)
	opts.SourceID = nil
	return opts
}

func (s *scopedEngine) restrictStats(opts StatsOptions) StatsOptions {
	requested := opts.SourceIDs
	if requested == nil && opts.SourceID != nil {
		requested = []int64{*opts.SourceID}
	}
	opts.SourceIDs = s.restrict(requested)
	opts.SourceID = nil
	return opts
}

func (s *scopedEngine) restrictQuery(q *search.Query) *search.Query {
	if q == nil {
		q = &search.Query{}
	}
	clone := *q
	clone.AccountIDs = s.restrict(q.AccountIDs)
	return &clone
}

func (s *scopedEngine) restrictContext(analytical Context) Context {
	analytical.SourceIDs = s.restrict(analytical.SourceIDs)
	return analytical
}

func (s *scopedEngine) restrictExplore(request ExploreRequest) ExploreRequest {
	request.Context = s.restrictContext(request.Context)
	return request
}

// restrictSingle handles the text views, which filter to one source: a
// requested source must be visible, and a caller who sees exactly one source
// gets it by default. A caller who sees several must name one.
func (s *scopedEngine) restrictSingle(requested *int64) (*int64, error) {
	if requested != nil {
		if s.sees(*requested) {
			return requested, nil
		}
		none := noVisibleSource
		return &none, nil
	}
	switch len(s.visible) {
	case 0:
		none := noVisibleSource
		return &none, nil
	case 1:
		only := s.visible[0]
		return &only, nil
	}
	return nil, ErrScopeRequiresSource
}

func (s *scopedEngine) restrictTextFilter(filter TextFilter) (TextFilter, error) {
	source, err := s.restrictSingle(filter.SourceID)
	if err != nil {
		return filter, err
	}
	filter.SourceID = source
	return filter, nil
}

func (s *scopedEngine) visibleSummaries(rows []MessageSummary) []MessageSummary {
	out := make([]MessageSummary, 0, len(rows))
	for _, row := range rows {
		if s.sees(row.SourceID) {
			out = append(out, row)
		}
	}
	return out
}

// --- Engine ------------------------------------------------------------------

func (s *scopedEngine) Aggregate(ctx context.Context, groupBy ViewType, opts AggregateOptions) ([]AggregateRow, error) {
	return s.inner.Aggregate(ctx, groupBy, s.restrictAggregate(opts))
}

func (s *scopedEngine) SubAggregate(ctx context.Context, filter MessageFilter, groupBy ViewType, opts AggregateOptions) ([]AggregateRow, error) {
	return s.inner.SubAggregate(ctx, s.restrictFilter(filter), groupBy, s.restrictAggregate(opts))
}

func (s *scopedEngine) ListMessages(ctx context.Context, filter MessageFilter) ([]MessageSummary, error) {
	return s.inner.ListMessages(ctx, s.restrictFilter(filter))
}

func (s *scopedEngine) GetMessage(ctx context.Context, id int64) (*MessageDetail, error) {
	message, err := s.inner.GetMessage(ctx, id)
	if err != nil || message == nil || !s.sees(message.SourceID) {
		return nil, err
	}
	return message, nil
}

func (s *scopedEngine) GetMessageBySourceID(ctx context.Context, sourceMessageID string) (*MessageDetail, error) {
	message, err := s.inner.GetMessageBySourceID(ctx, sourceMessageID)
	if err != nil || message == nil || !s.sees(message.SourceID) {
		return nil, err
	}
	return message, nil
}

// GetAttachment and GetAttachmentsByHash are deliberately unscoped: attachment
// blobs are content-addressed and shared across sources by design.
func (s *scopedEngine) GetAttachment(ctx context.Context, id int64) (*AttachmentInfo, error) {
	return s.inner.GetAttachment(ctx, id)
}

func (s *scopedEngine) GetAttachmentsByHash(ctx context.Context, contentHash string) ([]AttachmentInfo, error) {
	return s.inner.GetAttachmentsByHash(ctx, contentHash)
}

func (s *scopedEngine) GetMessageRaw(ctx context.Context, id int64) ([]byte, error) {
	message, err := s.inner.GetMessage(ctx, id)
	if err != nil {
		return nil, err
	}
	if message == nil || !s.sees(message.SourceID) {
		return nil, nil
	}
	return s.inner.GetMessageRaw(ctx, id)
}

func (s *scopedEngine) GetMessageSummariesByIDs(ctx context.Context, ids []int64) ([]MessageSummary, error) {
	rows, err := s.inner.GetMessageSummariesByIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	return s.visibleSummaries(rows), nil
}

func (s *scopedEngine) Search(ctx context.Context, q *search.Query, limit, offset int) ([]MessageSummary, error) {
	return s.inner.Search(ctx, s.restrictQuery(q), limit, offset)
}

func (s *scopedEngine) SearchDeep(ctx context.Context, q *search.Query, filter MessageFilter, limit, offset int) ([]MessageSummary, error) {
	return s.inner.SearchDeep(ctx, s.restrictQuery(q), s.restrictFilter(filter), limit, offset)
}

func (s *scopedEngine) SearchDeepWithStats(ctx context.Context, q *search.Query, filter MessageFilter, limit, offset int) (*SearchFastResult, error) {
	return s.inner.SearchDeepWithStats(ctx, s.restrictQuery(q), s.restrictFilter(filter), limit, offset)
}

func (s *scopedEngine) SearchFast(ctx context.Context, q *search.Query, filter MessageFilter, limit, offset int) ([]MessageSummary, error) {
	return s.inner.SearchFast(ctx, s.restrictQuery(q), s.restrictFilter(filter), limit, offset)
}

func (s *scopedEngine) SearchFastCount(ctx context.Context, q *search.Query, filter MessageFilter) (int64, error) {
	return s.inner.SearchFastCount(ctx, s.restrictQuery(q), s.restrictFilter(filter))
}

func (s *scopedEngine) SearchFastWithStats(ctx context.Context, q *search.Query, queryStr string,
	filter MessageFilter, statsGroupBy ViewType, limit, offset int) (*SearchFastResult, error) {
	return s.inner.SearchFastWithStats(ctx, s.restrictQuery(q), queryStr, s.restrictFilter(filter), statsGroupBy, limit, offset)
}

func (s *scopedEngine) GetDeletionTargetsByFilter(ctx context.Context, filter MessageFilter) ([]DeletionTarget, error) {
	return s.inner.GetDeletionTargetsByFilter(ctx, s.restrictFilter(filter))
}

func (s *scopedEngine) SearchByDomains(ctx context.Context, domains []string, after, before *time.Time, limit, offset int) ([]MessageSummary, error) {
	rows, err := s.inner.SearchByDomains(ctx, domains, after, before, limit, offset)
	if err != nil {
		return nil, err
	}
	return s.visibleSummaries(rows), nil
}

func (s *scopedEngine) ListAccounts(ctx context.Context) ([]AccountInfo, error) {
	accounts, err := s.inner.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]AccountInfo, 0, len(accounts))
	for _, account := range accounts {
		if s.sees(account.ID) {
			out = append(out, account)
		}
	}
	return out, nil
}

func (s *scopedEngine) GetTotalStats(ctx context.Context, opts StatsOptions) (*TotalStats, error) {
	return s.inner.GetTotalStats(ctx, s.restrictStats(opts))
}

// Close is a no-op: the wrapper is built per request over a shared engine.
func (s *scopedEngine) Close() error { return nil }

// --- text, deletion, and body-search tier ------------------------------------

type scopedTextEngine struct {
	*scopedEngine
}

func (s *scopedTextEngine) text() TextEngine {
	engine, _ := s.inner.(TextEngine)
	return engine
}

func (s *scopedTextEngine) ListConversations(ctx context.Context, filter TextFilter) ([]ConversationRow, error) {
	filter, err := s.restrictTextFilter(filter)
	if err != nil {
		return nil, err
	}
	return s.text().ListConversations(ctx, filter)
}

func (s *scopedTextEngine) TextAggregate(ctx context.Context, viewType TextViewType, opts TextAggregateOptions) ([]AggregateRow, error) {
	source, err := s.restrictSingle(opts.SourceID)
	if err != nil {
		return nil, err
	}
	opts.SourceID = source
	return s.text().TextAggregate(ctx, viewType, opts)
}

func (s *scopedTextEngine) ListConversationMessages(ctx context.Context, convID int64, filter TextFilter) ([]MessageSummary, error) {
	filter, err := s.restrictTextFilter(filter)
	if err != nil {
		return nil, err
	}
	rows, err := s.text().ListConversationMessages(ctx, convID, filter)
	if err != nil {
		return nil, err
	}
	return s.visibleSummaries(rows), nil
}

func (s *scopedTextEngine) TextSearch(ctx context.Context, query string, limit, offset int) ([]MessageSummary, error) {
	rows, err := s.text().TextSearch(ctx, query, limit, offset)
	if err != nil {
		return nil, err
	}
	return s.visibleSummaries(rows), nil
}

func (s *scopedTextEngine) GetTextStats(ctx context.Context, opts TextStatsOptions) (*TotalStats, error) {
	source, err := s.restrictSingle(opts.SourceID)
	if err != nil {
		return nil, err
	}
	opts.SourceID = source
	return s.text().GetTextStats(ctx, opts)
}

func (s *scopedTextEngine) snapshots() TextSnapshotReader {
	reader, _ := s.inner.(TextSnapshotReader)
	return reader
}

func (s *scopedTextEngine) ListConversationsSnapshot(ctx context.Context, filter TextFilter) ([]ConversationRow, string, error) {
	filter, err := s.restrictTextFilter(filter)
	if err != nil {
		return nil, "", err
	}
	return s.snapshots().ListConversationsSnapshot(ctx, filter)
}

func (s *scopedTextEngine) ListConversationMessagesSnapshot(ctx context.Context, conversationID int64, filter TextFilter) ([]MessageSummary, string, error) {
	filter, err := s.restrictTextFilter(filter)
	if err != nil {
		return nil, "", err
	}
	rows, revision, err := s.snapshots().ListConversationMessagesSnapshot(ctx, conversationID, filter)
	if err != nil {
		return nil, "", err
	}
	return s.visibleSummaries(rows), revision, nil
}

func (s *scopedTextEngine) TextSnapshotRevision(ctx context.Context, scope TextSnapshotScope) (string, error) {
	reader, ok := s.inner.(interface {
		TextSnapshotRevision(ctx context.Context, scope TextSnapshotScope) (string, error)
	})
	if !ok {
		return "", ErrNotImplemented
	}
	filter, err := s.restrictTextFilter(scope.Filter)
	if err != nil {
		return "", err
	}
	scope.Filter = filter
	return reader.TextSnapshotRevision(ctx, scope)
}

func (s *scopedTextEngine) GetDeletionTargetsByMessageIDs(ctx context.Context, ids []int64) ([]DeletionTarget, error) {
	resolver, ok := s.inner.(interface {
		GetDeletionTargetsByMessageIDs(ctx context.Context, ids []int64) ([]DeletionTarget, error)
	})
	if !ok {
		return nil, ErrNotImplemented
	}
	targets, err := resolver.GetDeletionTargetsByMessageIDs(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make([]DeletionTarget, 0, len(targets))
	for _, target := range targets {
		if s.sees(target.SourceID) {
			out = append(out, target)
		}
	}
	return out, nil
}

func (s *scopedTextEngine) GetDeletionTargetsBySearch(ctx context.Context, searchQuery *search.Query, filter MessageFilter, mode DeletionSearchMode) ([]DeletionTarget, error) {
	resolver, ok := s.inner.(DeletionTargetSearchResolver)
	if !ok {
		return nil, ErrNotImplemented
	}
	return resolver.GetDeletionTargetsBySearch(ctx, s.restrictQuery(searchQuery), s.restrictFilter(filter), mode)
}

func (s *scopedTextEngine) GetDeletionTargetsByAggregateSearch(ctx context.Context, searchQuery string, filter MessageFilter, groupBy ViewType, key string) ([]DeletionTarget, error) {
	resolver, ok := s.inner.(DeletionTargetAggregateSearchResolver)
	if !ok {
		return nil, ErrNotImplemented
	}
	return resolver.GetDeletionTargetsByAggregateSearch(ctx, searchQuery, s.restrictFilter(filter), groupBy, key)
}

func (s *scopedTextEngine) SearchMessageBodies(ctx context.Context, query *search.Query, limit, offset int) ([]MessageSummary, error) {
	searcher, ok := s.inner.(MessageBodySearcher)
	if !ok {
		return nil, ErrNotImplemented
	}
	return searcher.SearchMessageBodies(ctx, s.restrictQuery(query), limit, offset)
}

// --- analytical tier (DuckDB) --------------------------------------------------

type scopedAnalyticalEngine struct {
	*scopedTextEngine
}

func (s *scopedAnalyticalEngine) explorer() Explorer {
	explorer, _ := s.inner.(Explorer)
	return explorer
}

func (s *scopedAnalyticalEngine) Explore(ctx context.Context, request ExploreRequest) (*ExploreResponse, error) {
	return s.explorer().Explore(ctx, s.restrictExplore(request))
}

func (s *scopedAnalyticalEngine) ExploreCoverage(ctx context.Context, request ExploreCoverageRequest, visit func(messageIDs []int64) error) (*ExploreCoverageResult, error) {
	request.Context = s.restrictContext(request.Context)
	return s.explorer().ExploreCoverage(ctx, request, visit)
}

func (s *scopedAnalyticalEngine) ExploreGroups(ctx context.Context, request ExploreGroupRequest) (*ExploreGroupResponse, error) {
	request.Explore = s.restrictExplore(request.Explore)
	return s.explorer().ExploreGroups(ctx, request)
}

func (s *scopedAnalyticalEngine) ExploreSelectionStats(ctx context.Context, request ExploreSelectionRequest) (*ExploreSelectionStats, error) {
	request.Explore = s.restrictExplore(request.Explore)
	return s.explorer().ExploreSelectionStats(ctx, request)
}

func (s *scopedAnalyticalEngine) ExploreFiles(ctx context.Context, request ExploreFilesRequest) (*ExploreFilesResponse, error) {
	request.Explore = s.restrictExplore(request.Explore)
	return s.explorer().ExploreFiles(ctx, request)
}

func (s *scopedAnalyticalEngine) ExploreMatchCounts(ctx context.Context, request ExploreMatchCountsRequest) (*ExploreMatchCountsResponse, error) {
	request.Explore = s.restrictExplore(request.Explore)
	return s.explorer().ExploreMatchCounts(ctx, request)
}

func (s *scopedAnalyticalEngine) people() PeopleAnalyzer {
	analyzer, _ := s.inner.(PeopleAnalyzer)
	return analyzer
}

func (s *scopedAnalyticalEngine) SearchPeople(ctx context.Context, request PersonSearchRequest) (*PersonSearchResponse, error) {
	request.Explore = s.restrictExplore(request.Explore)
	return s.people().SearchPeople(ctx, request)
}

func (s *scopedAnalyticalEngine) GetPerson(ctx context.Context, id int64, analyticalContext Context, clusterMemberIDs []int64) (*PersonSummary, error) {
	return s.people().GetPerson(ctx, id, s.restrictContext(analyticalContext), clusterMemberIDs)
}

func (s *scopedAnalyticalEngine) GetPersonSummary(ctx context.Context, id int64, explore ExploreRequest, clusterMemberIDs []int64) (*PersonSearchResponse, error) {
	return s.people().GetPersonSummary(ctx, id, s.restrictExplore(explore), clusterMemberIDs)
}

func (s *scopedAnalyticalEngine) SearchDomains(ctx context.Context, request DomainSearchRequest) (*DomainSearchResponse, error) {
	request.Explore = s.restrictExplore(request.Explore)
	return s.people().SearchDomains(ctx, request)
}

func (s *scopedAnalyticalEngine) GetDomain(ctx context.Context, domain string, analyticalContext Context) (*DomainSummary, error) {
	return s.people().GetDomain(ctx, domain, s.restrictContext(analyticalContext))
}

func (s *scopedAnalyticalEngine) GetDomainSummary(ctx context.Context, domain string, explore ExploreRequest) (*DomainSearchResponse, error) {
	return s.people().GetDomainSummary(ctx, domain, s.restrictExplore(explore))
}

// CompletePeople and the relationship calendar read the shared people graph
// and its archive-wide rollups, which are shared by design.
func (s *scopedAnalyticalEngine) CompletePeople(ctx context.Context, request PeopleCompletionRequest) (*PeopleCompletionResponse, error) {
	completer, ok := s.inner.(PeopleCompleter)
	if !ok {
		return nil, ErrNotImplemented
	}
	return completer.CompletePeople(ctx, request)
}

func (s *scopedAnalyticalEngine) ListPersonInboxes(ctx context.Context, request PersonInboxRequest) (*PersonInboxResponse, error) {
	analyzer, ok := s.inner.(PeopleInboxAnalyzer)
	if !ok {
		return nil, ErrNotImplemented
	}
	response, err := analyzer.ListPersonInboxes(ctx, request)
	if err != nil || response == nil {
		return response, err
	}
	rows := make([]PersonInboxRow, 0, len(response.Rows))
	for _, row := range response.Rows {
		if s.sees(row.SourceID) {
			rows = append(rows, row)
		}
	}
	response.Rows = rows
	return response, nil
}

func (s *scopedAnalyticalEngine) ResolveCanonicalParticipant(ctx context.Context, participantID int64) (int64, error) {
	resolver, ok := s.inner.(RelationshipCanonicalResolver)
	if !ok {
		return 0, ErrNotImplemented
	}
	return resolver.ResolveCanonicalParticipant(ctx, participantID)
}

func (s *scopedAnalyticalEngine) relationships() RelationshipAnalyzer {
	analyzer, _ := s.inner.(RelationshipAnalyzer)
	return analyzer
}

func (s *scopedAnalyticalEngine) Relationships(ctx context.Context, request RelationshipsRequest) (*RelationshipsResponse, error) {
	request.Context = s.restrictContext(request.Context)
	return s.relationships().Relationships(ctx, request)
}

func (s *scopedAnalyticalEngine) RelationshipTimeline(ctx context.Context, request RelationshipTimelineRequest) (*RelationshipTimelineResponse, error) {
	request.Context = s.restrictContext(request.Context)
	return s.relationships().RelationshipTimeline(ctx, request)
}

func (s *scopedAnalyticalEngine) RelationshipCalendar(ctx context.Context, request RelationshipCalendarRequest) (*RelationshipCalendarResponse, error) {
	analyzer, ok := s.inner.(RelationshipCalendarAnalyzer)
	if !ok {
		return nil, ErrNotImplemented
	}
	return analyzer.RelationshipCalendar(ctx, request)
}

func (s *scopedAnalyticalEngine) SearchFiles(ctx context.Context, request FileSearchRequest) (*FileSearchResponse, error) {
	searcher, ok := s.inner.(FileSearcher)
	if !ok {
		return nil, ErrNotImplemented
	}
	request.Explore = s.restrictExplore(request.Explore)
	return searcher.SearchFiles(ctx, request)
}

func (s *scopedAnalyticalEngine) GroupFiles(ctx context.Context, request FileGroupRequest) (*ExploreGroupResponse, error) {
	grouper, ok := s.inner.(FileGrouper)
	if !ok {
		return nil, ErrNotImplemented
	}
	request.Explore = s.restrictExplore(request.Explore)
	return grouper.GroupFiles(ctx, request)
}

// QuerySQL cannot be confined to a set of sources.
func (s *scopedAnalyticalEngine) QuerySQL(context.Context, string) (*QueryResult, error) {
	return nil, ErrScopedSQL
}
