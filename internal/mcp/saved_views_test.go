package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/query"
	"go.kenn.io/msgvault/internal/query/querytest"
	"go.kenn.io/msgvault/internal/savedview"
	"go.kenn.io/msgvault/internal/store"
	"go.kenn.io/msgvault/internal/testutil"
)

type savedViewServiceFixture struct {
	views     []store.SavedView
	page      *savedview.RunPage
	runID     int64
	runLimit  int
	runCursor string
	err       error
}

func savedViewTestMap(t *testing.T, value any) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	require.True(t, ok, "map value: %#v", value)
	return result
}

func savedViewTestSlice(t *testing.T, value any) []any {
	t.Helper()
	result, ok := value.([]any)
	require.True(t, ok, "slice value: %#v", value)
	return result
}

func savedViewToolErrorText(t *testing.T, result map[string]any) string {
	t.Helper()
	content := savedViewTestSlice(t, result["content"])
	require.NotEmpty(t, content)
	block := savedViewTestMap(t, content[0])
	text, ok := block["text"].(string)
	require.True(t, ok, "error text: %#v", block["text"])
	return text
}

func (f *savedViewServiceFixture) ListSavedViews(context.Context) ([]store.SavedView, error) {
	return append([]store.SavedView(nil), f.views...), f.err
}

func (f *savedViewServiceFixture) GetSavedView(_ context.Context, id int64) (*store.SavedView, error) {
	if f.err != nil {
		return nil, f.err
	}
	for i := range f.views {
		if f.views[i].ID == id {
			view := f.views[i]
			return &view, nil
		}
	}
	return nil, store.ErrSavedViewNotFound
}

func (f *savedViewServiceFixture) RunSavedView(
	_ context.Context, id int64, limit int, cursor string,
) (*savedview.RunPage, error) {
	f.runID, f.runLimit, f.runCursor = id, limit, cursor
	if f.err != nil {
		return nil, f.err
	}
	return f.page, nil
}

func (f *savedViewServiceFixture) CreateSavedView(context.Context, store.SavedViewInput) (*store.SavedView, error) {
	return nil, errors.ErrUnsupported
}

func (f *savedViewServiceFixture) UpdateSavedView(
	context.Context, int64, int64, savedview.Patch,
) (*store.SavedView, error) {
	return nil, errors.ErrUnsupported
}

func (f *savedViewServiceFixture) DeleteSavedView(context.Context, int64, int64) error {
	return errors.ErrUnsupported
}

func TestSavedViewReadToolsUseTypedDefinitions(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)
	now := time.Date(2026, 8, 18, 9, 30, 0, 0, time.UTC)
	description := "Invoices from the primary archive"
	view := store.SavedView{
		ID: 17, Name: "Invoices", Description: &description,
		CanonicalState: json.RawMessage(`{
			"query":"invoice","search_mode":"full_text",
			"filters":[{"field":"source","operator":"in","values":["3"]}],
			"grouping":["domain"],"presentation":"table",
			"sort":[{"field":"occurred_at","direction":"desc"}],
			"columns":["kind","title","time"]
		}`),
		SchemaVersion: 1, Revision: 4, CreatedAt: now.Add(-time.Hour), UpdatedAt: now,
	}
	reader := &savedViewServiceFixture{views: []store.SavedView{view}}
	opts := ServeOptions{Engine: &querytest.MockEngine{}, SavedViews: reader}

	listed := rawCallTool(t, opts, ToolListSavedViews, map[string]any{})
	requirements.NotEqual(true, listed["isError"], "result: %#v", listed)
	listContent := savedViewTestMap(t, listed["structuredContent"])
	views := savedViewTestSlice(t, listContent["saved_views"])
	requirements.Len(views, 1)
	listedView := savedViewTestMap(t, views[0])
	assertions.Equal("Invoices", listedView["name"])
	assertions.Equal("invoice", savedViewTestMap(t, listedView["canonical_state"])["query"])

	got := rawCallTool(t, opts, ToolGetSavedView, map[string]any{"id": 17})
	requirements.NotEqual(true, got["isError"], "result: %#v", got)
	definition := savedViewTestMap(t, got["structuredContent"])
	assertions.InDelta(float64(17), definition["id"], 0)
	assertions.InDelta(float64(4), definition["revision"], 0)
	assertions.Equal([]any{"domain"}, savedViewTestMap(t, definition["canonical_state"])["grouping"])
}

func TestRunSavedViewReturnsTypedExplorePage(t *testing.T) {
	assertions := assert.New(t)
	view := store.SavedView{
		ID: 7, Name: "Project", CanonicalState: json.RawMessage(`{"presentation":"table"}`),
		SchemaVersion: 1, Revision: 1,
	}
	total := int64(9)
	reader := &savedViewServiceFixture{page: &savedview.RunPage{
		View: view, ResultKind: savedview.ResultEntries,
		Rows:       []query.EntryRow{{Key: "message:42", Kind: query.EntryEmail, Title: "Project update"}},
		TotalCount: &total, Returned: 1, HasMore: true, NextCursor: "next-page",
		CacheRevision: "cache-7",
	}}
	opts := ServeOptions{Engine: &querytest.MockEngine{}, SavedViews: reader}

	result := rawCallTool(t, opts, ToolRunSavedView, map[string]any{
		"id": 7, "limit": 5000, "cursor": "current-page",
	})
	require.NotEqual(t, true, result["isError"], "result: %#v", result)
	structured := savedViewTestMap(t, result["structuredContent"])
	assertions.Equal("entries", structured["result_kind"])
	assertions.InDelta(float64(1), structured["returned"], 0)
	assertions.Equal(true, structured["has_more"])
	assertions.Equal("next-page", structured["next_cursor"])
	assertions.Len(structured["rows"], 1)
	assertions.Equal(int64(7), reader.runID)
	assertions.Equal(maxSearchMessagesLimit, reader.runLimit)
	assertions.Equal("current-page", reader.runCursor)
}

func TestSavedViewReadToolsReturnCleanErrors(t *testing.T) {
	assertions := assert.New(t)
	opts := ServeOptions{Engine: &querytest.MockEngine{}, SavedViews: &savedViewServiceFixture{
		err: store.ErrSavedViewNotFound,
	}}

	missing := rawCallTool(t, opts, ToolGetSavedView, map[string]any{"id": 999})
	assertions.Equal(true, missing["isError"])
	assertions.Contains(savedViewToolErrorText(t, missing), "saved_view_not_found")

	invalid := opts
	invalid.SavedViews = &savedViewServiceFixture{err: store.ErrSavedViewInvalidState}
	failed := rawCallTool(t, invalid, ToolRunSavedView, map[string]any{"id": 7})
	assertions.Equal(true, failed["isError"])
	assertions.Contains(savedViewToolErrorText(t, failed), "invalid_saved_view")
}

type savedViewStoreService struct {
	store *store.Store
}

func (s *savedViewStoreService) ListSavedViews(ctx context.Context) ([]store.SavedView, error) {
	return s.store.ListSavedViews(ctx)
}

func (s *savedViewStoreService) GetSavedView(ctx context.Context, id int64) (*store.SavedView, error) {
	return s.store.GetSavedView(ctx, id)
}

func (s *savedViewStoreService) CreateSavedView(
	ctx context.Context, input store.SavedViewInput,
) (*store.SavedView, error) {
	return s.store.CreateSavedView(ctx, input)
}

func (s *savedViewStoreService) UpdateSavedView(
	ctx context.Context, id, expectedRevision int64, patch savedview.Patch,
) (*store.SavedView, error) {
	current, err := s.store.GetSavedView(ctx, id)
	if err != nil {
		return nil, err
	}
	input := store.SavedViewInput{
		Name: current.Name, Description: current.Description,
		CanonicalState: current.CanonicalState, SchemaVersion: current.SchemaVersion,
	}
	if patch.Name != nil {
		input.Name = *patch.Name
	}
	if patch.Description != nil {
		if *patch.Description == "" {
			input.Description = nil
		} else {
			input.Description = patch.Description
		}
	}
	if patch.CanonicalState != nil {
		input.CanonicalState, err = json.Marshal(patch.CanonicalState)
		if err != nil {
			return nil, err
		}
	}
	if patch.SchemaVersion != nil {
		input.SchemaVersion = *patch.SchemaVersion
	}
	return s.store.UpdateSavedView(ctx, id, expectedRevision, input)
}

func (s *savedViewStoreService) DeleteSavedView(ctx context.Context, id, expectedRevision int64) error {
	return s.store.DeleteSavedView(ctx, id, expectedRevision)
}

func (s *savedViewStoreService) RunSavedView(
	ctx context.Context, id int64, _ int, _ string,
) (*savedview.RunPage, error) {
	view, err := s.store.GetSavedView(ctx, id)
	if err != nil {
		return nil, err
	}
	var state store.SavedViewStateEnvelope
	if err := json.Unmarshal(view.CanonicalState, &state); err != nil {
		return nil, err
	}
	return &savedview.RunPage{
		View: *view, ResultKind: savedview.ResultEntries,
		Rows:     []query.EntryRow{{Key: "message:1", Kind: query.EntryEmail, Title: state.Query}},
		Returned: 1,
	}, nil
}

func TestSavedViewToolsLifecycleThroughStore(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)
	service := &savedViewStoreService{store: testutil.NewTestStore(t)}
	opts := ServeOptions{Engine: &querytest.MockEngine{}, SavedViews: service}

	createdResult := rawCallTool(t, opts, ToolCreateSavedView, map[string]any{
		"name": "Invoices", "description": "Quarterly review", "schema_version": 1,
		"canonical_state": map[string]any{
			"query": "invoice", "search_mode": "full_text", "presentation": "table",
			"filters": []any{map[string]any{
				"field": "source", "operator": "in", "values": []any{"3"},
			}},
		},
	})
	requirements.NotEqual(true, createdResult["isError"], "result: %#v", createdResult)
	created := savedViewTestMap(t, createdResult["structuredContent"])
	createdID, ok := created["id"].(float64)
	requirements.True(ok, "id: %#v", created["id"])
	id := int64(createdID)
	assertions.InDelta(float64(1), created["revision"], 0)

	gotResult := rawCallTool(t, opts, ToolGetSavedView, map[string]any{"id": id})
	requirements.NotEqual(true, gotResult["isError"], "result: %#v", gotResult)
	got := savedViewTestMap(t, gotResult["structuredContent"])
	assertions.Equal("invoice", savedViewTestMap(t, got["canonical_state"])["query"])

	updatedResult := rawCallTool(t, opts, ToolUpdateSavedView, map[string]any{
		"id": id, "revision": int64(1), "name": "Receipts", "description": "",
		"canonical_state": map[string]any{
			"query": "receipt", "search_mode": "full_text", "presentation": "timeline",
		},
	})
	requirements.NotEqual(true, updatedResult["isError"], "result: %#v", updatedResult)
	updated := savedViewTestMap(t, updatedResult["structuredContent"])
	assertions.InDelta(float64(2), updated["revision"], 0)
	assertions.Equal("Receipts", updated["name"])
	assertions.NotContains(updated, "description")

	stale := rawCallTool(t, opts, ToolUpdateSavedView, map[string]any{
		"id": id, "revision": int64(1), "name": "Stale edit",
	})
	assertions.Equal(true, stale["isError"])
	assertions.Contains(savedViewToolErrorText(t, stale), "saved_view_revision_conflict")

	runResult := rawCallTool(t, opts, ToolRunSavedView, map[string]any{"id": id})
	requirements.NotEqual(true, runResult["isError"], "result: %#v", runResult)
	run := savedViewTestMap(t, runResult["structuredContent"])
	runView := savedViewTestMap(t, run["saved_view"])
	assertions.Equal("receipt", savedViewTestMap(t, runView["canonical_state"])["query"])
	rows := savedViewTestSlice(t, run["rows"])
	requirements.NotEmpty(rows)
	assertions.Equal("receipt", savedViewTestMap(t, rows[0])["title"])

	deletedResult := rawCallTool(t, opts, ToolDeleteSavedView, map[string]any{
		"id": id, "revision": int64(2),
	})
	requirements.NotEqual(true, deletedResult["isError"], "result: %#v", deletedResult)
	assertions.Equal(true, savedViewTestMap(t, deletedResult["structuredContent"])["deleted"])

	missing := rawCallTool(t, opts, ToolGetSavedView, map[string]any{"id": id})
	assertions.Equal(true, missing["isError"])
	assertions.Contains(savedViewToolErrorText(t, missing), "saved_view_not_found")
}

func TestSavedViewWriteToolsRejectInvalidInput(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)
	service := &savedViewStoreService{store: testutil.NewTestStore(t)}
	opts := ServeOptions{Engine: &querytest.MockEngine{}, SavedViews: service}

	invalid := rawCallTool(t, opts, ToolCreateSavedView, map[string]any{
		"name": "Invalid", "schema_version": 1,
		"canonical_state": map[string]any{"selection": []any{1}},
	})
	assertions.Equal(true, invalid["isError"])

	created := rawCallTool(t, opts, ToolCreateSavedView, map[string]any{
		"name": "Unique", "schema_version": 1, "canonical_state": map[string]any{},
	})
	requirements.NotEqual(true, created["isError"], "result: %#v", created)
	conflict := rawCallTool(t, opts, ToolCreateSavedView, map[string]any{
		"name": "Unique", "schema_version": 1, "canonical_state": map[string]any{},
	})
	assertions.Equal(true, conflict["isError"])
	assertions.Contains(savedViewToolErrorText(t, conflict), "saved_view_name_conflict")

	createdContent := savedViewTestMap(t, created["structuredContent"])
	createdID, ok := createdContent["id"].(float64)
	requirements.True(ok, "id: %#v", createdContent["id"])
	id := int64(createdID)
	emptyPatch := rawCallTool(t, opts, ToolUpdateSavedView, map[string]any{"id": id, "revision": int64(1)})
	assertions.Equal(true, emptyPatch["isError"])
	assertions.Contains(savedViewToolErrorText(t, emptyPatch), "at least one mutable")
}
