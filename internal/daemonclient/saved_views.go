package daemonclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"go.kenn.io/msgvault/internal/jsonexact"
	"go.kenn.io/msgvault/internal/query"
	"go.kenn.io/msgvault/internal/savedview"
	"go.kenn.io/msgvault/internal/store"
	apiclient "go.kenn.io/msgvault/pkg/client"
	"go.kenn.io/msgvault/pkg/client/generated"
)

func (c *Client) ListSavedViews(ctx context.Context) ([]store.SavedView, error) {
	resp, err := APIResponse(c, func(client *apiclient.Client) (*generated.ListSavedViewsResp, error) {
		return client.ListSavedViewsWithResponse(ctx)
	})
	if err != nil {
		return nil, savedViewAPIError(err)
	}

	views := make([]store.SavedView, 0, len(resp.JSON200.SavedViews))
	for i := range resp.JSON200.SavedViews {
		view, err := savedViewFromGenerated(resp.JSON200.SavedViews[i])
		if err != nil {
			return nil, err
		}
		views = append(views, *view)
	}
	return views, nil
}

func (c *Client) GetSavedView(ctx context.Context, id int64) (*store.SavedView, error) {
	resp, err := APIResponse(c, func(client *apiclient.Client) (*generated.GetSavedViewResp, error) {
		return client.GetSavedViewWithResponse(ctx, &generated.GetSavedViewRequestOptions{
			PathParams: &generated.GetSavedViewPath{ID: id},
		})
	})
	if err != nil {
		return nil, savedViewAPIError(err)
	}
	return savedViewFromGenerated(*resp.JSON200)
}

func (c *Client) CreateSavedView(
	ctx context.Context,
	input store.SavedViewInput,
) (*store.SavedView, error) {
	state, err := savedViewStateFromJSON(input.CanonicalState)
	if err != nil {
		return nil, err
	}
	resp, err := APIResponseWithStatuses(c, []int{http.StatusCreated}, func(client *apiclient.Client) (*generated.CreateSavedViewResp, error) {
		return client.CreateSavedViewWithResponse(ctx, &generated.CreateSavedViewRequestOptions{
			Body: &generated.CreateSavedViewRequest{
				Name: input.Name, Description: input.Description, CanonicalState: state,
				SchemaVersion: int64(input.SchemaVersion),
			},
		})
	})
	if err != nil {
		return nil, savedViewAPIError(err)
	}
	return savedViewFromGenerated(*resp.JSON201)
}

func (c *Client) UpdateSavedView(
	ctx context.Context,
	id, expectedRevision int64,
	patch savedview.Patch,
) (*store.SavedView, error) {
	body := generated.PatchSavedViewRequest{
		Name: patch.Name, Description: patch.Description,
	}
	if patch.CanonicalState != nil {
		state, err := savedViewStateFromEnvelope(*patch.CanonicalState)
		if err != nil {
			return nil, err
		}
		body.CanonicalState = &state
	}
	if patch.SchemaVersion != nil {
		value := int64(*patch.SchemaVersion)
		body.SchemaVersion = &value
	}
	resp, err := APIResponse(c, func(client *apiclient.Client) (*generated.PatchSavedViewResp, error) {
		return client.PatchSavedViewWithResponse(ctx, &generated.PatchSavedViewRequestOptions{
			PathParams: &generated.PatchSavedViewPath{ID: id},
			Header: &generated.PatchSavedViewHeaders{
				IfMatch: savedViewRevisionTag(id, expectedRevision),
			},
			Body: &body,
		})
	})
	if err != nil {
		return nil, savedViewAPIError(err)
	}
	return savedViewFromGenerated(*resp.JSON200)
}

func (c *Client) DeleteSavedView(ctx context.Context, id, expectedRevision int64) error {
	_, err := APIResponseWithStatuses(c, []int{http.StatusNoContent}, func(client *apiclient.Client) (*generated.DeleteSavedViewResp, error) {
		return client.DeleteSavedViewWithResponse(ctx, &generated.DeleteSavedViewRequestOptions{
			PathParams: &generated.DeleteSavedViewPath{ID: id},
			Header: &generated.DeleteSavedViewHeaders{
				IfMatch: savedViewRevisionTag(id, expectedRevision),
			},
		})
	})
	return savedViewAPIError(err)
}

func (c *Client) RunSavedView(
	ctx context.Context,
	id int64,
	limit int,
	cursor string,
) (*savedview.RunPage, error) {
	view, err := c.GetSavedView(ctx, id)
	if err != nil {
		return nil, err
	}
	predicate, state, err := savedViewPredicate(*view, limit, cursor)
	if err != nil {
		return nil, err
	}

	switch {
	case len(state.Grouping) > 0:
		return c.runSavedViewGroups(ctx, *view, predicate, state.Grouping[0])
	case state.Presentation == string(query.PresentationFiles):
		return c.runSavedViewFiles(ctx, *view, predicate, limit, cursor)
	default:
		return c.runSavedViewEntries(ctx, *view, predicate)
	}
}

func savedViewPredicate(
	view store.SavedView,
	limit int,
	cursor string,
) (generated.ExploreHTTPRequest, store.SavedViewStateEnvelope, error) {
	state, err := savedview.ExecutableState(view)
	if err != nil {
		return generated.ExploreHTTPRequest{}, store.SavedViewStateEnvelope{}, err
	}

	predicate := generated.ExploreHTTPRequest{Limit: new(int64(limit))}
	if cursor != "" {
		predicate.Cursor = &cursor
	}
	for _, filter := range state.Filters {
		predicate.Filters = append(predicate.Filters, generated.ExploreFilter{
			Dimension: generated.ExploreFilterDimension(savedview.FilterDimension(filter.Field)),
			Values:    append([]string(nil), filter.Values...),
		})
	}
	for _, grouping := range state.Grouping {
		predicate.Grouping = append(predicate.Grouping, generated.ExploreGroupDimension(grouping))
	}

	queryText := strings.TrimSpace(state.Query)
	if queryText != "" {
		mode := state.SearchMode
		if mode == "" {
			mode = savedview.DefaultSearchMode
		}
		predicate.Query = &queryText
		searchMode := generated.ExploreHTTPRequestSearchMode(mode)
		predicate.SearchMode = &searchMode
	}
	presentation := state.Presentation
	if presentation == "" {
		presentation = string(query.PresentationTable)
	}
	generatedPresentation := generated.ExploreHTTPRequestPresentation(presentation)
	predicate.Presentation = &generatedPresentation
	for _, sort := range state.Sort {
		predicate.Sort = append(predicate.Sort, generated.ExploreSort{
			Field: generated.ExploreSortField(sort.Field), Direction: generated.ExploreSortDirection(sort.Direction),
		})
	}
	return predicate, state, nil
}

func (c *Client) runSavedViewEntries(
	ctx context.Context,
	view store.SavedView,
	predicate generated.ExploreHTTPRequest,
) (*savedview.RunPage, error) {
	// Timeline is a client-side rendering of the same canonical entry rows.
	presentation := generated.ExploreHTTPRequestPresentationTable
	predicate.Presentation = &presentation
	resp, err := APIResponse(c, func(client *apiclient.Client) (*generated.ExploreResp, error) {
		return client.ExploreWithResponse(ctx, &generated.ExploreRequestOptions{Body: &predicate})
	})
	if err != nil {
		return nil, err
	}
	result := resp.JSON200
	rows := make([]query.EntryRow, len(result.Rows))
	for i := range result.Rows {
		rows[i] = entryRowFromGenerated(result.Rows[i])
	}
	return &savedview.RunPage{
		View: view, ResultKind: savedview.ResultEntries, Rows: rows,
		TotalCount: result.TotalCount, Returned: len(rows),
		HasMore: result.NextCursor != nil, NextCursor: stringValue(result.NextCursor),
		CacheRevision: result.CacheRevision, SearchProvenance: searchProvenanceFromGenerated(result.SearchProvenance),
		CandidateSnapshotID:    stringValue(result.CandidateSnapshotID),
		CandidatePoolSaturated: boolValue(result.CandidatePoolSaturated),
		SearchDeletionScope:    stringValue(result.SearchDeletionScope),
	}, nil
}

func (c *Client) runSavedViewGroups(
	ctx context.Context,
	view store.SavedView,
	predicate generated.ExploreHTTPRequest,
	grouping string,
) (*savedview.RunPage, error) {
	presentation := generated.ExploreGroupsHTTPRequestPresentationTable
	request := generated.ExploreGroupsHTTPRequest{
		Cursor: predicate.Cursor, Filters: predicate.Filters,
		Grouping: []generated.ExploreGroupDimension{generated.ExploreGroupDimension(grouping)},
		Limit:    predicate.Limit, Presentation: &presentation, Query: predicate.Query,
	}
	if predicate.SearchMode != nil {
		mode := generated.ExploreGroupsHTTPRequestSearchMode(*predicate.SearchMode)
		request.SearchMode = &mode
	}
	resp, err := APIResponse(c, func(client *apiclient.Client) (*generated.ExploreGroupsResp, error) {
		return client.ExploreGroupsWithResponse(ctx, &generated.ExploreGroupsRequestOptions{Body: &request})
	})
	if err != nil {
		return nil, err
	}
	result := resp.JSON200
	groups := make([]query.ExploreGroupRow, len(result.Rows))
	for i, group := range result.Rows {
		groups[i] = query.ExploreGroupRow{
			Key: group.Key, Label: group.Label, Count: group.Count,
			EstimatedBytes: group.EstimatedBytes, LatestAt: group.LatestAt,
		}
	}
	total := result.TotalCount
	return &savedview.RunPage{
		View: view, ResultKind: savedview.ResultGroups, Groups: groups,
		TotalCount: &total, Returned: len(groups),
		HasMore: result.NextCursor != nil, NextCursor: stringValue(result.NextCursor),
		CacheRevision: result.CacheRevision, SearchProvenance: searchProvenanceFromGenerated(result.SearchProvenance),
		CandidateSnapshotID: stringValue(result.CandidateSnapshotID),
		SearchDeletionScope: stringValue(result.SearchDeletionScope),
	}, nil
}

func (c *Client) runSavedViewFiles(
	ctx context.Context,
	view store.SavedView,
	predicate generated.ExploreHTTPRequest,
	limit int,
	cursor string,
) (*savedview.RunPage, error) {
	predicate.Cursor = nil
	request := generated.ExploreFilesHTTPRequest{Predicate: predicate, Limit: new(int64(limit))}
	if cursor != "" {
		request.Cursor = &cursor
	}
	resp, err := APIResponse(c, func(client *apiclient.Client) (*generated.ListExploreFilesResp, error) {
		return client.ListExploreFilesWithResponse(ctx, &generated.ListExploreFilesRequestOptions{Body: &request})
	})
	if err != nil {
		return nil, err
	}
	result := resp.JSON200
	files := make([]query.ExploreFileFact, len(result.Files))
	for i, file := range result.Files {
		files[i] = query.ExploreFileFact{
			ID: file.ID, Key: file.Key, EntryKey: file.EntryKey, MessageID: file.MessageID,
			ConversationID: file.ConversationID, OccurredAt: file.OccurredAt,
			SourceID: file.SourceID, SourceIdentifier: file.SourceIdentifier,
			Title: file.Title, Filename: file.Filename, MimeType: file.MimeType, Size: file.Size,
		}
	}
	total := result.TotalCount
	return &savedview.RunPage{
		View: view, ResultKind: savedview.ResultFiles, Files: files,
		TotalCount: &total, Returned: len(files),
		HasMore: result.NextCursor != nil, NextCursor: stringValue(result.NextCursor),
		CacheRevision: result.CacheRevision, SearchProvenance: searchProvenanceFromGenerated(result.SearchProvenance),
		CandidateSnapshotID: stringValue(result.CandidateSnapshotID),
	}, nil
}

func savedViewFromGenerated(view generated.SavedView) (*store.SavedView, error) {
	state, err := json.Marshal(view.CanonicalState)
	if err != nil {
		return nil, fmt.Errorf("encode Saved View %d canonical state: %w", view.ID, err)
	}
	return &store.SavedView{
		ID: view.ID, Name: view.Name, Description: view.Description,
		CanonicalState: state, SchemaVersion: int(view.SchemaVersion), Revision: view.Revision,
		CreatedAt: view.CreatedAt, UpdatedAt: view.UpdatedAt,
	}, nil
}

func savedViewStateFromJSON(data []byte) (generated.SavedViewStateEnvelope, error) {
	if err := jsonexact.Validate(data, store.SavedViewStateEnvelope{}); err != nil {
		return generated.SavedViewStateEnvelope{}, fmt.Errorf("%w: %w", store.ErrSavedViewInvalidState, err)
	}
	var state generated.SavedViewStateEnvelope
	if err := json.Unmarshal(data, &state); err != nil {
		return generated.SavedViewStateEnvelope{}, fmt.Errorf("decode Saved View canonical state: %w", err)
	}
	return state, nil
}

func savedViewStateFromEnvelope(state store.SavedViewStateEnvelope) (generated.SavedViewStateEnvelope, error) {
	data, err := json.Marshal(state)
	if err != nil {
		return generated.SavedViewStateEnvelope{}, fmt.Errorf("encode Saved View canonical state: %w", err)
	}
	return savedViewStateFromJSON(data)
}

func savedViewRevisionTag(id, revision int64) string {
	return fmt.Sprintf(`"saved-view-%d-r%d"`, id, revision)
}

func savedViewAPIError(err error) error {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	switch apiErr.Code {
	case "saved_view_not_found":
		return fmt.Errorf("%w: %s", store.ErrSavedViewNotFound, apiErr.Message)
	case "saved_view_name_conflict":
		return fmt.Errorf("%w: %s", store.ErrSavedViewNameConflict, apiErr.Message)
	case "saved_view_revision_conflict":
		return fmt.Errorf("%w: %s", store.ErrSavedViewRevisionConflict, apiErr.Message)
	case "invalid_saved_view":
		return fmt.Errorf("%w: %s", store.ErrSavedViewInvalidState, apiErr.Message)
	default:
		return err
	}
}

func searchProvenanceFromGenerated(value generated.SearchProvenance) query.SearchProvenance {
	return query.SearchProvenance{
		LexicalIndexRevision: stringValue(value.LexicalIndexRevision),
		VectorGeneration:     value.VectorGeneration,
	}
}
