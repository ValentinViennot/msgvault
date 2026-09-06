package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"go.kenn.io/msgvault/internal/explorecatalog"
	"go.kenn.io/msgvault/internal/jsonexact"
	"go.kenn.io/msgvault/internal/query"
	"go.kenn.io/msgvault/internal/savedview"
	"go.kenn.io/msgvault/internal/store"
)

type savedViewDefinition struct {
	ID             int64                        `json:"id"`
	Name           string                       `json:"name"`
	Description    *string                      `json:"description,omitempty"`
	CanonicalState store.SavedViewStateEnvelope `json:"canonical_state"`
	SchemaVersion  int                          `json:"schema_version"`
	Revision       int64                        `json:"revision"`
	CreatedAt      time.Time                    `json:"created_at"`
	UpdatedAt      time.Time                    `json:"updated_at"`
}

type listSavedViewsResponse struct {
	SavedViews []savedViewDefinition `json:"saved_views"`
}

type runSavedViewResponse struct {
	SavedView              savedViewDefinition     `json:"saved_view"`
	ResultKind             savedview.ResultKind    `json:"result_kind"`
	Rows                   []query.EntryRow        `json:"rows,omitempty"`
	Groups                 []query.ExploreGroupRow `json:"groups,omitempty"`
	Files                  []query.ExploreFileFact `json:"files,omitempty"`
	TotalCount             *int64                  `json:"total_count,omitempty"`
	Returned               int                     `json:"returned"`
	HasMore                bool                    `json:"has_more"`
	NextCursor             string                  `json:"next_cursor,omitempty"`
	CacheRevision          string                  `json:"cache_revision"`
	SearchProvenance       query.SearchProvenance  `json:"search_provenance"`
	CandidateSnapshotID    string                  `json:"candidate_snapshot_id,omitempty"`
	CandidatePoolSaturated bool                    `json:"candidate_pool_saturated,omitempty"`
	SearchDeletionScope    string                  `json:"search_deletion_scope,omitempty"`
}

type deleteSavedViewResponse struct {
	ID      int64 `json:"id"`
	Deleted bool  `json:"deleted"`
}

func listSavedViewsDefinition(_ *handlers) toolDefinition {
	return savedViewTool(readDefinition(
		ToolListSavedViews,
		"List persistent reusable msgvault Saved Views with their complete definitions so an agent can choose an existing view.",
		closedObject(map[string]*jsonschema.Schema{}),
		outputSchemaFor[listSavedViewsResponse](),
		(*handlers).listSavedViews,
	))
}

func getSavedViewDefinition(_ *handlers) toolDefinition {
	return savedViewTool(readDefinition(
		ToolGetSavedView,
		"Get one persistent reusable msgvault Saved View by stable ID, including its complete query, filters, grouping, presentation, and revision.",
		closedObject(map[string]*jsonschema.Schema{
			"id": safeIDSchema("Stable Saved View ID returned by list_saved_views"),
		}, "id"),
		outputSchemaFor[savedViewDefinition](),
		(*handlers).getSavedView,
	))
}

func runSavedViewDefinition(_ *handlers) toolDefinition {
	return savedViewTool(readDefinition(
		ToolRunSavedView,
		"Run a persistent reusable msgvault Saved View through its canonical Explore query. Prefer this tool over manually reconstructing a known Saved View. Returns typed entries, groups, or files according to the saved definition; semantic and hybrid views require vector search.",
		closedObject(map[string]*jsonschema.Schema{
			"id":     safeIDSchema("Stable Saved View ID returned by list_saved_views"),
			"limit":  searchLimitProperty(),
			"cursor": stringSchema("Opaque next_cursor from the previous run_saved_view page; omit for the first page"),
		}, "id"),
		outputSchemaFor[runSavedViewResponse](),
		(*handlers).runSavedView,
	))
}

func createSavedViewDefinition(_ *handlers) toolDefinition {
	return savedViewTool(writeDefinition(
		ToolCreateSavedView,
		"Create a persistent reusable msgvault Saved View using the canonical Saved View definition. Returns the created view and its revision.",
		closedObject(map[string]*jsonschema.Schema{
			"name":            stringSchema("Unique Saved View name"),
			"description":     stringSchema("Optional description that helps agents choose the Saved View"),
			"canonical_state": savedViewStateInputSchema(),
			"schema_version":  boundedIntegerSchema("Saved View schema version; currently must be 1", 1, 1),
		}, "name", "canonical_state", "schema_version"),
		outputSchemaFor[savedViewDefinition](),
		(*handlers).createSavedView,
	))
}

func updateSavedViewDefinition(_ *handlers) toolDefinition {
	return savedViewTool(writeDefinition(
		ToolUpdateSavedView,
		"Patch mutable fields on a persistent reusable msgvault Saved View. Supply the latest revision from list_saved_views or get_saved_view; an empty description clears it. Returns the updated view.",
		closedObject(map[string]*jsonschema.Schema{
			"id":              safeIDSchema("Stable Saved View ID"),
			"revision":        safeIDSchema("Latest Saved View revision for optimistic concurrency"),
			"name":            stringSchema("Replacement Saved View name"),
			"description":     stringSchema("Replacement description; use an empty string to clear it"),
			"canonical_state": savedViewStateInputSchema(),
			"schema_version":  boundedIntegerSchema("Replacement schema version; currently must be 1", 1, 1),
		}, "id", "revision"),
		outputSchemaFor[savedViewDefinition](),
		(*handlers).updateSavedView,
	))
}

func deleteSavedViewDefinition(_ *handlers) toolDefinition {
	return savedViewTool(destructiveWriteDefinition(
		ToolDeleteSavedView,
		"Delete a persistent reusable msgvault Saved View definition. This does not delete archive messages. Supply the latest revision for optimistic concurrency.",
		closedObject(map[string]*jsonschema.Schema{
			"id":       safeIDSchema("Stable Saved View ID"),
			"revision": safeIDSchema("Latest Saved View revision for optimistic concurrency"),
		}, "id", "revision"),
		outputSchemaFor[deleteSavedViewResponse](),
		(*handlers).deleteSavedView,
	))
}

func savedViewTool(definition toolDefinition) toolDefinition {
	definition.availability = savedViewsAvailable
	return definition
}

func (h *handlers) listSavedViews(ctx context.Context, _ toolRequest) (*toolResult, error) {
	views, err := h.savedViews.ListSavedViews(ctx)
	if err != nil {
		return savedViewHandlerError("list Saved Views", err)
	}
	response := listSavedViewsResponse{SavedViews: make([]savedViewDefinition, 0, len(views))}
	for i := range views {
		definition, err := savedViewDefinitionFromStore(views[i])
		if err != nil {
			return nil, newInternalError("decode Saved View definition", err)
		}
		response.SavedViews = append(response.SavedViews, definition)
	}
	return jsonResult(response)
}

func (h *handlers) getSavedView(ctx context.Context, req toolRequest) (*toolResult, error) {
	id, err := getIDArg(req.GetArguments(), "id")
	if err != nil {
		return toolErrorResult(err.Error()), nil
	}
	view, err := h.savedViews.GetSavedView(ctx, id)
	if err != nil {
		return savedViewHandlerError("get Saved View", err)
	}
	definition, err := savedViewDefinitionFromStore(*view)
	if err != nil {
		return nil, newInternalError("decode Saved View definition", err)
	}
	return jsonResult(definition)
}

func (h *handlers) runSavedView(ctx context.Context, req toolRequest) (*toolResult, error) {
	args := req.GetArguments()
	id, err := getIDArg(args, "id")
	if err != nil {
		return toolErrorResult(err.Error()), nil
	}
	cursor, _ := args["cursor"].(string)
	page, err := h.savedViews.RunSavedView(ctx, id, searchLimitArg(args), cursor)
	if err != nil {
		return savedViewHandlerError("run Saved View", err)
	}
	definition, err := savedViewDefinitionFromStore(page.View)
	if err != nil {
		return nil, newInternalError("decode Saved View definition", err)
	}
	return jsonResult(runSavedViewResponse{
		SavedView: definition, ResultKind: page.ResultKind,
		Rows: page.Rows, Groups: page.Groups, Files: page.Files,
		TotalCount: page.TotalCount, Returned: page.Returned,
		HasMore: page.HasMore, NextCursor: page.NextCursor,
		CacheRevision: page.CacheRevision, SearchProvenance: page.SearchProvenance,
		CandidateSnapshotID:    page.CandidateSnapshotID,
		CandidatePoolSaturated: page.CandidatePoolSaturated,
		SearchDeletionScope:    page.SearchDeletionScope,
	})
}

func (h *handlers) createSavedView(ctx context.Context, req toolRequest) (*toolResult, error) {
	args := req.GetArguments()
	name, _ := args["name"].(string)
	if name == "" {
		return toolErrorResult("name parameter is required"), nil
	}
	_, rawState, err := savedViewStateArgument(args, "canonical_state")
	if err != nil {
		return toolErrorResult(err.Error()), nil
	}
	version, err := getIDArg(args, "schema_version")
	if err != nil {
		return toolErrorResult(err.Error()), nil
	}
	var description *string
	if value, present := args["description"].(string); present {
		description = &value
	}
	created, err := h.savedViews.CreateSavedView(ctx, store.SavedViewInput{
		Name: name, Description: description, CanonicalState: rawState, SchemaVersion: int(version),
	})
	if err != nil {
		return savedViewHandlerError("create Saved View", err)
	}
	definition, err := savedViewDefinitionFromStore(*created)
	if err != nil {
		return nil, newInternalError("decode created Saved View", err)
	}
	return jsonResult(definition)
}

func (h *handlers) updateSavedView(ctx context.Context, req toolRequest) (*toolResult, error) {
	args := req.GetArguments()
	id, err := getIDArg(args, "id")
	if err != nil {
		return toolErrorResult(err.Error()), nil
	}
	revision, err := getIDArg(args, "revision")
	if err != nil {
		return toolErrorResult(err.Error()), nil
	}
	patch := savedview.Patch{}
	if value, present := args["name"].(string); present {
		patch.Name = &value
	}
	if value, present := args["description"].(string); present {
		patch.Description = &value
	}
	if _, present := args["canonical_state"]; present {
		state, _, err := savedViewStateArgument(args, "canonical_state")
		if err != nil {
			return toolErrorResult(err.Error()), nil
		}
		patch.CanonicalState = &state
	}
	if _, present := args["schema_version"]; present {
		version, err := getIDArg(args, "schema_version")
		if err != nil {
			return toolErrorResult(err.Error()), nil
		}
		value := int(version)
		patch.SchemaVersion = &value
	}
	if patch.Name == nil && patch.Description == nil && patch.CanonicalState == nil && patch.SchemaVersion == nil {
		return toolErrorResult("at least one mutable Saved View field is required"), nil
	}
	updated, err := h.savedViews.UpdateSavedView(ctx, id, revision, patch)
	if err != nil {
		return savedViewHandlerError("update Saved View", err)
	}
	definition, err := savedViewDefinitionFromStore(*updated)
	if err != nil {
		return nil, newInternalError("decode updated Saved View", err)
	}
	return jsonResult(definition)
}

func (h *handlers) deleteSavedView(ctx context.Context, req toolRequest) (*toolResult, error) {
	args := req.GetArguments()
	id, err := getIDArg(args, "id")
	if err != nil {
		return toolErrorResult(err.Error()), nil
	}
	revision, err := getIDArg(args, "revision")
	if err != nil {
		return toolErrorResult(err.Error()), nil
	}
	if err := h.savedViews.DeleteSavedView(ctx, id, revision); err != nil {
		return savedViewHandlerError("delete Saved View", err)
	}
	return jsonResult(deleteSavedViewResponse{ID: id, Deleted: true})
}

func savedViewDefinitionFromStore(view store.SavedView) (savedViewDefinition, error) {
	var state store.SavedViewStateEnvelope
	if err := json.Unmarshal(view.CanonicalState, &state); err != nil {
		return savedViewDefinition{}, fmt.Errorf("decode Saved View %d canonical state: %w", view.ID, err)
	}
	return savedViewDefinition{
		ID: view.ID, Name: view.Name, Description: view.Description,
		CanonicalState: state, SchemaVersion: view.SchemaVersion, Revision: view.Revision,
		CreatedAt: view.CreatedAt, UpdatedAt: view.UpdatedAt,
	}, nil
}

func savedViewHandlerError(operation string, err error) (*toolResult, error) {
	switch {
	case errors.Is(err, store.ErrSavedViewNotFound):
		return toolErrorResult("saved_view_not_found: Saved View not found"), nil
	case errors.Is(err, store.ErrSavedViewInvalidState),
		errors.Is(err, store.ErrSavedViewUnsupportedSchemaVersion):
		return toolErrorResult("invalid_saved_view: " + err.Error()), nil
	case errors.Is(err, store.ErrSavedViewNameConflict):
		return toolErrorResult("saved_view_name_conflict: A Saved View with that name already exists"), nil
	case errors.Is(err, store.ErrSavedViewRevisionConflict):
		return toolErrorResult("saved_view_revision_conflict: Saved View changed; read the latest revision and retry"), nil
	}
	if result := translateVectorErr(err); result != nil {
		return result, nil
	}
	var coded daemonAPIErrorCoder
	if errors.As(err, &coded) {
		switch coded.APIErrorCode() {
		case "invalid_cursor", "invalid_filter", "invalid_grouping", "invalid_limit",
			"invalid_presentation", "invalid_query", "invalid_search", "invalid_search_mode", "invalid_sort":
			return toolErrorResult(coded.APIErrorCode() + ": Saved View execution failed: " + err.Error()), nil
		}
	}
	return nil, newInternalError(operation, err)
}

func savedViewStateArgument(
	args map[string]any,
	key string,
) (store.SavedViewStateEnvelope, json.RawMessage, error) {
	value, present := args[key]
	if !present || value == nil {
		return store.SavedViewStateEnvelope{}, nil, fmt.Errorf("%s parameter is required", key)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return store.SavedViewStateEnvelope{}, nil, fmt.Errorf("%s is invalid", key)
	}
	if err := jsonexact.Validate(data, store.SavedViewStateEnvelope{}); err != nil {
		return store.SavedViewStateEnvelope{}, nil, fmt.Errorf("%s is invalid: %w", key, err)
	}
	var state store.SavedViewStateEnvelope
	if err := json.Unmarshal(data, &state); err != nil {
		return store.SavedViewStateEnvelope{}, nil, fmt.Errorf("%s is invalid: %w", key, err)
	}
	return state, json.RawMessage(data), nil
}

func savedViewStateInputSchema() *jsonschema.Schema {
	one := 1
	filterFields := append(slices.Clone(savedview.FilterFields), slices.Sorted(maps.Keys(savedview.FilterAliases))...)
	filterValues := arraySchema(stringSchema("Exact filter value; numeric IDs use decimal strings"))
	filterValues.MinItems = &one
	return closedObject(map[string]*jsonschema.Schema{
		"query":       stringSchema("Optional full-text, semantic, or hybrid query"),
		"search_mode": stringSchema("Query mode", savedview.SearchModes...),
		"filters": arraySchema(closedObject(map[string]*jsonschema.Schema{
			"field":    stringSchema("Explore filter field", filterFields...),
			"operator": stringSchema("Filter operator", savedview.FilterOperators...),
			"values":   filterValues,
		}, "field", "operator", "values")),
		"grouping":     arraySchema(stringSchema("Analytical grouping dimension", explorecatalog.GroupingDimensions()...)),
		"presentation": stringSchema("Presentation", savedview.Presentations...),
		"sort": arraySchema(closedObject(map[string]*jsonschema.Schema{
			"field":     stringSchema("Sort field", savedview.SortFields...),
			"direction": stringSchema("Sort direction", savedview.SortDirections...),
		}, "field", "direction")),
		"columns":          arraySchema(stringSchema("Visible column", savedview.Columns...)),
		"inspector_pinned": booleanSchema("Whether the Web inspector is pinned"),
	})
}

func arraySchema(items *jsonschema.Schema) *jsonschema.Schema {
	return &jsonschema.Schema{Type: "array", Items: items}
}
