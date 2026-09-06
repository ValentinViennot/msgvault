// Package savedview defines the Saved View service contract shared by MCP and
// the daemon client, plus the version-1 executable-state vocabulary that the
// Web UI, the daemon client, and the MCP input schema all agree on.
package savedview

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"go.kenn.io/msgvault/internal/explorecatalog"
	"go.kenn.io/msgvault/internal/query"
	"go.kenn.io/msgvault/internal/store"
)

// Reader exposes durable Saved View definitions and executes them through the
// archive's canonical Explore machinery.
type Reader interface {
	ListSavedViews(ctx context.Context) ([]store.SavedView, error)
	GetSavedView(ctx context.Context, id int64) (*store.SavedView, error)
	RunSavedView(ctx context.Context, id int64, limit int, cursor string) (*RunPage, error)
}

// Writer mutates Saved Views while preserving the store/API optimistic
// revision contract.
type Writer interface {
	CreateSavedView(ctx context.Context, input store.SavedViewInput) (*store.SavedView, error)
	UpdateSavedView(ctx context.Context, id, expectedRevision int64, patch Patch) (*store.SavedView, error)
	DeleteSavedView(ctx context.Context, id, expectedRevision int64) error
}

// Service is the full Saved View surface an embedder wires into MCP.
type Service interface {
	Reader
	Writer
}

// Patch contains only fields supplied by the caller. An empty Description
// string clears the existing description, matching the HTTP API.
type Patch struct {
	Name           *string
	Description    *string
	CanonicalState *store.SavedViewStateEnvelope
	SchemaVersion  *int
}

// ResultKind names which typed array a RunPage carries.
type ResultKind string

const (
	ResultEntries ResultKind = "entries"
	ResultGroups  ResultKind = "groups"
	ResultFiles   ResultKind = "files"
)

// RunPage is one typed page from the Explore surface selected by a Saved
// View's grouping and presentation definition.
type RunPage struct {
	View                   store.SavedView         `json:"view"`
	ResultKind             ResultKind              `json:"result_kind"`
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

// Version-1 executable vocabulary. The Web UI's Saved Views workspace applies
// the same rules before opening a view, so a definition the Web UI can open is
// one the daemon client can execute, and vice versa.
var (
	// FilterFields are the Explore filter dimensions a v1 definition may name.
	// The legacy aliases source_id and participant_id are also accepted and
	// normalized by FilterDimension.
	FilterFields = []string{"source", "participant", "domain", "message_type", "after", "before", "deletion"}
	// FilterAliases map legacy v1 filter field names onto Explore dimensions.
	FilterAliases   = map[string]string{"source_id": "source", "participant_id": "participant"}
	FilterOperators = []string{"eq", "in"}
	SearchModes     = []string{"full_text", "semantic", "hybrid"}
	Presentations   = []string{"table", "timeline", "files"}
	SortFields      = []string{"occurred_at"}
	SortDirections  = []string{"desc"}
	Columns         = []string{"kind", "people", "title", "excerpt", "time", "attachments", "size"}
)

// DefaultSearchMode applies when a definition carries a query without a mode.
const DefaultSearchMode = "full_text"

// FilterDimension maps a v1 filter field, including legacy aliases, onto the
// Explore dimension it executes against.
func FilterDimension(field string) string {
	if dimension, ok := FilterAliases[field]; ok {
		return dimension
	}
	return field
}

// ExecutableState decodes a Saved View's canonical state and checks it against
// the v1 executable contract. Errors wrap store.ErrSavedViewUnsupportedSchemaVersion
// or store.ErrSavedViewInvalidState so callers can map them uniformly.
func ExecutableState(view store.SavedView) (store.SavedViewStateEnvelope, error) {
	if view.SchemaVersion != store.CurrentSavedViewSchemaVersion {
		return store.SavedViewStateEnvelope{}, fmt.Errorf(
			"%w: Saved View %d uses schema version %d",
			store.ErrSavedViewUnsupportedSchemaVersion, view.ID, view.SchemaVersion,
		)
	}
	var state store.SavedViewStateEnvelope
	if err := json.Unmarshal(view.CanonicalState, &state); err != nil {
		return store.SavedViewStateEnvelope{}, fmt.Errorf(
			"%w: decode Saved View %d: %w", store.ErrSavedViewInvalidState, view.ID, err,
		)
	}
	if err := validateExecutable(state); err != nil {
		return store.SavedViewStateEnvelope{}, fmt.Errorf(
			"%w: Saved View %d: %w", store.ErrSavedViewInvalidState, view.ID, err,
		)
	}
	return state, nil
}

func validateExecutable(state store.SavedViewStateEnvelope) error {
	for i, filter := range state.Filters {
		if !slices.Contains(FilterFields, FilterDimension(filter.Field)) {
			return fmt.Errorf("filters[%d].field %q is not executable", i, filter.Field)
		}
		if !slices.Contains(FilterOperators, filter.Operator) {
			return fmt.Errorf("filters[%d].operator must be eq or in", i)
		}
		if len(filter.Values) == 0 {
			return fmt.Errorf("filters[%d].values must not be empty", i)
		}
		for j, value := range filter.Values {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("filters[%d].values[%d] must not be empty", i, j)
			}
		}
	}
	if state.SearchMode != "" && !slices.Contains(SearchModes, state.SearchMode) {
		return fmt.Errorf("search_mode %q is not supported", state.SearchMode)
	}
	for i, grouping := range state.Grouping {
		if !explorecatalog.IsGroupingDimension(grouping) {
			return fmt.Errorf("grouping[%d] %q is not supported", i, grouping)
		}
	}
	if state.Presentation != "" && !slices.Contains(Presentations, state.Presentation) {
		return fmt.Errorf("presentation %q is not supported", state.Presentation)
	}
	for i, sort := range state.Sort {
		if !slices.Contains(SortFields, sort.Field) || !slices.Contains(SortDirections, sort.Direction) {
			return fmt.Errorf("sort[%d] must be occurred_at descending", i)
		}
	}
	for i, column := range state.Columns {
		if !slices.Contains(Columns, column) {
			return fmt.Errorf("columns[%d] %q is not supported", i, column)
		}
	}
	return nil
}
