package savedview

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/store"
)

func TestExecutableStateDecodesCanonicalDefinition(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)
	state, err := ExecutableState(store.SavedView{
		ID: 7, SchemaVersion: store.CurrentSavedViewSchemaVersion,
		CanonicalState: json.RawMessage(`{
			"query":"invoice","search_mode":"hybrid",
			"filters":[{"field":"source_id","operator":"in","values":["3"]}],
			"grouping":["domain"],"presentation":"files",
			"sort":[{"field":"occurred_at","direction":"desc"}],
			"columns":["kind","title"]
		}`),
	})
	requirements.NoError(err)
	assertions.Equal("invoice", state.Query)
	assertions.Equal("hybrid", state.SearchMode)
	requirements.Len(state.Filters, 1)
	assertions.Equal("source_id", state.Filters[0].Field, "aliases are preserved in the decoded state")
	assertions.Equal("source", FilterDimension(state.Filters[0].Field))
	assertions.Equal("participant", FilterDimension("participant_id"))
	assertions.Equal("domain", FilterDimension("domain"))
}

func TestExecutableStateRejectsNonExecutableDefinitions(t *testing.T) {
	cases := []struct {
		name    string
		view    store.SavedView
		wantErr error
		message string
	}{
		{
			name:    "unsupported schema version",
			view:    store.SavedView{ID: 1, SchemaVersion: 2, CanonicalState: json.RawMessage(`{}`)},
			wantErr: store.ErrSavedViewUnsupportedSchemaVersion,
			message: "schema version 2",
		},
		{
			name:    "malformed state",
			view:    store.SavedView{ID: 2, SchemaVersion: 1, CanonicalState: json.RawMessage(`{"query":`)},
			wantErr: store.ErrSavedViewInvalidState,
			message: "decode Saved View 2",
		},
		{
			name: "unknown filter field",
			view: store.SavedView{ID: 3, SchemaVersion: 1, CanonicalState: json.RawMessage(
				`{"filters":[{"field":"identity","operator":"eq","values":["x"]}]}`)},
			wantErr: store.ErrSavedViewInvalidState,
			message: `filters[0].field "identity" is not executable`,
		},
		{
			name: "unsupported operator",
			view: store.SavedView{ID: 4, SchemaVersion: 1, CanonicalState: json.RawMessage(
				`{"filters":[{"field":"source","operator":"contains","values":["3"]}]}`)},
			wantErr: store.ErrSavedViewInvalidState,
			message: "filters[0].operator must be eq or in",
		},
		{
			name: "blank filter value",
			view: store.SavedView{ID: 5, SchemaVersion: 1, CanonicalState: json.RawMessage(
				`{"filters":[{"field":"domain","operator":"eq","values":[" "]}]}`)},
			wantErr: store.ErrSavedViewInvalidState,
			message: "filters[0].values[0] must not be empty",
		},
		{
			name:    "unsupported search mode",
			view:    store.SavedView{ID: 6, SchemaVersion: 1, CanonicalState: json.RawMessage(`{"search_mode":"regex"}`)},
			wantErr: store.ErrSavedViewInvalidState,
			message: `search_mode "regex" is not supported`,
		},
		{
			name:    "unsupported grouping",
			view:    store.SavedView{ID: 7, SchemaVersion: 1, CanonicalState: json.RawMessage(`{"grouping":["weekday"]}`)},
			wantErr: store.ErrSavedViewInvalidState,
			message: `grouping[0] "weekday" is not supported`,
		},
		{
			name:    "unsupported presentation",
			view:    store.SavedView{ID: 8, SchemaVersion: 1, CanonicalState: json.RawMessage(`{"presentation":"map"}`)},
			wantErr: store.ErrSavedViewInvalidState,
			message: `presentation "map" is not supported`,
		},
		{
			name: "ascending sort",
			view: store.SavedView{ID: 9, SchemaVersion: 1, CanonicalState: json.RawMessage(
				`{"sort":[{"field":"occurred_at","direction":"asc"}]}`)},
			wantErr: store.ErrSavedViewInvalidState,
			message: "sort[0] must be occurred_at descending",
		},
		{
			name:    "unknown column",
			view:    store.SavedView{ID: 10, SchemaVersion: 1, CanonicalState: json.RawMessage(`{"columns":["labels"]}`)},
			wantErr: store.ErrSavedViewInvalidState,
			message: `columns[0] "labels" is not supported`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ExecutableState(tc.view)
			require.ErrorIs(t, err, tc.wantErr)
			assert.ErrorContains(t, err, tc.message)
		})
	}
}
