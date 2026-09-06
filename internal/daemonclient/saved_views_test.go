package daemonclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/savedview"
	"go.kenn.io/msgvault/internal/store"
	"go.kenn.io/msgvault/internal/vector"
	"go.kenn.io/msgvault/pkg/client/generated"
)

const savedViewFixtureJSON = `{
	"id":7,"name":"Invoices","description":"Reusable invoice search",
	"canonical_state":{
		"query":"quarterly invoice","search_mode":"hybrid",
		"filters":[{"field":"source_id","operator":"in","values":["3"]}],
		"presentation":"timeline","sort":[{"field":"occurred_at","direction":"desc"}],
		"columns":["kind","title","time"]
	},
	"schema_version":1,"revision":2,
	"created_at":"2026-08-18T08:00:00Z","updated_at":"2026-08-18T09:00:00Z"
}`

func TestRunSavedViewUsesCanonicalExploreDefinition(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)
	var explored generated.ExploreHTTPRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/saved-views/7":
			_, _ = w.Write([]byte(savedViewFixtureJSON))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/explore":
			if !assertions.NoError(json.NewDecoder(r.Body).Decode(&explored)) {
				return
			}
			_, _ = w.Write([]byte(`{
				"rows":[{
					"key":"message:42","kind":"email","anchor_message_id":42,
					"occurred_at":"2026-08-18T07:00:00Z","match":{"semantic_score":0.91},
					"source_id":3,"source_type":"gmail","source_identifier":"archive@example.com",
					"message_type":"email","conversation_type":"thread","title":"Quarterly invoice",
					"preview":"Invoice details","matched_sender_identities":["archive@example.com"],
					"matched_recipient_identities":["billing@example.com"],"message_count":1,
					"has_attachments":true,"attachment_count":1,"attachment_size":2048,
					"deleted_from_source":false
				}],
				"total_count":1,"cache_revision":"cache-9",
				"search_provenance":{"lexical_index_revision":"fts-4","vector_generation":12}
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client := newSavedViewTestClient(t, server)

	page, err := client.RunSavedView(t.Context(), 7, 25, "")
	requirements.NoError(err)
	assertions.Equal(savedview.ResultEntries, page.ResultKind)
	requirements.Len(page.Rows, 1)
	assertions.Equal("Quarterly invoice", page.Rows[0].Title)
	assertions.Equal("cache-9", page.CacheRevision)

	requirements.NotNil(explored.Query)
	assertions.Equal("quarterly invoice", *explored.Query)
	requirements.NotNil(explored.SearchMode)
	assertions.Equal(generated.ExploreHTTPRequestSearchModeHybrid, *explored.SearchMode)
	requirements.Len(explored.Filters, 1)
	assertions.Equal(generated.ExploreFilterDimensionSource, explored.Filters[0].Dimension)
	assertions.Equal([]string{"3"}, explored.Filters[0].Values)
	requirements.NotNil(explored.Presentation)
	assertions.Equal(generated.ExploreHTTPRequestPresentationTable, *explored.Presentation,
		"timeline uses the same canonical entry query and changes only client rendering")
	requirements.Len(explored.Sort, 1)
	assertions.Equal(generated.ExploreSortFieldOccurredAt, explored.Sort[0].Field)
	assertions.Equal(generated.ExploreSortDirectionDesc, explored.Sort[0].Direction)
}

func TestRunSavedViewPreservesGrouping(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)
	groupedView := `{
		"id":8,"name":"By domain","canonical_state":{"grouping":["domain"],"presentation":"table"},
		"schema_version":1,"revision":1,
		"created_at":"2026-08-18T08:00:00Z","updated_at":"2026-08-18T09:00:00Z"
	}`
	var grouped generated.ExploreGroupsHTTPRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/saved-views/8":
			_, _ = w.Write([]byte(groupedView))
		case "/api/v1/explore/groups":
			if !assertions.Equal(http.MethodPost, r.Method) ||
				!assertions.NoError(json.NewDecoder(r.Body).Decode(&grouped)) {
				return
			}
			_, _ = w.Write([]byte(`{
				"rows":[{"key":"example.com","label":"example.com","count":4,"estimated_bytes":1024,"latest_at":"2026-08-18T07:00:00Z"}],
				"total_count":1,"cache_revision":"cache-groups","search_provenance":{}
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	page, err := newSavedViewTestClient(t, server).RunSavedView(t.Context(), 8, 20, "")
	requirements.NoError(err)
	assertions.Equal(savedview.ResultGroups, page.ResultKind)
	requirements.Len(page.Groups, 1)
	assertions.Equal("example.com", page.Groups[0].Key)
	assertions.Equal([]generated.ExploreGroupDimension{generated.ExploreGroupDimensionDomain}, grouped.Grouping)
}

func TestRunSavedViewPreservesFilesPresentationAndCursor(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)
	filesView := `{
		"id":10,"name":"Invoice files","canonical_state":{
			"query":"invoice","search_mode":"full_text","presentation":"files",
			"filters":[{"field":"domain","operator":"eq","values":["example.com"]}]
		},
		"schema_version":1,"revision":1,
		"created_at":"2026-08-18T08:00:00Z","updated_at":"2026-08-18T09:00:00Z"
	}`
	var filesRequest generated.ExploreFilesHTTPRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/saved-views/10":
			_, _ = w.Write([]byte(filesView))
		case "/api/v1/explore/files":
			if !assertions.Equal(http.MethodPost, r.Method) ||
				!assertions.NoError(json.NewDecoder(r.Body).Decode(&filesRequest)) {
				return
			}
			_, _ = w.Write([]byte(`{
				"files":[{
					"id":5,"key":"attachment:5","entry_key":"message:42","message_id":42,
					"occurred_at":"2026-08-18T07:00:00Z","source_id":3,
					"source_identifier":"archive@example.com","title":"Invoice",
					"filename":"invoice.pdf","mime_type":"application/pdf","size":2048
				}],
				"total_count":2,"cache_revision":"cache-files","search_provenance":{},
				"next_cursor":"files-next"
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	page, err := newSavedViewTestClient(t, server).RunSavedView(t.Context(), 10, 20, "files-current")
	requirements.NoError(err)
	assertions.Equal(savedview.ResultFiles, page.ResultKind)
	requirements.Len(page.Files, 1)
	assertions.Equal("invoice.pdf", page.Files[0].Filename)
	assertions.Equal("files-next", page.NextCursor)
	requirements.NotNil(filesRequest.Cursor)
	assertions.Equal("files-current", *filesRequest.Cursor)
	assertions.Nil(filesRequest.Predicate.Cursor, "the outer files cursor owns pagination")
	requirements.NotNil(filesRequest.Predicate.Query)
	assertions.Equal("invoice", *filesRequest.Predicate.Query)
	requirements.Len(filesRequest.Predicate.Filters, 1)
	assertions.Equal(generated.ExploreFilterDimensionDomain, filesRequest.Predicate.Filters[0].Dimension)
}

func TestRunSavedViewRejectsInvalidDefinitionBeforeExplore(t *testing.T) {
	invalid := `{
		"id":9,"name":"Invalid","canonical_state":{"filters":[{"field":"source","operator":"contains","values":["3"]}]},
		"schema_version":1,"revision":1,
		"created_at":"2026-08-18T08:00:00Z","updated_at":"2026-08-18T09:00:00Z"
	}`
	var exploreCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/saved-views/9" {
			_, _ = w.Write([]byte(invalid))
			return
		}
		exploreCalls++
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	_, err := newSavedViewTestClient(t, server).RunSavedView(t.Context(), 9, 20, "")
	require.ErrorIs(t, err, store.ErrSavedViewInvalidState)
	assert.Zero(t, exploreCalls)
}

func TestRunSavedViewSurfacesVectorCapabilityError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/saved-views/7" {
			_, _ = w.Write([]byte(savedViewFixtureJSON))
			return
		}
		if r.URL.Path == "/api/v1/explore" {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"vector_not_enabled","message":"Vector search is not configured"}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	_, err := newSavedViewTestClient(t, server).RunSavedView(t.Context(), 7, 20, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, vector.ErrNotEnabled)
}

func TestSavedViewManagementUsesAPIRevisionContract(t *testing.T) {
	assertions := assert.New(t)
	requirements := require.New(t)
	var createBody map[string]any
	var patchBody map[string]any
	var patchMatch string
	var deleteMatch string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/saved-views":
			if !assertions.NoError(json.NewDecoder(r.Body).Decode(&createBody)) {
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(savedViewFixtureJSON))
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/saved-views/7":
			patchMatch = r.Header.Get("If-Match")
			if !assertions.NoError(json.NewDecoder(r.Body).Decode(&patchBody)) {
				return
			}
			_, _ = w.Write([]byte(`{
				"id":7,"name":"Receipts","canonical_state":{"query":"receipt","presentation":"table"},
				"schema_version":1,"revision":3,
				"created_at":"2026-08-18T08:00:00Z","updated_at":"2026-08-18T10:00:00Z"
			}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/saved-views/7":
			deleteMatch = r.Header.Get("If-Match")
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client := newSavedViewTestClient(t, server)
	description := "Reusable invoice search"

	created, err := client.CreateSavedView(t.Context(), store.SavedViewInput{
		Name: "Invoices", Description: &description,
		CanonicalState: json.RawMessage(`{"query":"quarterly invoice","search_mode":"hybrid"}`),
		SchemaVersion:  1,
	})
	requirements.NoError(err)
	assertions.Equal(int64(7), created.ID)
	assertions.Equal("Invoices", createBody["name"])
	createState, ok := createBody["canonical_state"].(map[string]any)
	requirements.True(ok, "canonical_state: %#v", createBody["canonical_state"])
	assertions.Equal("hybrid", createState["search_mode"])

	name := "Receipts"
	emptyDescription := ""
	state := store.SavedViewStateEnvelope{Query: "receipt", Presentation: "table"}
	updated, err := client.UpdateSavedView(t.Context(), 7, 2, savedview.Patch{
		Name: &name, Description: &emptyDescription, CanonicalState: &state,
	})
	requirements.NoError(err)
	assertions.Equal(int64(3), updated.Revision)
	assertions.Equal(`"saved-view-7-r2"`, patchMatch)
	assertions.Equal("Receipts", patchBody["name"])
	assertions.Empty(patchBody["description"])
	patchState, ok := patchBody["canonical_state"].(map[string]any)
	requirements.True(ok, "canonical_state: %#v", patchBody["canonical_state"])
	assertions.Equal("receipt", patchState["query"])
	assertions.NotContains(patchBody, "schema_version")

	requirements.NoError(client.DeleteSavedView(t.Context(), 7, 3))
	assertions.Equal(`"saved-view-7-r3"`, deleteMatch)
}

func TestSavedViewManagementMapsDomainErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{
			"error":"saved_view_revision_conflict",
			"message":"Saved View revision does not match"
		}`))
	}))
	t.Cleanup(server.Close)

	name := "Stale"
	_, err := newSavedViewTestClient(t, server).UpdateSavedView(
		t.Context(), 7, 1, savedview.Patch{Name: &name},
	)
	require.ErrorIs(t, err, store.ErrSavedViewRevisionConflict)
}

func TestCreateSavedViewRejectsTransientStateBeforeRequest(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	_, err := newSavedViewTestClient(t, server).CreateSavedView(t.Context(), store.SavedViewInput{
		Name: "Invalid", CanonicalState: json.RawMessage(`{"selection":[1]}`), SchemaVersion: 1,
	})
	require.ErrorIs(t, err, store.ErrSavedViewInvalidState)
	assert.Zero(t, calls)
}

func newSavedViewTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	client, err := New(Config{
		URL: server.URL, AllowInsecure: true, HTTPClient: server.Client(),
		Context: t.Context(), RequestMode: RequestModeCLI,
	})
	require.NoError(t, err)
	return client
}
