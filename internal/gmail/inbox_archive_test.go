package gmail

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordedRequest struct {
	method string
	path   string
	body   map[string]any
}

// archiveTestServer stands in for Gmail and records what the client actually
// sent, so the assertions are about the wire request rather than about the
// client's own bookkeeping.
func archiveTestServer(t *testing.T, status int) (*Client, func() []recordedRequest) {
	t.Helper()

	var mu sync.Mutex
	var requests []recordedRequest

	// The handler runs on the server's goroutine, where a failed assertion
	// could not stop the test cleanly, so problems are recorded and asserted
	// on the test's own goroutine instead.
	var handlerErr error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, err := io.ReadAll(r.Body)
		recorded := recordedRequest{method: r.Method, path: r.URL.Path}
		if err == nil && len(payload) > 0 {
			err = json.Unmarshal(payload, &recorded.body)
		}

		mu.Lock()
		if err != nil && handlerErr == nil {
			handlerErr = err
		}
		requests = append(requests, recorded)
		mu.Unlock()

		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)

	client := &Client{
		httpClient: &http.Client{
			Transport: &rewriteTransport{base: srv.URL, wrapped: http.DefaultTransport},
		},
		userID:      "me",
		concurrency: 1,
		rateLimiter: NewRateLimiter(1000),
	}

	return client, func() []recordedRequest {
		mu.Lock()
		defer mu.Unlock()
		require.NoError(t, handlerErr, "test server could not read a request")
		out := make([]recordedRequest, len(requests))
		copy(out, requests)
		return out
	}
}

func TestArchiveFromInboxRemovesOnlyTheInboxLabel(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	client, recorded := archiveTestServer(t, http.StatusNoContent)

	failures, err := client.ArchiveFromInbox(
		context.Background(), []string{"msg-1", "msg-2"})
	require.NoError(err)
	assert.Empty(failures, "batchModify is applied as a unit, so nothing is partially failed")

	requests := recorded()
	require.Len(requests, 1, "two messages must cost one request, not two")
	assert.Equal(http.MethodPost, requests[0].method)
	assert.True(strings.HasSuffix(requests[0].path, "/users/me/messages/batchModify"),
		"unexpected path %q", requests[0].path)
	assert.Equal([]any{"msg-1", "msg-2"}, requests[0].body["ids"])
	assert.Equal([]any{"INBOX"}, requests[0].body["removeLabelIds"])
	assert.NotContains(requests[0].body, "addLabelIds",
		"archiving must not add labels")
	assert.NotContains(requests[0].body, "deleteLabelIds")
}

func TestArchiveFromInboxEmptyInputIssuesNoRequest(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	client, recorded := archiveTestServer(t, http.StatusNoContent)

	failures, err := client.ArchiveFromInbox(context.Background(), nil)
	require.NoError(err)
	assert.Empty(failures)
	assert.Empty(recorded())
}

// TestArchiveFromInboxRefusesOversizedBatch: Gmail caps batchModify at 1000
// ids. Sending more silently modifies nothing, so it has to be refused here.
func TestArchiveFromInboxRefusesOversizedBatch(t *testing.T) {
	assert := assert.New(t)

	client, recorded := archiveTestServer(t, http.StatusNoContent)

	ids := make([]string, 1001)
	for i := range ids {
		ids[i] = "msg"
	}

	_, err := client.ArchiveFromInbox(context.Background(), ids)
	require.Error(t, err)
	assert.Empty(recorded(), "an oversized batch must not reach the API")
}

// TestArchiveFromInboxPropagatesProviderErrors: a refused batch is fatal for
// every id in it, so the caller must not record any of them as archived.
func TestArchiveFromInboxPropagatesProviderErrors(t *testing.T) {
	assert := assert.New(t)

	client, _ := archiveTestServer(t, http.StatusForbidden)

	failures, err := client.ArchiveFromInbox(
		context.Background(), []string{"msg-1"})
	require.Error(t, err)
	assert.Empty(failures)
}
