package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/config"
)

// stubInboxArchiveRunner stands in for the provider work the daemon does.
type stubInboxArchiveRunner struct {
	calls  []InboxArchiveRunRequest
	result InboxArchiveRunResult
	err    error
}

func (s *stubInboxArchiveRunner) RunInboxArchive(
	_ context.Context, req InboxArchiveRunRequest,
) (InboxArchiveRunResult, error) {
	s.calls = append(s.calls, req)
	return s.result, s.err
}

func newInboxArchiveServer(
	t *testing.T, enabled bool, runner InboxArchiveRunner,
) *Server {
	t.Helper()
	return NewServerWithOptions(ServerOptions{
		Config: &config.Config{
			InboxArchive: config.InboxArchiveConfig{RemoteEnabled: enabled},
		},
		Store:         &operationArchiveStore{mockStore: &mockStore{}, uid: operationTestArchiveUID},
		OperationGate: NewSerialOperationGate(),
		InboxArchive:  runner,
		Logger:        testLogger(),
	})
}

func doInboxArchivePost(
	t *testing.T, srv *Server, path string, body any,
) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Router().ServeHTTP(w, req)
	return w
}

func authorizeInboxArchive(t *testing.T, srv *Server, ids []string) string {
	t.Helper()
	w := doInboxArchivePost(t, srv, "/api/v1/inbox-archive/authorize",
		InboxArchiveAuthorizeRequest{
			Account: "alice@example.com", SourceID: 1, SourceMessageIDs: ids,
		})
	require.Equalf(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp InboxArchiveAuthorizeResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.ConfirmationToken)
	return resp.ConfirmationToken
}

// TestInboxArchiveRefusedWithoutDaemonOptIn is the daemon's own gate. The MCP
// server's --allow-mailbox-writes decides whether a model may ask; this decides
// whether the daemon acts, and the endpoint is reachable by every API client.
func TestInboxArchiveRefusedWithoutDaemonOptIn(t *testing.T) {
	assert := assert.New(t)
	runner := &stubInboxArchiveRunner{}
	srv := newInboxArchiveServer(t, false, runner)

	authorized := doInboxArchivePost(t, srv, "/api/v1/inbox-archive/authorize",
		InboxArchiveAuthorizeRequest{
			Account: "alice@example.com", SourceID: 1, SourceMessageIDs: []string{"m-1"},
		})
	assert.Equal(http.StatusForbidden, authorized.Code)
	assert.Equal("mailbox_writes_disabled", decodeErrorEnvelope(t, authorized).Error)

	executed := doInboxArchivePost(t, srv, "/api/v1/inbox-archive/execute",
		InboxArchiveExecuteRequest{ConfirmationToken: "t", SourceMessageIDs: []string{"m-1"}})
	assert.Equal(http.StatusForbidden, executed.Code)
	assert.Empty(runner.calls, "nothing may reach the provider while writes are disabled")
}

func TestInboxArchiveAuthorizeThenExecute(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	runner := &stubInboxArchiveRunner{result: InboxArchiveRunResult{Archived: 2}}
	srv := newInboxArchiveServer(t, true, runner)
	ids := []string{"m-1", "m-2"}

	token := authorizeInboxArchive(t, srv, ids)
	assert.Empty(runner.calls, "authorizing must not archive anything")

	w := doInboxArchivePost(t, srv, "/api/v1/inbox-archive/execute",
		InboxArchiveExecuteRequest{ConfirmationToken: token, SourceMessageIDs: ids})
	require.Equalf(http.StatusOK, w.Code, "body: %s", w.Body.String())

	var resp InboxArchiveExecuteResponse
	require.NoError(json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(2, int(resp.Archived))
	assert.Equal("alice@example.com", resp.Account)
	assert.NotEmpty(resp.BatchID)

	require.Len(runner.calls, 1)
	assert.Equal(int64(1), runner.calls[0].SourceID)
	assert.Equal(ids, runner.calls[0].SourceMessageIDs)
}

// TestInboxArchiveTokenBindsToItsSelection is the point of the token: a plan the
// user approved must not be redeemable against different messages.
func TestInboxArchiveTokenBindsToItsSelection(t *testing.T) {
	assert := assert.New(t)
	runner := &stubInboxArchiveRunner{}
	srv := newInboxArchiveServer(t, true, runner)

	token := authorizeInboxArchive(t, srv, []string{"m-1", "m-2"})

	tests := []struct {
		name string
		ids  []string
	}{
		{name: "an extra message", ids: []string{"m-1", "m-2", "m-3"}},
		{name: "a swapped message", ids: []string{"m-1", "m-9"}},
		{name: "a subset", ids: []string{"m-1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := doInboxArchivePost(t, srv, "/api/v1/inbox-archive/execute",
				InboxArchiveExecuteRequest{ConfirmationToken: token, SourceMessageIDs: tc.ids})
			assert.Equal(http.StatusPreconditionFailed, w.Code)
			assert.Equal("confirmation_token_invalid", decodeErrorEnvelope(t, w).Error)
		})
	}
	assert.Empty(runner.calls)
}

// TestInboxArchiveTokenOrderDoesNotMatter: the order ids arrive in is not part
// of what the user approved, so it must not invalidate their confirmation.
func TestInboxArchiveTokenOrderDoesNotMatter(t *testing.T) {
	require := require.New(t)
	srv := newInboxArchiveServer(t, true, &stubInboxArchiveRunner{})

	token := authorizeInboxArchive(t, srv, []string{"m-1", "m-2", "m-3"})

	w := doInboxArchivePost(t, srv, "/api/v1/inbox-archive/execute",
		InboxArchiveExecuteRequest{
			ConfirmationToken: token, SourceMessageIDs: []string{"m-3", "m-1", "m-2"},
		})
	require.Equalf(http.StatusOK, w.Code, "body: %s", w.Body.String())
}

func TestInboxArchiveTokenIsSpentOnce(t *testing.T) {
	assert := assert.New(t)
	runner := &stubInboxArchiveRunner{}
	srv := newInboxArchiveServer(t, true, runner)
	ids := []string{"m-1"}

	token := authorizeInboxArchive(t, srv, ids)

	first := doInboxArchivePost(t, srv, "/api/v1/inbox-archive/execute",
		InboxArchiveExecuteRequest{ConfirmationToken: token, SourceMessageIDs: ids})
	assert.Equal(http.StatusOK, first.Code)

	second := doInboxArchivePost(t, srv, "/api/v1/inbox-archive/execute",
		InboxArchiveExecuteRequest{ConfirmationToken: token, SourceMessageIDs: ids})
	assert.Equal(http.StatusPreconditionFailed, second.Code)
	assert.Equal("confirmation_token_invalid", decodeErrorEnvelope(t, second).Error)
	assert.Len(runner.calls, 1, "a spent token must not reach the provider again")
}

func TestInboxArchiveRejectsForeignAndMalformedTokens(t *testing.T) {
	assert := assert.New(t)
	srv := newInboxArchiveServer(t, true, &stubInboxArchiveRunner{})

	for _, token := range []string{"not-a-token", "op2.deadbeef", ""} {
		w := doInboxArchivePost(t, srv, "/api/v1/inbox-archive/execute",
			InboxArchiveExecuteRequest{ConfirmationToken: token, SourceMessageIDs: []string{"m-1"}})
		assert.Truef(w.Code == http.StatusPreconditionFailed || w.Code == http.StatusPreconditionRequired,
			"token %q: unexpected status %d: %s", token, w.Code, w.Body.String())
	}
}

func TestInboxArchiveValidatesSelection(t *testing.T) {
	assert := assert.New(t)
	srv := newInboxArchiveServer(t, true, &stubInboxArchiveRunner{})

	tooMany := make([]string, maxInboxArchiveMessages+1)
	for i := range tooMany {
		tooMany[i] = "m"
	}

	tests := []struct {
		name   string
		req    InboxArchiveAuthorizeRequest
		status int
		code   string
	}{
		{
			name:   "no source",
			req:    InboxArchiveAuthorizeRequest{Account: "a", SourceMessageIDs: []string{"m-1"}},
			status: http.StatusBadRequest, code: "invalid_request",
		},
		{
			name:   "no messages",
			req:    InboxArchiveAuthorizeRequest{Account: "a", SourceID: 1},
			status: http.StatusBadRequest, code: "invalid_request",
		},
		{
			name:   "blank message id",
			req:    InboxArchiveAuthorizeRequest{Account: "a", SourceID: 1, SourceMessageIDs: []string{" "}},
			status: http.StatusBadRequest, code: "invalid_request",
		},
		{
			name:   "over the per-call cap",
			req:    InboxArchiveAuthorizeRequest{Account: "a", SourceID: 1, SourceMessageIDs: tooMany},
			status: http.StatusUnprocessableEntity, code: "selection_too_large",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := doInboxArchivePost(t, srv, "/api/v1/inbox-archive/authorize", tc.req)
			assert.Equal(tc.status, w.Code, "body: %s", w.Body.String())
			assert.Equal(tc.code, decodeErrorEnvelope(t, w).Error)
		})
	}
}

func TestInboxArchiveReportsUnsupportedSource(t *testing.T) {
	assert := assert.New(t)
	runner := &stubInboxArchiveRunner{err: ErrInboxArchiveUnsupportedSource}
	srv := newInboxArchiveServer(t, true, runner)
	ids := []string{"m-1"}

	token := authorizeInboxArchive(t, srv, ids)
	w := doInboxArchivePost(t, srv, "/api/v1/inbox-archive/execute",
		InboxArchiveExecuteRequest{ConfirmationToken: token, SourceMessageIDs: ids})

	assert.Equal(http.StatusUnprocessableEntity, w.Code)
	assert.Equal("unsupported_source", decodeErrorEnvelope(t, w).Error)
}

func TestInboxArchiveUnavailableWithoutRunner(t *testing.T) {
	assert := assert.New(t)
	srv := newInboxArchiveServer(t, true, nil)

	w := doInboxArchivePost(t, srv, "/api/v1/inbox-archive/authorize",
		InboxArchiveAuthorizeRequest{Account: "a", SourceID: 1, SourceMessageIDs: []string{"m-1"}})

	assert.Equal(http.StatusServiceUnavailable, w.Code)
	assert.Equal("mailbox_writes_unavailable", decodeErrorEnvelope(t, w).Error)
}

// TestInboxArchiveSelectionHashIgnoresOrderButNotContent guards the binding
// directly: concatenating ids without a delimiter would let {"ab","c"} and
// {"a","bc"} share a token.
func TestInboxArchiveSelectionHashIgnoresOrderButNotContent(t *testing.T) {
	assert := assert.New(t)

	base := inboxArchiveSelectionHash(1, []string{"ab", "c"})
	assert.Equal(base, inboxArchiveSelectionHash(1, []string{"c", "ab"}))
	assert.NotEqual(base, inboxArchiveSelectionHash(1, []string{"a", "bc"}))
	assert.NotEqual(base, inboxArchiveSelectionHash(2, []string{"ab", "c"}))
}

func TestInboxArchivePartialFailureIsReported(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	runner := &stubInboxArchiveRunner{
		result: InboxArchiveRunResult{
			Archived: 1, Failed: 1, Remaining: 3,
			FailedIDs: []string{"m-2"}, Yielded: true,
		},
		err: errors.New("provider refused the rest"),
	}
	srv := newInboxArchiveServer(t, true, runner)
	ids := []string{"m-1", "m-2"}
	token := authorizeInboxArchive(t, srv, ids)

	w := doInboxArchivePost(t, srv, "/api/v1/inbox-archive/execute",
		InboxArchiveExecuteRequest{ConfirmationToken: token, SourceMessageIDs: ids})

	require.Equal(http.StatusInternalServerError, w.Code)
	assert.Equal("archive_failed", decodeErrorEnvelope(t, w).Error)
}

// TestInboxArchiveAuthorizeIsNotGatedButExecuteIs pins the split: minting a
// token reads and seals, so it must not queue behind a long-running mutation,
// while the archive itself takes the same serial gate as every other mutating
// request rather than racing a scheduled sync of the same source.
func TestInboxArchiveAuthorizeIsNotGatedButExecuteIs(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	gate := NewSerialOperationGate()
	srv := NewServerWithOptions(ServerOptions{
		Config: &config.Config{
			InboxArchive: config.InboxArchiveConfig{RemoteEnabled: true},
		},
		Store:         &operationArchiveStore{mockStore: &mockStore{}, uid: operationTestArchiveUID},
		OperationGate: gate,
		InboxArchive:  &stubInboxArchiveRunner{},
		Logger:        testLogger(),
	})

	// Authorize first, while the gate is free, so the token exists.
	ids := []string{"m-1"}
	token := authorizeInboxArchive(t, srv, ids)

	release, ok := gate.BeginWorkContext(t.Context())
	require.True(ok, "test could not take the gate")
	defer release()

	// A token can still be minted while something else holds the gate.
	authorized := doInboxArchivePost(t, srv, "/api/v1/inbox-archive/authorize",
		InboxArchiveAuthorizeRequest{
			Account: "alice@example.com", SourceID: 1, SourceMessageIDs: ids,
		})
	assert.Equalf(http.StatusOK, authorized.Code, "body: %s", authorized.Body.String())

	// Archiving must not proceed alongside the other operation. The request
	// carries its own short deadline so the assertion does not sit through the
	// gate's full ten-second wait; what is under test is that it is turned
	// away, not how long it is willing to queue.
	payload, err := json.Marshal(
		InboxArchiveExecuteRequest{ConfirmationToken: token, SourceMessageIDs: ids})
	require.NoError(err)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodPost,
		"/api/v1/inbox-archive/execute", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	executed := httptest.NewRecorder()
	srv.Router().ServeHTTP(executed, req)

	assert.Equal(http.StatusServiceUnavailable, executed.Code)
	assert.Equal("operation_in_progress", decodeErrorEnvelope(t, executed).Error)
}
