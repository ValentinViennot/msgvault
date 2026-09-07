package mcp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.kenn.io/msgvault/internal/query"
	"go.kenn.io/msgvault/internal/query/querytest"
)

// fakeInboxArchiver records what the tool asked the daemon to do.
type fakeInboxArchiver struct {
	token         string
	authorizeErr  error
	executeErr    error
	result        InboxArchiveResult
	authorizeReqs []InboxArchiveAuthorizeRequest
	executeReqs   []InboxArchiveExecuteRequest
}

func (f *fakeInboxArchiver) AuthorizeInboxArchive(
	_ context.Context, req InboxArchiveAuthorizeRequest,
) (string, error) {
	f.authorizeReqs = append(f.authorizeReqs, req)
	if f.authorizeErr != nil {
		return "", f.authorizeErr
	}
	if f.token == "" {
		return "token-abc", nil
	}
	return f.token, nil
}

func (f *fakeInboxArchiver) ExecuteInboxArchive(
	_ context.Context, req InboxArchiveExecuteRequest,
) (InboxArchiveResult, error) {
	f.executeReqs = append(f.executeReqs, req)
	if f.executeErr != nil {
		return InboxArchiveResult{}, f.executeErr
	}
	return f.result, nil
}

func inboxArchiveEngine() *querytest.MockEngine {
	return &querytest.MockEngine{
		Accounts: []query.AccountInfo{
			{ID: 1, SourceType: "gmail", Identifier: "alice@example.com"},
		},
		GmailIDs: []string{"gmail-001", "gmail-002"},
		SearchFastResults: []query.MessageSummary{
			{ID: 1, SourceID: 1, Subject: "Newsletter", FromEmail: "news@example.com", SourceMessageID: "gmail-001"},
			{ID: 2, SourceID: 1, Subject: "Promo", FromEmail: "promo@example.com", SourceMessageID: "gmail-002"},
		},
	}
}

// TestArchiveFromInboxNeedsBothOptIns is the gate test. stdio passes
// allowWrites=true unconditionally, so allowWrites alone must not be enough to
// expose a tool that reaches the user's live mailbox.
func TestArchiveFromInboxNeedsBothOptIns(t *testing.T) {
	archiver := &fakeInboxArchiver{}

	tests := []struct {
		name    string
		opts    ServeOptions
		exposed bool
	}{
		{
			name: "neither opt-in",
			opts: ServeOptions{Engine: &querytest.MockEngine{}},
		},
		{
			name: "flag without a daemon seam",
			opts: ServeOptions{Engine: &querytest.MockEngine{}, AllowMailboxWrites: true},
		},
		{
			name: "daemon seam without the flag",
			opts: ServeOptions{Engine: &querytest.MockEngine{}, InboxArchiver: archiver},
		},
		{
			name:    "both",
			opts:    ServeOptions{Engine: &querytest.MockEngine{}, AllowMailboxWrites: true, InboxArchiver: archiver},
			exposed: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// allowWrites=true is what stdio hardcodes.
			byName := toolsByName(t, rawListTools(t, tc.opts, true))
			_, present := byName[ToolArchiveFromInbox]
			assert.Equal(t, tc.exposed, present)

			// A read-only server never exposes it, whatever else is set.
			readOnly := toolsByName(t, rawListTools(t, tc.opts, false))
			assert.NotContains(t, readOnly, ToolArchiveFromInbox)
		})
	}
}

// TestArchiveFromInboxIsTheOnlyDestructiveTool guards the annotation change.
// Every other tool reports destructiveHint:false, and that is how a client
// tells this one apart; generalising the annotation helper is exactly the kind
// of change that could silently flip the rest of the catalog.
func TestArchiveFromInboxIsTheOnlyDestructiveTool(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	opts := ServeOptions{
		Engine:             &querytest.MockEngine{},
		AllowMailboxWrites: true,
		InboxArchiver:      &fakeInboxArchiver{},
	}
	byName := toolsByName(t, rawListTools(t, opts, true))

	archive, ok := byName[ToolArchiveFromInbox]
	require.True(ok, "archive tool must be registered for this check")
	annotations, ok := archive["annotations"].(map[string]any)
	require.True(ok, "annotations: %#v", archive)

	assert.Equal(true, annotations["destructiveHint"])
	assert.Equal(true, annotations["openWorldHint"])
	assert.Equal(true, annotations["idempotentHint"])
	assert.Equal(false, annotations["readOnlyHint"])

	for name, tool := range byName {
		if name == ToolArchiveFromInbox {
			continue
		}
		other, ok := tool["annotations"].(map[string]any)
		require.True(ok, "%s annotations: %#v", name, tool)
		assert.Equal(false, other["destructiveHint"], "%s must stay non-destructive", name)
		assert.Equal(false, other["openWorldHint"], "%s must stay closed-world", name)
	}
}

func TestArchiveFromInboxPlanChangesNothing(t *testing.T) {
	assert := assert.New(t)

	archiver := &fakeInboxArchiver{token: "token-xyz"}
	h := &handlers{engine: inboxArchiveEngine(), inboxArchiver: archiver}

	resp := runTool[inboxArchivePlanResponse](
		t, ToolArchiveFromInbox, h.archiveFromInbox,
		map[string]any{"query": "label:INBOX from:news"},
	)

	assert.Equal("plan", resp.Status)
	assert.Equal("alice@example.com", resp.Account)
	assert.Equal(2, resp.MessageCount)
	assert.False(resp.Truncated)
	assert.Equal("token-xyz", resp.ConfirmationToken)
	assert.Contains(resp.NextStep, "explicitly agree")
	assert.Empty(archiver.executeReqs, "a plan must not archive anything")

	require.Len(t, archiver.authorizeReqs, 1)
	assert.Equal([]string{"gmail-001", "gmail-002"},
		archiver.authorizeReqs[0].SourceMessageIDs)
}

// TestArchiveFromInboxPlanNamesRealMessages: a count alone cannot show the user
// that the selection is wrong. The plan carries a sample.
func TestArchiveFromInboxPlanNamesRealMessages(t *testing.T) {
	assert := assert.New(t)

	engine := inboxArchiveEngine()
	engine.GetMessageSummariesByIDsFunc = func(
		_ context.Context, ids []int64,
	) ([]query.MessageSummary, error) {
		assert.Equal([]int64{1, 2}, ids)
		return engine.SearchFastResults, nil
	}
	h := &handlers{engine: engine, inboxArchiver: &fakeInboxArchiver{}}

	resp := runTool[inboxArchivePlanResponse](
		t, ToolArchiveFromInbox, h.archiveFromInbox,
		map[string]any{"query": "label:INBOX from:news"},
	)

	assert.Len(resp.Sample, 2)
	assert.Equal("Newsletter", resp.Sample[0].Subject)
	assert.Equal("news@example.com", resp.Sample[0].From)
}

func TestArchiveFromInboxConfirmWithoutTokenIsRefused(t *testing.T) {
	assert := assert.New(t)

	archiver := &fakeInboxArchiver{}
	h := &handlers{engine: inboxArchiveEngine(), inboxArchiver: archiver}

	result := runToolExpectError(t, ToolArchiveFromInbox, h.archiveFromInbox,
		map[string]any{"query": "from:news", "confirm": true})

	assert.Contains(resultText(t, result), "confirmation_required")
	assert.Empty(archiver.executeReqs)
	assert.Empty(archiver.authorizeReqs, "a bad confirm must not mint a token either")
}

func TestArchiveFromInboxExecutesWithToken(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	archiver := &fakeInboxArchiver{
		result: InboxArchiveResult{BatchID: "batch-1", Archived: 2},
	}
	h := &handlers{engine: inboxArchiveEngine(), inboxArchiver: archiver}

	resp := runTool[inboxArchiveExecuteResponse](
		t, ToolArchiveFromInbox, h.archiveFromInbox,
		map[string]any{
			"query": "from:news", "confirm": true, "confirmation_token": "token-xyz",
		},
	)

	assert.Equal("archived", resp.Status)
	assert.Equal("batch-1", resp.BatchID)
	assert.Equal(2, resp.Archived)
	assert.Contains(resp.NextStep, "incremental sync")

	require.Len(archiver.executeReqs, 1)
	assert.Equal("token-xyz", archiver.executeReqs[0].ConfirmationToken)
	assert.Equal([]string{"gmail-001", "gmail-002"},
		archiver.executeReqs[0].SourceMessageIDs)
}

func TestArchiveFromInboxReportsRemainingWork(t *testing.T) {
	assert := assert.New(t)

	h := &handlers{
		engine: inboxArchiveEngine(),
		inboxArchiver: &fakeInboxArchiver{
			result: InboxArchiveResult{BatchID: "b", Archived: 1, Remaining: 40, Yielded: true},
		},
	}

	resp := runTool[inboxArchiveExecuteResponse](
		t, ToolArchiveFromInbox, h.archiveFromInbox,
		map[string]any{"query": "from:news", "confirm": true, "confirmation_token": "t"},
	)

	assert.Equal(40, resp.Remaining)
	assert.Contains(resp.NextStep, "Paused")
}

// TestArchiveFromInboxTranslatesDaemonRefusals: each of these is a condition
// the model can act on, so none of them may surface as an internal error.
func TestArchiveFromInboxTranslatesDaemonRefusals(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantSub string
	}{
		{"writes disabled", ErrMailboxWritesDisabled, "mailbox_writes_disabled"},
		{"stale token", ErrInboxArchiveTokenInvalid, "confirmation_token_invalid"},
		{"unsupported provider", ErrInboxArchiveUnsupported, "unsupported_source"},
		{"read-only grant", ErrInboxArchiveScopeRequired, "scope_escalation_required"},
		{"daemon busy", ErrInboxArchiveBusy, "busy"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := &handlers{
				engine:        inboxArchiveEngine(),
				inboxArchiver: &fakeInboxArchiver{executeErr: tc.err, authorizeErr: tc.err},
			}

			executed := runToolExpectError(t, ToolArchiveFromInbox, h.archiveFromInbox,
				map[string]any{"query": "from:news", "confirm": true, "confirmation_token": "t"})
			assert.Contains(t, resultText(t, executed), tc.wantSub)

			// The same condition must also stop the plan, so the user is never
			// asked to confirm something that cannot happen.
			planned := runToolExpectError(t, ToolArchiveFromInbox, h.archiveFromInbox,
				map[string]any{"query": "from:news"})
			assert.Contains(t, resultText(t, planned), tc.wantSub)
		})
	}
}

func TestArchiveFromInboxWithoutSeamIsUnavailable(t *testing.T) {
	h := &handlers{engine: inboxArchiveEngine()}

	result := runToolExpectError(t, ToolArchiveFromInbox, h.archiveFromInbox,
		map[string]any{"query": "from:news"})

	assert.Contains(t, resultText(t, result), "mailbox_writes_unavailable")
}
