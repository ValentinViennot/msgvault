package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"go.kenn.io/msgvault/internal/deletion"
)

// maxArchiveFromInboxResults bounds how many messages one selection may resolve
// to. It is far below stage_deletion's cap because this tool acts immediately:
// a call has to finish inside one MCP request without holding the daemon's
// operation gate long enough to stall everything else. Larger selections are
// archived over several calls, which is safe because a message that has left
// the inbox drops out of the next selection.
const maxArchiveFromInboxResults = 1000

// inboxArchiveSampleSize is how many messages a plan shows by name.
const inboxArchiveSampleSize = 10

// ErrMailboxWritesDisabled reports that the daemon has not opted in to mailbox
// writes. It is deliberately distinct from an authorization failure: nothing is
// wrong with the request, the operator simply has not enabled the capability.
var ErrMailboxWritesDisabled = errors.New("mailbox writes are disabled on this daemon")

// ErrInboxArchiveTokenInvalid reports a confirmation token that does not match
// the messages being confirmed, or that has already been spent.
var ErrInboxArchiveTokenInvalid = errors.New("inbox archive confirmation token is not valid for this selection")

// ErrInboxArchiveUnsupported reports a source whose provider cannot archive.
var ErrInboxArchiveUnsupported = errors.New("source does not support inbox archiving")

// ErrInboxArchiveScopeRequired reports an account added read-only, whose grant
// does not permit changing the mailbox.
var ErrInboxArchiveScopeRequired = errors.New("account's grant does not permit mailbox changes")

// ErrInboxArchiveBusy reports that the daemon is already running a mutating
// operation and declined to queue behind it.
var ErrInboxArchiveBusy = errors.New("daemon is busy with another operation")

// InboxArchiveAuthorizeRequest asks the daemon to authorize archiving an exact
// set of messages.
type InboxArchiveAuthorizeRequest struct {
	Account          string   `json:"account"`
	SourceID         int64    `json:"source_id"`
	Description      string   `json:"description"`
	SourceMessageIDs []string `json:"source_message_ids"`
}

// InboxArchiveExecuteRequest redeems a token minted by AuthorizeInboxArchive.
type InboxArchiveExecuteRequest struct {
	ConfirmationToken string   `json:"confirmation_token"`
	SourceMessageIDs  []string `json:"source_message_ids"`
}

// InboxArchiveResult reports what the daemon did.
type InboxArchiveResult struct {
	BatchID   string   `json:"batch_id"`
	Archived  int      `json:"archived"`
	Failed    int      `json:"failed"`
	Remaining int      `json:"remaining"`
	FailedIDs []string `json:"failed_ids,omitempty"`
	Yielded   bool     `json:"yielded,omitempty"`
}

// InboxArchiver removes messages from a mail account's inbox through the
// selected daemon. The MCP process holds no provider credentials of its own and
// never contacts a mail provider directly; it resolves which messages the user
// meant and asks the daemon to act.
//
// The split into authorize and execute exists so the token that permits an
// archive is minted by the daemon, bound to one exact set of messages, and
// spent once. A plan the model showed the user cannot then be redeemed against
// a different set of messages.
type InboxArchiver interface {
	// AuthorizeInboxArchive mints a one-shot confirmation token for this set of
	// messages, or returns ErrMailboxWritesDisabled when the daemon has not
	// opted in to mailbox writes.
	AuthorizeInboxArchive(ctx context.Context, req InboxArchiveAuthorizeRequest) (string, error)

	// ExecuteInboxArchive archives the messages a token was minted for.
	ExecuteInboxArchive(ctx context.Context, req InboxArchiveExecuteRequest) (InboxArchiveResult, error)
}

type inboxArchiveSample struct {
	From    string `json:"from,omitempty"`
	Subject string `json:"subject,omitempty"`
	SentAt  string `json:"sent_at,omitempty"`
}

type inboxArchivePlanResponse struct {
	Status            string               `json:"status"`
	Account           string               `json:"account"`
	Selection         string               `json:"selection"`
	MessageCount      int                  `json:"message_count"`
	Truncated         bool                 `json:"truncated"`
	Sample            []inboxArchiveSample `json:"sample,omitempty"`
	ConfirmationToken string               `json:"confirmation_token"`
	NextStep          string               `json:"next_step"`
}

type inboxArchiveExecuteResponse struct {
	Status    string   `json:"status"`
	Account   string   `json:"account"`
	BatchID   string   `json:"batch_id"`
	Archived  int      `json:"archived"`
	Failed    int      `json:"failed"`
	Remaining int      `json:"remaining"`
	FailedIDs []string `json:"failed_ids,omitempty"`
	NextStep  string   `json:"next_step"`
}

func inboxArchiveOutputSchema() *jsonschema.Schema {
	plan := outputSchemaFor[inboxArchivePlanResponse]()
	plan.Schema = ""
	executed := outputSchemaFor[inboxArchiveExecuteResponse]()
	executed.Schema = ""
	return &jsonschema.Schema{
		Schema: schema202012,
		Type:   "object",
		OneOf:  []*jsonschema.Schema{plan, executed},
	}
}

func archiveFromInboxDefinition(_ *handlers) toolDefinition {
	return mailboxWriteDefinition(
		ToolArchiveFromInbox,
		"Remove messages from the account's inbox at the mail provider. This CHANGES THE USER'S LIVE MAILBOX. "+
			"It does not delete anything: archived messages keep every other label, stay searchable at the provider, "+
			"and stay in the local archive. "+
			"Call without 'confirm' first: that returns a plan with the message count, a sample, and a "+
			"confirmation_token, and changes nothing. Show the plan to the user, get their explicit agreement, "+
			"then call again with confirm=true and that token. Never pass confirm=true on the first call. "+
			"Use EITHER 'query' (Gmail-style search) OR structured filters, not both; add label:INBOX to the "+
			"selection so the count reflects messages that are actually in the inbox. "+
			"At most 1000 messages per call; call again to continue a larger selection.",
		closedObject(map[string]*jsonschema.Schema{
			toolArgAccount: accountProperty(),
			toolArgQuery: stringSchema(
				"Gmail-style search query (e.g. 'label:INBOX from:newsletter before:2024-01-01'). " +
					"Cannot be combined with structured filters."),
			toolArgFrom:      stringSchema("Filter by sender email address"),
			"domain":         stringSchema("Filter by sender domain (e.g. 'linkedin.com')"),
			"label":          stringSchema("Filter by label (use 'INBOX' to select only messages still in the inbox)"),
			toolArgAfter:     afterProperty(),
			toolArgBefore:    beforeProperty(),
			"has_attachment": booleanSchema("Only messages with attachments"),
			"confirm": booleanSchema(
				"Set true only after the user has seen the plan and agreed to it. Requires confirmation_token."),
			"confirmation_token": stringSchema(
				"The confirmation_token returned by the preceding plan call. Valid for that exact set of messages, once."),
		}),
		inboxArchiveOutputSchema(),
		(*handlers).archiveFromInbox,
	)
}

func (h *handlers) archiveFromInbox(ctx context.Context, req toolRequest) (*toolResult, error) {
	if h.inboxArchiver == nil {
		return toolErrorResult(
			"mailbox_writes_unavailable: this server cannot archive messages at the mail provider"), nil
	}

	args := req.GetArguments()
	confirm, _ := args["confirm"].(bool)
	token, _ := args["confirmation_token"].(string)
	token = strings.TrimSpace(token)

	if confirm && token == "" {
		return toolErrorResult(
			"confirmation_required: call without 'confirm' first, show the returned plan to the user, " +
				"and pass the confirmation_token it returns"), nil
	}

	selection, result, err := h.resolveMutationTargets(
		ctx, args, maxArchiveFromInboxResults, "inbox archive")
	if result != nil || err != nil {
		return result, err
	}
	if len(selection.targets) == 0 {
		return toolErrorResult("no messages match the specified criteria"), nil
	}

	source, sourceErr := deletion.SourceReferenceForTargets(selection.targets)
	switch {
	case errors.Is(sourceErr, deletion.ErrMultipleDeletionSources):
		return toolErrorResult(
			"selected messages span multiple sources; set account or archive each source separately"), nil
	case errors.Is(sourceErr, deletion.ErrIncompleteDeletionSource):
		return toolErrorResult("selected message has incomplete source metadata"), nil
	case sourceErr != nil:
		return toolErrorResult(sourceErr.Error()), nil
	}

	sourceMessageIDs := deletion.SourceMessageIDs(selection.targets)
	truncated := len(sourceMessageIDs) >= maxArchiveFromInboxResults

	if !confirm {
		return h.planInboxArchive(ctx, selection, source, sourceMessageIDs, truncated)
	}

	return h.executeInboxArchive(ctx, source, sourceMessageIDs, token, truncated)
}

func (h *handlers) executeInboxArchive(
	ctx context.Context,
	source deletion.SourceReference,
	sourceMessageIDs []string,
	token string,
	truncated bool,
) (*toolResult, error) {
	archiveResult, err := h.inboxArchiver.ExecuteInboxArchive(ctx, InboxArchiveExecuteRequest{
		ConfirmationToken: token,
		SourceMessageIDs:  sourceMessageIDs,
	})
	if translated := translateInboxArchiveErr(err); translated != nil {
		return translated, nil
	}
	if err != nil {
		return nil, newInternalError("archive messages from inbox", err)
	}

	return jsonResult(inboxArchiveExecuteResponse{
		Status:    "archived",
		Account:   source.Identifier,
		BatchID:   archiveResult.BatchID,
		Archived:  archiveResult.Archived,
		Failed:    archiveResult.Failed,
		Remaining: archiveResult.Remaining,
		FailedIDs: archiveResult.FailedIDs,
		NextStep:  inboxArchiveNextStep(archiveResult, truncated),
	})
}

func (h *handlers) planInboxArchive(
	ctx context.Context,
	selection *mutationSelection,
	source deletion.SourceReference,
	sourceMessageIDs []string,
	truncated bool,
) (*toolResult, error) {
	token, err := h.inboxArchiver.AuthorizeInboxArchive(ctx, InboxArchiveAuthorizeRequest{
		Account:          source.Identifier,
		SourceID:         source.ID,
		Description:      selection.description,
		SourceMessageIDs: sourceMessageIDs,
	})
	if translated := translateInboxArchiveErr(err); translated != nil {
		return translated, nil
	}
	if err != nil {
		return nil, newInternalError("authorize inbox archive", err)
	}

	nextStep := fmt.Sprintf(
		"Show this plan to the user. Only if they explicitly agree, call %s again with the same "+
			"selection, confirm=true and confirmation_token=%q. Nothing has changed yet.",
		ToolArchiveFromInbox, token)
	if truncated {
		nextStep += fmt.Sprintf(
			" This plan covers the first %d matches and the selection may hold more; "+
				"repeat the cycle afterwards until a plan reports no matches.",
			maxArchiveFromInboxResults)
	}

	return jsonResult(inboxArchivePlanResponse{
		Status:            "plan",
		Account:           source.Identifier,
		Selection:         selection.description,
		MessageCount:      len(sourceMessageIDs),
		Truncated:         truncated,
		Sample:            h.inboxArchiveSample(ctx, selection),
		ConfirmationToken: token,
		NextStep:          nextStep,
	})
}

// inboxArchiveSample hydrates a handful of the selected messages so the plan
// names real mail rather than only a count. A sample the user recognises is
// what makes a wrong selection visible before it is confirmed, so a failure to
// build one is not worth failing the plan over.
func (h *handlers) inboxArchiveSample(
	ctx context.Context, selection *mutationSelection,
) []inboxArchiveSample {
	ids := make([]int64, 0, inboxArchiveSampleSize)
	for _, target := range selection.targets {
		if len(ids) == inboxArchiveSampleSize {
			break
		}
		if target.MessageID > 0 {
			ids = append(ids, target.MessageID)
		}
	}
	if len(ids) == 0 {
		return nil
	}

	summaries, err := h.engine.GetMessageSummariesByIDs(ctx, ids)
	if err != nil {
		return nil
	}

	samples := make([]inboxArchiveSample, 0, len(summaries))
	for _, summary := range summaries {
		sample := inboxArchiveSample{
			From:    summary.FromEmail,
			Subject: summary.Subject,
		}
		if !summary.SentAt.IsZero() {
			sample.SentAt = summary.SentAt.Format("2006-01-02")
		}
		samples = append(samples, sample)
	}
	return samples
}

// inboxArchiveNextStep says what, if anything, is left to do. truncated reports
// that the selection itself hit the per-call cap, which the daemon cannot see:
// it only ever received the capped list, so its own Remaining counts messages
// left inside that list, not beyond it.
func inboxArchiveNextStep(result InboxArchiveResult, truncated bool) string {
	switch {
	case result.Remaining > 0 && result.Yielded:
		return fmt.Sprintf(
			"Paused after %d messages to let another request through; %d remain. "+
				"Repeat the plan-then-confirm cycle to continue.",
			result.Archived, result.Remaining)
	case result.Remaining > 0:
		return fmt.Sprintf(
			"%d messages remain in this selection. Repeat the plan-then-confirm cycle to continue.",
			result.Remaining)
	case truncated:
		return fmt.Sprintf(
			"This call archived the first %d matches. The selection may hold more; "+
				"repeat the plan-then-confirm cycle until a plan reports no matches.",
			maxArchiveFromInboxResults)
	case result.Failed > 0:
		return "Some messages could not be archived and kept their inbox label; they are listed in failed_ids."
	default:
		return "The selection is archived. Run an incremental sync to confirm the mailbox and archive agree."
	}
}

// translateInboxArchiveErr maps the seam's known conditions to tool errors the
// model can act on, rather than surfacing them as internal failures.
func translateInboxArchiveErr(err error) *toolResult {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrMailboxWritesDisabled):
		return toolErrorResult(
			"mailbox_writes_disabled: the daemon has not enabled mailbox writes. " +
				"Ask the user to set '[inbox_archive] remote_enabled = true' in the daemon's config.toml " +
				"and restart it. Nothing has been changed.")
	case errors.Is(err, ErrInboxArchiveTokenInvalid):
		return toolErrorResult(
			"confirmation_token_invalid: the token does not match this set of messages, or has already " +
				"been used. Call again without 'confirm' to get a fresh plan, show it to the user, and " +
				"confirm that one. Nothing has been changed.")
	case errors.Is(err, ErrInboxArchiveUnsupported):
		return toolErrorResult(
			"unsupported_source: this account's provider cannot archive messages from the inbox. " +
				"Only Gmail and IMAP accounts support it.")
	case errors.Is(err, ErrInboxArchiveScopeRequired):
		return toolErrorResult(
			"scope_escalation_required: this account was added read-only, so its authorization " +
				"does not permit changing the mailbox. Ask the user to re-authorize it by running " +
				"'msgvault add-account <email>'. Nothing has been changed.")
	case errors.Is(err, ErrInboxArchiveBusy):
		return toolErrorResult(
			"busy: the daemon is running another operation. Nothing has been changed; try again shortly.")
	default:
		return nil
	}
}
