// Package inboxarchive removes messages from a mail account's inbox without
// deleting them, and keeps the local archive in step with the result.
//
// Archiving is deliberately kept apart from internal/deletion. The two look
// similar -- both walk a list of source message IDs and call the provider --
// but they differ in the one way that matters: archiving is reversible and
// deletion is not. Sharing a manifest type, a status directory or an executor
// between them would create routes by which an archive request could be
// executed as a delete. Nothing here carries a method discriminant, so there is
// no value this package could hold that means "delete".
package inboxarchive

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"go.kenn.io/msgvault/internal/gmail"
	"go.kenn.io/msgvault/internal/store"
)

// DefaultChunkSize is how many messages are handed to the provider at once.
// Gmail's batchModify accepts 1000 per call; providers that archive one message
// at a time should be given a smaller chunk so a run yields more often.
const DefaultChunkSize = 1000

// ErrNotSupported is returned when the source's client cannot archive.
var ErrNotSupported = errors.New("source does not support inbox archiving")

// Result reports what one Archive call did. It is returned even when the call
// fails part-way, because the messages already archived stay archived and the
// caller needs to say so.
type Result struct {
	Requested   int      `json:"requested"`
	Archived    int      `json:"archived"`
	Failed      int      `json:"failed"`
	Remaining   int      `json:"remaining"`
	ArchivedIDs []string `json:"archived_ids,omitempty"`
	FailedIDs   []string `json:"failed_ids,omitempty"`
	Yielded     bool     `json:"yielded,omitempty"`
}

// Archiver removes messages from one source's inbox.
type Archiver struct {
	client      gmail.InboxArchiver
	store       *store.Store
	logger      *slog.Logger
	chunkSize   int
	shouldYield func() bool
}

// New returns an Archiver over a provider client that supports archiving.
// Callers holding a plain gmail.API should use For, which performs the
// capability assertion.
func New(client gmail.InboxArchiver, st *store.Store) *Archiver {
	return &Archiver{
		client:    client,
		store:     st,
		logger:    slog.Default(),
		chunkSize: DefaultChunkSize,
	}
}

// For adapts a provider client to an Archiver, reporting ErrNotSupported when
// the client cannot archive. Most sources -- Slack, Teams, imported archives --
// land here.
func For(client any, st *store.Store) (*Archiver, error) {
	archiver, ok := client.(gmail.InboxArchiver)
	if !ok {
		return nil, ErrNotSupported
	}
	return New(archiver, st), nil
}

// WithLogger sets the logger.
func (a *Archiver) WithLogger(logger *slog.Logger) *Archiver {
	if logger != nil {
		a.logger = logger
	}
	return a
}

// WithChunkSize overrides how many messages go to the provider per call.
func (a *Archiver) WithChunkSize(size int) *Archiver {
	if size > 0 {
		a.chunkSize = size
	}
	return a
}

// WithYieldCheck installs a predicate consulted between chunks. When it reports
// true the run stops early and returns what it managed, with Yielded set. The
// daemon uses this to step aside for a waiting request rather than holding the
// serial operation gate for a long run; nothing is lost, because re-running the
// same selection picks up where this one stopped.
func (a *Archiver) WithYieldCheck(fn func() bool) *Archiver {
	a.shouldYield = fn
	return a
}

// Archive removes the listed messages from the source's inbox, dropping the
// local INBOX label for each chunk as it succeeds.
//
// The per-chunk local write is what makes an interrupted run safe to repeat:
// messages already archived have lost the label locally, so an inbox-scoped
// selection no longer offers them, and the next run continues with the rest.
// Re-archiving a message that is already out of the inbox is accepted by every
// provider here, so an overlapping repeat is harmless either way.
func (a *Archiver) Archive(
	ctx context.Context,
	source *store.Source,
	sourceMessageIDs []string,
) (Result, error) {
	result := Result{Requested: len(sourceMessageIDs)}
	if source == nil {
		return result, errors.New("archive requires a source")
	}
	if len(sourceMessageIDs) == 0 {
		return result, nil
	}

	for start := 0; start < len(sourceMessageIDs); start += a.chunkSize {
		if err := ctx.Err(); err != nil {
			result.Remaining = len(sourceMessageIDs) - start
			return result, err
		}
		if start > 0 && a.shouldYield != nil && a.shouldYield() {
			result.Remaining = len(sourceMessageIDs) - start
			result.Yielded = true
			a.logger.Info("inbox archive yielded to a waiting request",
				"source", source.Identifier,
				"archived", result.Archived,
				"remaining", result.Remaining)
			return result, nil
		}

		end := min(start+a.chunkSize, len(sourceMessageIDs))
		chunk := sourceMessageIDs[start:end]

		failures, err := a.client.ArchiveFromInbox(ctx, chunk)
		if err != nil {
			result.Remaining = len(sourceMessageIDs) - start
			return result, fmt.Errorf("archive %d messages from inbox: %w", len(chunk), err)
		}

		archived := chunk
		if len(failures) > 0 {
			archived = archived[:0:0]
			for _, id := range chunk {
				if failErr, failed := failures[id]; failed {
					result.FailedIDs = append(result.FailedIDs, id)
					a.logger.Warn("message could not be archived",
						"source_message_id", id, "error", failErr)
					continue
				}
				archived = append(archived, id)
			}
		}

		if err := a.converge(source.ID, archived); err != nil {
			result.Remaining = len(sourceMessageIDs) - end
			return result, err
		}

		result.Archived += len(archived)
		result.Failed += len(chunk) - len(archived)
		result.ArchivedIDs = append(result.ArchivedIDs, archived...)
	}

	return result, nil
}

// converge drops the local INBOX label so the vault agrees with the mailbox
// immediately, rather than waiting for the next sync to notice.
//
// For Gmail the next incremental sync sees the same change as a history
// LabelsRemoved record and converges to this exact state, so the two paths
// agree. For IMAP the message has moved mailbox and the next full sync re-keys
// it by RFC822 Message-ID; deliberately nothing here rewrites
// source_message_id, because that key is a compare-and-swap owned by sync.
func (a *Archiver) converge(sourceID int64, archivedIDs []string) error {
	if len(archivedIDs) == 0 {
		return nil
	}
	if _, err := a.store.RemoveLabelBySourceMessageIDs(
		sourceID, gmail.LabelInbox, archivedIDs); err != nil {
		return fmt.Errorf("drop local %s label: %w", gmail.LabelInbox, err)
	}
	return nil
}
