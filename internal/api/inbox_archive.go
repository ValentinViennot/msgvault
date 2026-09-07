package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// inboxArchiveTokenTTL bounds how long a confirmation token stays redeemable.
// It is short because a token exists to carry one plan across the gap between
// showing it to a user and their answer, not to be stored.
const inboxArchiveTokenTTL = 15 * time.Minute

// maxInboxArchiveMessages caps one archive call. It matches the MCP tool's own
// cap; the daemon enforces it again because the endpoint is reachable by any
// API client, not only the MCP server.
const maxInboxArchiveMessages = 1000

const (
	inboxArchiveAuthorizePath = "/api/v1/inbox-archive/authorize"
	inboxArchiveExecutePath   = "/api/v1/inbox-archive/execute"
)

// InboxArchiveRunRequest names the messages to remove from one source's inbox.
type InboxArchiveRunRequest struct {
	SourceID         int64
	Account          string
	SourceMessageIDs []string
}

// InboxArchiveRunResult reports what the provider call achieved.
type InboxArchiveRunResult struct {
	Archived  int
	Failed    int
	Remaining int
	FailedIDs []string
	Yielded   bool
}

// ErrInboxArchiveUnsupportedSource reports a source whose provider cannot
// archive messages out of the inbox.
var ErrInboxArchiveUnsupportedSource = errors.New("source does not support inbox archiving")

// ErrInboxArchiveScopeRequired reports an account whose OAuth grant was
// narrowed to read-only. Archiving needs the same modify scope as trashing, so
// it is refused here rather than surfaced as a provider rejection mid-batch.
var ErrInboxArchiveScopeRequired = errors.New("account's grant does not permit mailbox changes")

// InboxArchiveRunner archives messages at the mail provider.
//
// The implementation lives with the daemon's other provider work rather than
// here, because building an authenticated Gmail or IMAP client needs the OAuth
// managers and config that internal/api deliberately does not import.
type InboxArchiveRunner interface {
	// RunInboxArchive removes the named messages from the source's inbox and
	// drops their local INBOX label.
	RunInboxArchive(ctx context.Context, req InboxArchiveRunRequest) (InboxArchiveRunResult, error)
}

// InboxArchiveAuthorizeRequest asks for a confirmation token covering an exact
// set of messages.
type InboxArchiveAuthorizeRequest struct {
	Account          string   `json:"account"`
	SourceID         int64    `json:"source_id"`
	Description      string   `json:"description,omitempty"`
	SourceMessageIDs []string `json:"source_message_ids"`
}

// InboxArchiveAuthorizeResponse carries the minted token.
type InboxArchiveAuthorizeResponse struct {
	ConfirmationToken string    `json:"confirmation_token"`
	MessageCount      int       `json:"message_count"`
	ExpiresAt         time.Time `json:"expires_at"`
}

// InboxArchiveExecuteRequest redeems a confirmation token.
type InboxArchiveExecuteRequest struct {
	ConfirmationToken string   `json:"confirmation_token"`
	SourceMessageIDs  []string `json:"source_message_ids"`
}

// InboxArchiveExecuteResponse reports the outcome.
type InboxArchiveExecuteResponse struct {
	BatchID   string   `json:"batch_id"`
	Account   string   `json:"account"`
	Archived  int      `json:"archived"`
	Failed    int      `json:"failed"`
	Remaining int      `json:"remaining"`
	FailedIDs []string `json:"failed_ids,omitempty"`
	Yielded   bool     `json:"yielded,omitempty"`
}

// inboxArchiveGrant is the sealed token payload.
type inboxArchiveGrant struct {
	SourceID      int64  `json:"source_id"`
	Account       string `json:"account"`
	SelectionHash string `json:"selection_hash"`
	MessageCount  int    `json:"message_count"`
	IssuedAt      int64  `json:"issued_at"`
	ExpiresAt     int64  `json:"expires_at"`
	Nonce         string `json:"nonce"`
}

// spentInboxArchiveTokens remembers redeemed tokens for as long as an unspent
// one could still be valid, so a plan cannot be confirmed twice.
type spentInboxArchiveTokens struct {
	mu    sync.Mutex
	spent map[string]time.Time
}

func (s *spentInboxArchiveTokens) claim(token string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.spent == nil {
		s.spent = make(map[string]time.Time)
	}
	for candidate, expiry := range s.spent {
		if now.After(expiry) {
			delete(s.spent, candidate)
		}
	}
	if _, used := s.spent[token]; used {
		return false
	}
	s.spent[token] = now.Add(inboxArchiveTokenTTL)
	return true
}

// inboxArchiveSelectionHash binds a token to one exact set of messages. The
// order callers happen to send them in is not part of the selection, so the
// digest is taken over sorted, length-delimited ids.
func inboxArchiveSelectionHash(sourceID int64, sourceMessageIDs []string) string {
	sorted := append([]string(nil), sourceMessageIDs...)
	sort.Strings(sorted)

	// hash.Hash.Write never returns an error, which is why the results are
	// discarded rather than threaded through this function's signature.
	digest := sha256.New()
	_, _ = fmt.Fprintf(digest, "%d\n", sourceID)
	for _, id := range sorted {
		_, _ = fmt.Fprintf(digest, "%d:%s\n", len(id), id)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// newInboxArchiveNonce makes each token distinct even when two plans cover the
// same messages, so spending one does not invalidate the other.
func newInboxArchiveNonce() (string, error) {
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func (s *Server) handleInboxArchiveAuthorize(w http.ResponseWriter, r *http.Request) {
	_, codec, archiveUID, ok := s.inboxArchiveContext(w, r)
	if !ok {
		return
	}

	var req InboxArchiveAuthorizeRequest
	if !decodeInboxArchiveRequest(w, r, &req) {
		return
	}
	if !validateInboxArchiveSelection(w, req.SourceID, req.SourceMessageIDs) {
		return
	}
	if !s.inboxArchiveEnabled() {
		writeInboxArchiveDisabled(w)
		return
	}

	now := time.Now().UTC()
	expiry := now.Add(inboxArchiveTokenTTL)
	nonce, err := newInboxArchiveNonce()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_error", "could not mint a confirmation token")
		return
	}

	token, err := codec.seal(r.Context(), archiveUID, inboxArchiveGrant{
		SourceID:      req.SourceID,
		Account:       req.Account,
		SelectionHash: inboxArchiveSelectionHash(req.SourceID, req.SourceMessageIDs),
		MessageCount:  len(req.SourceMessageIDs),
		IssuedAt:      now.Unix(),
		ExpiresAt:     expiry.Unix(),
		Nonce:         nonce,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token_error", "could not mint a confirmation token")
		return
	}

	writeJSON(w, http.StatusOK, InboxArchiveAuthorizeResponse{
		ConfirmationToken: token,
		MessageCount:      len(req.SourceMessageIDs),
		ExpiresAt:         expiry,
	})
}

func (s *Server) handleInboxArchiveExecute(w http.ResponseWriter, r *http.Request) {
	runner, codec, archiveUID, ok := s.inboxArchiveContext(w, r)
	if !ok {
		return
	}

	var req InboxArchiveExecuteRequest
	if !decodeInboxArchiveRequest(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.ConfirmationToken) == "" {
		writeError(w, http.StatusPreconditionRequired, "confirmation_required",
			"a confirmation_token from the authorize step is required")
		return
	}
	if !s.inboxArchiveEnabled() {
		writeInboxArchiveDisabled(w)
		return
	}

	sealed, err := codec.open(r.Context(), archiveUID, req.ConfirmationToken)
	if err != nil {
		writeInboxArchiveTokenInvalid(w, "the confirmation token could not be verified")
		return
	}
	var grant inboxArchiveGrant
	if err := json.Unmarshal(sealed, &grant); err != nil {
		writeInboxArchiveTokenInvalid(w, "the confirmation token could not be read")
		return
	}

	now := time.Now().UTC()
	if now.Unix() > grant.ExpiresAt {
		writeInboxArchiveTokenInvalid(w, "the confirmation token has expired")
		return
	}
	if !validateInboxArchiveSelection(w, grant.SourceID, req.SourceMessageIDs) {
		return
	}
	if inboxArchiveSelectionHash(grant.SourceID, req.SourceMessageIDs) != grant.SelectionHash {
		writeInboxArchiveTokenInvalid(w,
			"the confirmation token was issued for a different set of messages")
		return
	}
	if !s.spentInboxArchiveTokens.claim(req.ConfirmationToken, now) {
		writeInboxArchiveTokenInvalid(w, "the confirmation token has already been used")
		return
	}

	// The operation gate is already held for this request by
	// operationGateMiddleware, which gates every mutating POST. Taking it again
	// here would deadlock against ourselves; what the archiver does instead is
	// consult HasRequestWaiters between chunks and stop early, so a long run
	// hands the gate back rather than starving the daemon.
	result, err := runner.RunInboxArchive(r.Context(), InboxArchiveRunRequest{
		SourceID:         grant.SourceID,
		Account:          grant.Account,
		SourceMessageIDs: req.SourceMessageIDs,
	})
	switch {
	case errors.Is(err, ErrInboxArchiveUnsupportedSource):
		writeError(w, http.StatusUnprocessableEntity, "unsupported_source",
			"this account's provider cannot archive messages from the inbox")
		return
	case errors.Is(err, ErrInboxArchiveScopeRequired):
		writeError(w, http.StatusForbidden, "scope_escalation_required",
			"this account was added read-only; re-authorize it with "+
				"'msgvault add-account <email>' to permit mailbox changes")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "archive_failed", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, InboxArchiveExecuteResponse{
		BatchID:   inboxArchiveBatchID(grant),
		Account:   grant.Account,
		Archived:  result.Archived,
		Failed:    result.Failed,
		Remaining: result.Remaining,
		FailedIDs: result.FailedIDs,
		Yielded:   result.Yielded,
	})
}

// inboxArchiveBatchID names the run in a way the caller can quote back to the
// user without exposing the sealed token.
func inboxArchiveBatchID(grant inboxArchiveGrant) string {
	return fmt.Sprintf("inbox-archive-%d-%s",
		grant.IssuedAt, grant.SelectionHash[:12])
}

func (s *Server) inboxArchiveContext(
	w http.ResponseWriter, r *http.Request,
) (InboxArchiveRunner, operationTokenCodec, string, bool) {
	runner, ok := s.inboxArchiveRunner()
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "mailbox_writes_unavailable",
			"this daemon cannot archive messages at the mail provider")
		return nil, operationTokenCodec{}, "", false
	}
	keyring, ok := s.store.(operationTokenKeyring)
	if !ok {
		writeError(w, http.StatusServiceUnavailable, "token_unavailable",
			"confirmation tokens are unavailable on this archive")
		return nil, operationTokenCodec{}, "", false
	}
	archiveUID, ok := s.operationHistoryArchiveUID(w, r)
	if !ok {
		return nil, operationTokenCodec{}, "", false
	}
	return runner, newOperationTokenCodec(keyring), archiveUID, true
}

// inboxArchiveEnabled reports the daemon's own opt-in. It is deliberately
// separate from the MCP server's --allow-mailbox-writes: that decides whether a
// model may ask, this decides whether the daemon will act, and the endpoint is
// reachable by every API client, not only the MCP server.
func (s *Server) inboxArchiveEnabled() bool {
	return s.cfg != nil && s.cfg.InboxArchive.RemoteEnabled
}

// decodeInboxArchiveRequest rejects unknown fields: a typo in a field name
// would otherwise be silently dropped, and this request names messages that are
// about to be moved.
func decodeInboxArchiveRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("invalid JSON request body: %v", err))
		return false
	}
	return requireSingleJSONValue(w, dec, "invalid_request")
}

func (s *Server) inboxArchiveRunner() (InboxArchiveRunner, bool) {
	if s.inboxArchive != nil {
		return s.inboxArchive, true
	}
	runner, ok := s.store.(InboxArchiveRunner)
	return runner, ok
}

func validateInboxArchiveSelection(w http.ResponseWriter, sourceID int64, ids []string) bool {
	if sourceID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"source_id is required; archiving is scoped to one account")
		return false
	}
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"source_message_ids must name at least one message")
		return false
	}
	if len(ids) > maxInboxArchiveMessages {
		writeError(w, http.StatusUnprocessableEntity, "selection_too_large",
			fmt.Sprintf("at most %d messages may be archived per call, got %d",
				maxInboxArchiveMessages, len(ids)))
		return false
	}
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			writeError(w, http.StatusBadRequest, "invalid_request",
				"source_message_ids must not contain empty values")
			return false
		}
	}
	return true
}

func writeInboxArchiveDisabled(w http.ResponseWriter) {
	writeError(w, http.StatusForbidden, "mailbox_writes_disabled",
		"mailbox writes are disabled; set '[inbox_archive] remote_enabled = true' "+
			"in the daemon's config.toml and restart it")
}

func writeInboxArchiveTokenInvalid(w http.ResponseWriter, detail string) {
	writeError(w, http.StatusPreconditionFailed, "confirmation_token_invalid", detail)
}
