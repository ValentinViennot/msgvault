package api

import (
	"net/http"

	"go.kenn.io/msgvault/internal/query"
)

// handleListMessagesScoped serves GET /messages for a caller who sees only
// some sources. The unfiltered store path cannot express that, so the
// (scoped) engine lists the page and counts the visible total.
func (s *Server) handleListMessagesScoped(w http.ResponseWriter, r *http.Request, page, pageSize, offset int) {
	engine := s.queryEngineForContext(r.Context())
	if engine == nil {
		writeError(w, http.StatusServiceUnavailable, "scope_unavailable", "Scoped access needs the analytics engine")
		return
	}
	rows, err := engine.ListMessages(r.Context(), query.MessageFilter{
		Pagination: query.Pagination{Limit: pageSize, Offset: offset},
	})
	if err != nil {
		if s.writeIfContextError(w, err) {
			return
		}
		s.logger.Error("failed to list scoped messages", "error", err)
		writeError(w, http.StatusInternalServerError, "internal_error", "Failed to retrieve messages")
		return
	}
	var total int64
	if stats, err := engine.GetTotalStats(r.Context(), query.StatsOptions{}); err == nil && stats != nil {
		total = stats.MessageCount
	}
	messages := make([]MessageSummary, 0, len(rows))
	for _, row := range rows {
		messages = append(messages, toMessageSummaryFromQuery(row))
	}
	writeJSON(w, http.StatusOK, MessageListResponse{
		Messages: messages,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	})
}
