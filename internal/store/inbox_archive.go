package store

import (
	"fmt"
	"strings"
)

// removeLabelChunkSize bounds the IN list of one DELETE. It matches the chunk
// size the batch deletion path uses.
const removeLabelChunkSize = 500

// RemoveLabelBySourceMessageIDs drops one label from every listed message of a
// source, returning how many message/label links it removed.
//
// Archiving at the provider is only half of the operation: until the local row
// loses its INBOX label too, the vault disagrees with the mailbox and an
// inbox-scoped selection keeps offering the same messages. Doing it here, in
// one statement per chunk, keeps that write cheap enough to run after every
// provider batch rather than once at the end -- which is what makes an
// interrupted run self-heal, since the messages already archived drop out of
// the next selection.
//
// Messages that never carried the label, and IDs that belong to another source,
// are silently skipped: the end state is what matters, not who got there first.
func (s *Store) RemoveLabelBySourceMessageIDs(
	sourceID int64,
	labelName string,
	sourceMessageIDs []string,
) (int64, error) {
	if sourceID <= 0 {
		return 0, fmt.Errorf("source id required to remove label %q", labelName)
	}
	if labelName == "" {
		return 0, fmt.Errorf("label name required")
	}
	if len(sourceMessageIDs) == 0 {
		return 0, nil
	}

	var removed int64
	for i := 0; i < len(sourceMessageIDs); i += removeLabelChunkSize {
		end := min(i+removeLabelChunkSize, len(sourceMessageIDs))
		chunk := sourceMessageIDs[i:end]

		placeholders := make([]string, len(chunk))
		args := make([]any, 0, len(chunk)+3)
		args = append(args, sourceID, labelName, sourceID)
		for j, id := range chunk {
			placeholders[j] = "?"
			args = append(args, id)
		}

		result, err := s.db.Exec(fmt.Sprintf(`
			DELETE FROM message_labels
			WHERE label_id IN (
				SELECT id FROM labels WHERE source_id = ? AND name = ?
			)
			AND message_id IN (
				SELECT id FROM messages
				WHERE source_id = ? AND source_message_id IN (%s)
			)
		`, strings.Join(placeholders, ",")), args...)
		if err != nil {
			return removed, fmt.Errorf("remove label %q: %w", labelName, err)
		}
		if affected, err := result.RowsAffected(); err == nil {
			removed += affected
		}
	}

	return removed, nil
}
