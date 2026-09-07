package store

import (
	"errors"
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
		return 0, errors.New("label name required")
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

// SourceMessageIDsMissingRFC822ID reports which of the given messages have no
// RFC822 Message-ID recorded.
//
// This matters only for IMAP. A message's source_message_id there is
// "mailbox|uid", so moving it out of the inbox changes its key, and sync
// rejoins the moved message to its existing row by matching the RFC822
// Message-ID. Without one there is nothing to match on, and the next full sync
// inserts a second row for the same message. Such messages are excluded from an
// archive rather than silently duplicated.
//
// IDs that do not belong to the source are reported as missing: they are not
// safe to archive here either.
func (s *Store) SourceMessageIDsMissingRFC822ID(
	sourceID int64,
	sourceMessageIDs []string,
) ([]string, error) {
	if sourceID <= 0 {
		return nil, errors.New("source id required")
	}
	if len(sourceMessageIDs) == 0 {
		return nil, nil
	}

	usable := make(map[string]bool, len(sourceMessageIDs))
	for i := 0; i < len(sourceMessageIDs); i += removeLabelChunkSize {
		end := min(i+removeLabelChunkSize, len(sourceMessageIDs))
		chunk := sourceMessageIDs[i:end]

		placeholders := make([]string, len(chunk))
		args := make([]any, 0, len(chunk)+1)
		args = append(args, sourceID)
		for j, id := range chunk {
			placeholders[j] = "?"
			args = append(args, id)
		}

		rows, err := s.db.Query(fmt.Sprintf(`
			SELECT source_message_id FROM messages
			WHERE source_id = ?
			  AND source_message_id IN (%s)
			  AND rfc822_message_id IS NOT NULL
			  AND rfc822_message_id != ''
		`, strings.Join(placeholders, ",")), args...)
		if err != nil {
			return nil, fmt.Errorf("check rfc822 message ids: %w", err)
		}
		if err := scanUsableSourceMessageIDs(rows, usable); err != nil {
			return nil, err
		}
	}

	var missing []string
	for _, id := range sourceMessageIDs {
		if !usable[id] {
			missing = append(missing, id)
		}
	}
	return missing, nil
}

func scanUsableSourceMessageIDs(rows rowsScanner, usable map[string]bool) error {
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan rfc822 message id: %w", err)
		}
		usable[id] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate rfc822 message ids: %w", err)
	}
	return nil
}
