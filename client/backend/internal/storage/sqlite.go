package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

type Event struct {
	EventID      string
	EventKind    string
	EventDataset string
	Timestamp    time.Time
	DocJSON      []byte
}

type Want struct {
	EventKinds []string
	Datasets   []string
}

func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("sqlite path is empty")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	st := &Store{db: db}
	if err := st.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return st, nil
}

func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE,
  event_kind TEXT NOT NULL,
  event_dataset TEXT NOT NULL,
  ts TEXT NOT NULL,
  doc_json BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(event_kind);
CREATE INDEX IF NOT EXISTS idx_events_dataset ON events(event_dataset);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
`)
	return err
}

func (s *Store) InsertEvent(ctx context.Context, e Event) error {
	if strings.TrimSpace(e.EventID) == "" {
		return errors.New("event_id is empty")
	}
	if strings.TrimSpace(e.EventKind) == "" {
		return errors.New("event_kind is empty")
	}
	if strings.TrimSpace(e.EventDataset) == "" {
		return errors.New("event_dataset is empty")
	}
	if len(e.DocJSON) == 0 {
		return errors.New("doc_json is empty")
	}
	if !json.Valid(e.DocJSON) {
		return errors.New("doc_json is not valid json")
	}
	if e.Timestamp.IsZero() {
		return errors.New("timestamp is zero")
	}

	_, err := s.db.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO events(event_id, event_kind, event_dataset, ts, doc_json) VALUES (?, ?, ?, ?, ?)`,
		e.EventID,
		e.EventKind,
		e.EventDataset,
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.DocJSON,
	)
	return err
}

type PullResult struct {
	Items      []json.RawMessage
	NextCursor string
	HasMore    bool
}

func (s *Store) Pull(ctx context.Context, cursor string, limit int, want Want) (PullResult, error) {
	cursorID, err := strconv.ParseInt(cursor, 10, 64)
	if err != nil {
		return PullResult{}, fmt.Errorf("invalid cursor %q: %w", cursor, err)
	}
	if limit <= 0 {
		return PullResult{}, errors.New("limit must be > 0")
	}

	// Only apply kind filtering in SQL; dataset wildcard filtering is done in-process.
	var kinds []string
	for _, k := range want.EventKinds {
		k = strings.TrimSpace(k)
		if k != "" {
			kinds = append(kinds, k)
		}
	}

	baseSQL := `SELECT id, event_kind, event_dataset, doc_json FROM events WHERE id > ?`
	args := []any{cursorID}
	if len(kinds) > 0 {
		placeholders := strings.Repeat("?,", len(kinds))
		placeholders = strings.TrimSuffix(placeholders, ",")
		baseSQL += " AND event_kind IN (" + placeholders + ")"
		for _, k := range kinds {
			args = append(args, k)
		}
	}
	baseSQL += " ORDER BY id ASC LIMIT ?"
	args = append(args, limit+1)

	rows, err := s.db.QueryContext(ctx, baseSQL, args...)
	if err != nil {
		return PullResult{}, err
	}
	defer rows.Close()

	type row struct {
		ID      int64
		Kind    string
		Dataset string
		Doc     []byte
	}

	var collected []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.ID, &r.Kind, &r.Dataset, &r.Doc); err != nil {
			return PullResult{}, err
		}
		collected = append(collected, r)
	}
	if err := rows.Err(); err != nil {
		return PullResult{}, err
	}

	dsPatterns := normalizePatterns(want.Datasets)
	matchDataset := func(ds string) bool {
		if len(dsPatterns) == 0 {
			return true
		}
		for _, p := range dsPatterns {
			if wildcardMatch(p, ds) {
				return true
			}
		}
		return false
	}

	var items []json.RawMessage
	var lastScannedID int64 = cursorID
	for _, r := range collected {
		lastScannedID = r.ID
		if !matchDataset(r.Dataset) {
			continue
		}
		items = append(items, json.RawMessage(r.Doc))
		if len(items) >= limit {
			break
		}
	}

	hasMore := false
	if len(collected) > limit {
		hasMore = true
	}

	return PullResult{
		Items: items,
		// Cursor is a position in the underlying SQLite stream (id autoincrement),
		// not "last returned item". Even when `want.datasets` filters out items, we
		// must advance the cursor to avoid the center being stuck on non-matching rows.
		NextCursor: strconv.FormatInt(lastScannedID, 10),
		HasMore:    hasMore,
	}, nil
}

func normalizePatterns(patterns []string) []string {
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func wildcardMatch(pattern, s string) bool {
	// v1 only needs `*` wildcard (e.g. hostlog.* / netflow.*).
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") && strings.Count(pattern, "*") == 1 {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(s, prefix)
	}

	// Fallback to a very small matcher: split by '*' and check order.
	parts := strings.Split(pattern, "*")
	idx := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		pos := strings.Index(s[idx:], part)
		if pos < 0 {
			return false
		}
		if i == 0 && !strings.HasPrefix(pattern, "*") && pos != 0 {
			return false
		}
		idx += pos + len(part)
	}
	if !strings.HasSuffix(pattern, "*") && parts[len(parts)-1] != "" && !strings.HasSuffix(s, parts[len(parts)-1]) {
		return false
	}
	return true
}
