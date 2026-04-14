package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"
)

var errDecisionNotFound = errors.New("decision not found")

func decisionByID(db DB, ctx context.Context, id int64) (EventDecision, error) {
	var d EventDecision
	var checkedAt int64
	err := db.conn.QueryRowContext(ctx, `
		SELECT checked_at, event_id, pubkey, decision, reason FROM decisions WHERE id = ?
	`, id).Scan(&checkedAt, &d.EventID, &d.Pubkey, &d.Decision, &d.Reason)
	if errors.Is(err, sql.ErrNoRows) {
		return EventDecision{}, errDecisionNotFound
	}
	if err != nil {
		return EventDecision{}, err
	}
	d.CheckedAt = time.Unix(checkedAt, 0)
	return d, nil
}

func TestDecisionRoundtrip(t *testing.T) {
	db, err := New(Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	want := EventDecision{
		CheckedAt: time.Unix(time.Now().Unix(), 0), // truncate to seconds to match DB precision
		EventID:   "aabbccddeeff",
		Pubkey:    "pubkey123",
		Decision:  DecisionAccept,
		Reason:    "pubkey meets the minimum reputation threshold",
	}

	if err := db.RecordDecision(ctx, want); err != nil {
		t.Fatalf("RecordDecision: %v", err)
	}

	got, err := decisionByID(db, ctx, 1)
	if err != nil {
		t.Fatalf("decisionByID: %v", err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Errorf("decision mismatch:\n got  %+v\n want %+v", got, want)
	}
}
