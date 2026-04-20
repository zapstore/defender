package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/zapstore/defender/pkg/models"
)

var errAuditNotFound = errors.New("audit not found")

func auditByID(db DB, ctx context.Context, id int64) (Audit, error) {
	var a Audit
	var checkedAt int64
	err := db.conn.QueryRowContext(ctx, `
		SELECT type, hash, pubkey, decision, reason, checked_at FROM audits WHERE id = ?
	`, id).Scan(&a.Type, &a.Hash, &a.Pubkey, &a.Decision, &a.Reason, &checkedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Audit{}, errAuditNotFound
	}
	if err != nil {
		return Audit{}, err
	}
	a.CheckedAt = time.Unix(checkedAt, 0)
	return a, nil
}

func TestAuditRoundtrip(t *testing.T) {
	db, err := New(Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	want := Audit{
		Type:      AuditEvent,
		Hash:      "aabbccddeeff",
		Pubkey:    "pubkey123",
		Decision:  models.DecisionAccept,
		Reason:    "pubkey meets the minimum reputation threshold",
		CheckedAt: time.Unix(time.Now().Unix(), 0), // truncate to seconds to match DB precision
	}

	if err := db.Record(ctx, want); err != nil {
		t.Fatalf("Record: %v", err)
	}

	got, err := auditByID(db, ctx, 1)
	if err != nil {
		t.Fatalf("decisionByID: %v", err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Errorf("decision mismatch:\n got  %+v\n want %+v", got, want)
	}
}
