package sqlite

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/zapstore/defender/pkg/models"
)

var errAuditNotFound = errors.New("audit not found")

func TestAuditRoundtrip(t *testing.T) {
	db, err := New(Config{Path: ":memory:"})
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	defer db.Close()

	want := models.Audit{
		Type:      models.AuditEvent,
		Hash:      "aabbccddeeff",
		Pubkey:    "pubkey123",
		Decision:  models.DecisionAccept,
		Reason:    "pubkey meets the minimum reputation threshold",
		CheckedAt: time.Unix(time.Now().Unix(), 0).UTC(), // truncate to seconds to match DB precision
	}

	if err := db.Record(ctx, want); err != nil {
		t.Fatalf("Record: %v", err)
	}

	got, err := db.Audits(ctx, 1)
	if err != nil {
		t.Fatalf("Audits: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 audit, got %d", len(got))
	}
	if !reflect.DeepEqual(want, got[0]) {
		t.Errorf("decision mismatch:\n got  %+v\n want %+v", got, want)
	}
}
