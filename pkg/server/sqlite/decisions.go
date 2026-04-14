package sqlite

import (
	"context"
	"fmt"
	"time"
)

type Decision string

const (
	DecisionAccept Decision = "accept"
	DecisionReject Decision = "reject"
)

type EventDecision struct {
	CheckedAt time.Time
	EventID   string
	Pubkey    string
	Decision  Decision
	Reason    string
}

// RecordDecision inserts an audit record into the decisions table.
func (db DB) RecordDecision(ctx context.Context, d EventDecision) error {
	_, err := db.conn.ExecContext(ctx, `
		INSERT INTO decisions (checked_at, event_id, pubkey, decision, reason)
		VALUES (?, ?, ?, ?, ?)
	`,
		d.CheckedAt.Unix(),
		d.EventID,
		d.Pubkey,
		d.Decision,
		d.Reason,
	)
	if err != nil {
		return fmt.Errorf("failed to record decision: %w", err)
	}
	return nil
}
