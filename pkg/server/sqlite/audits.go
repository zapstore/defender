package sqlite

import (
	"context"
	"fmt"
	"time"

	"github.com/zapstore/defender/pkg/models"
)

type AuditType string

const (
	AuditEvent AuditType = "event"
	AuditBlob  AuditType = "blob"
)

// Audit represents an audit decision recorded in the decisions table.
type Audit struct {
	Type      AuditType
	Hash      string
	Pubkey    string
	Decision  models.Decision
	Reason    string
	CheckedAt time.Time
}

// Record inserts an audit record into the decisions table.
func (db DB) Record(ctx context.Context, a Audit) error {
	_, err := db.conn.ExecContext(ctx, `
		INSERT INTO audits (type, hash, pubkey, decision, reason, checked_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`,
		a.Type,
		a.Hash,
		a.Pubkey,
		a.Decision,
		a.Reason,
		a.CheckedAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("failed to record decision: %w", err)
	}
	return nil
}
