package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/pippellia-btc/blossom"
)

type AuditType string

const (
	AuditEvent AuditType = "event"
	AuditBlob  AuditType = "blob"
)

func (t AuditType) IsValid() bool {
	return t == AuditEvent || t == AuditBlob
}

// Audit represents an audit decision recorded in the decisions table.
type Audit struct {
	Type      AuditType
	Hash      string
	Pubkey    string
	Decision  Decision
	Reason    string
	CheckedAt time.Time
}

func (a Audit) String() string {
	return fmt.Sprintf("{\n"+
		"  Type: %s,\n"+
		"  Hash: %s,\n"+
		"  Pubkey: %s,\n"+
		"  Decision: %s,\n"+
		"  Reason: %s,\n"+
		"  CheckedAt: %v\n"+
		"}",
		a.Type, a.Hash, a.Pubkey, string(a.Decision), a.Reason, a.CheckedAt)
}

func (a Audit) Validate() error {
	if !a.Type.IsValid() {
		return fmt.Errorf("invalid type: %q", a.Type)
	}
	if err := blossom.ValidateHash(a.Hash); err != nil {
		return fmt.Errorf("invalid hash: %w", err)
	}
	if a.Pubkey == "" || !nostr.IsValidPublicKey(a.Pubkey) {
		return fmt.Errorf("invalid pubkey: %q", a.Pubkey)
	}
	if !a.Decision.IsValid() {
		return fmt.Errorf("invalid decision: %q", a.Decision)
	}
	if a.Reason == "" {
		return errors.New("reason cannot be empty")
	}
	if a.CheckedAt.IsZero() {
		return fmt.Errorf("missing checked_at")
	}
	return nil
}

func (a Audit) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"type":       a.Type,
		"hash":       a.Hash,
		"pubkey":     a.Pubkey,
		"decision":   string(a.Decision),
		"reason":     a.Reason,
		"checked_at": a.CheckedAt.Unix(), // unix timestamp for simplicity
	})
}

func (a *Audit) UnmarshalJSON(data []byte) error {
	var raw struct {
		Type      string `json:"type"`
		Hash      string `json:"hash"`
		Pubkey    string `json:"pubkey"`
		Decision  string `json:"decision"`
		Reason    string `json:"reason"`
		CheckedAt int64  `json:"checked_at"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	a.Type = AuditType(raw.Type)
	a.Hash = raw.Hash
	a.Pubkey = raw.Pubkey
	a.Decision = Decision(raw.Decision)
	a.Reason = raw.Reason
	a.CheckedAt = time.Unix(raw.CheckedAt, 0).UTC()
	return nil
}
