// Package models defines the core domain types shared across the server, client, and storage layers.
package models

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// Decision represents the decision made for an event in the check endpoint.
type Decision string

const (
	DecisionAccept Decision = "accept"
	DecisionReject Decision = "reject"
)

// CheckResponse represents the response to a /v1/events/check request.
type CheckResponse struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
}

// PolicyStatus represents the status of a policy, either "allowed" or "blocked".
type PolicyStatus string

const (
	StatusAllowed PolicyStatus = "allowed"
	StatusBlocked PolicyStatus = "blocked"
)

// Policy represents a pubkey policy, either allowed or blocked, with other metadata.
type Policy struct {
	Pubkey    string       `json:"pubkey"`
	Status    PolicyStatus `json:"status"`
	Reason    string       `json:"reason"`
	AddedBy   string       `json:"added_by"`
	CreatedAt time.Time    `json:"created_at"`
}

func (p Policy) Validate() error {
	if p.Pubkey == "" {
		return fmt.Errorf("missing pubkey")
	}
	if !nostr.IsValidPublicKey(p.Pubkey) {
		return fmt.Errorf("invalid pubkey")
	}
	if p.Status != StatusAllowed && p.Status != StatusBlocked {
		return fmt.Errorf("invalid status")
	}
	if p.AddedBy == "" {
		return fmt.Errorf("missing added_by")
	}
	if p.CreatedAt.IsZero() {
		return fmt.Errorf("missing created_at")
	}
	return nil
}

func (p Policy) String() string {
	return fmt.Sprintf("{\n"+
		"  Pubkey: %s,\n"+
		"  Status: %s,\n"+
		"  Reason: %s,\n"+
		"  AddedBy: %s,\n"+
		"  CreatedAt: %s\n"+
		"}",
		p.Pubkey, p.Status, p.Reason, p.AddedBy, p.CreatedAt)
}

func (p Policy) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"pubkey":     p.Pubkey,
		"status":     p.Status,
		"reason":     p.Reason,
		"added_by":   p.AddedBy,
		"created_at": p.CreatedAt.Unix(), // unix timestamp for simplicity
	})
}

func (p *Policy) UnmarshalJSON(data []byte) error {
	var raw struct {
		Pubkey    string       `json:"pubkey"`
		Status    PolicyStatus `json:"status"`
		Reason    string       `json:"reason"`
		AddedBy   string       `json:"added_by"`
		CreatedAt int64        `json:"created_at"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.Pubkey = raw.Pubkey
	p.Status = raw.Status
	p.Reason = raw.Reason
	p.AddedBy = raw.AddedBy
	p.CreatedAt = time.Unix(raw.CreatedAt, 0).UTC()
	return nil
}

const (
	KindProfile           = 0
	KindDeletion          = 5
	KindForumPost         = 11
	KindComment           = 1111
	KindZap               = 9735
	KindCommunityCreation = 10222
	KindIdentityProof     = 30509

	KindApp     = 32267
	KindRelease = 30063
	KindAsset   = 3063
)
