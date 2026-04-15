// Package models defines the core domain types shared across the server, client, and storage layers.
package models

import (
	"encoding/json"
	"time"
)

// CheckDecision represents the decision made for an event in the check endpoint.
type CheckDecision string

const (
	DecisionAccept CheckDecision = "accept"
	DecisionReject CheckDecision = "reject"
)

// CheckResponse represents the response to a /v1/events/check request.
type CheckResponse struct {
	Decision CheckDecision `json:"decision"`
	Reason   string        `json:"reason"`
}

// PubkeyStatus represents the status of a pubkey, either "allowed" or "blocked".
type PubkeyStatus string

const (
	StatusAllowed PubkeyStatus = "allowed"
	StatusBlocked PubkeyStatus = "blocked"
)

type PubkeyPolicy struct {
	Pubkey    string       `json:"pubkey"`
	Status    PubkeyStatus `json:"status"`
	Reason    string       `json:"reason"`
	AddedBy   string       `json:"added_by"`
	CreatedAt time.Time    `json:"created_at"`
}

func (p PubkeyPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"pubkey":     p.Pubkey,
		"status":     p.Status,
		"reason":     p.Reason,
		"added_by":   p.AddedBy,
		"created_at": p.CreatedAt.Unix(), // unix timestamp for simplicity
	})
}

func (p *PubkeyPolicy) UnmarshalJSON(data []byte) error {
	var raw struct {
		Pubkey    string       `json:"pubkey"`
		Status    PubkeyStatus `json:"status"`
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
