// Package models defines the core domain types shared across the server, client, and storage layers.
package models

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

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

// Decision represents the decision made for an event in the check endpoint.
type Decision string

const (
	DecisionAccept Decision = "accept"
	DecisionReject Decision = "reject"
)

func (d Decision) IsValid() bool {
	return d == DecisionAccept || d == DecisionReject
}

// CheckResponse represents the response to a /v1/events/check request.
type CheckResponse struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
}

// Platform represents the platform of a policy entity, e.g. "nostr", "github", "gitlab", "codeberg".
type Platform string

const (
	PlatformNostr    Platform = "nostr"
	PlatformGithub   Platform = "github"
	PlatformGitlab   Platform = "gitlab"
	PlatformCodeberg Platform = "codeberg"
)

func (p Platform) IsValid() bool {
	return p == PlatformNostr || p == PlatformGithub || p == PlatformGitlab || p == PlatformCodeberg
}

func (p Platform) Validate() error {
	if !p.IsValid() {
		return fmt.Errorf("unsupported platform: %s", p)
	}
	return nil
}

// Entity represents a policy entity with an identifier and platform.
// E.g. if the platform is "nostr", the ID is a public key.
// E.g. if the platform is "github", the ID is a username.
type Entity struct {
	ID       string
	Platform Platform
}

func (e Entity) Validate() error {
	switch e.Platform {
	case PlatformNostr:
		if e.ID == "" || !nostr.IsValidPublicKey(e.ID) {
			return fmt.Errorf("invalid pubkey")
		}
	case PlatformGithub, PlatformGitlab, PlatformCodeberg:
		if e.ID == "" {
			return fmt.Errorf("missing identifier")
		}
	default:
		return fmt.Errorf("invalid platform")
	}
	return nil
}

func (e Entity) String() string {
	return fmt.Sprintf("%s:%s", e.Platform, e.ID)
}

// PolicyStatus represents the status of a policy, either "allowed" or "blocked".
type PolicyStatus string

const (
	StatusAllowed PolicyStatus = "allowed"
	StatusBlocked PolicyStatus = "blocked"
)

func (s PolicyStatus) IsValid() bool {
	return s == StatusAllowed || s == StatusBlocked
}

// Policy represents a pubkey policy, either allowed or blocked, with other metadata.
type Policy struct {
	Entity    Entity
	Status    PolicyStatus
	Reason    string
	AddedBy   string
	CreatedAt time.Time
}

func (p Policy) Validate() error {
	if err := p.Entity.Validate(); err != nil {
		return err
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
		"  Platform: %s,\n"+
		"  ID: %s,\n"+
		"  Status: %s,\n"+
		"  Reason: %s,\n"+
		"  AddedBy: %s,\n"+
		"  CreatedAt: %s\n"+
		"}",
		p.Entity.Platform, p.Entity.ID, p.Status, p.Reason, p.AddedBy, p.CreatedAt)
}

func (p Policy) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"id":         p.Entity.ID,
		"platform":   p.Entity.Platform,
		"status":     p.Status,
		"reason":     p.Reason,
		"added_by":   p.AddedBy,
		"created_at": p.CreatedAt.Unix(), // unix timestamp for simplicity
	})
}

func (p *Policy) UnmarshalJSON(data []byte) error {
	var raw struct {
		EntityID       string       `json:"id"`
		EntityPlatform string       `json:"platform"`
		Status         PolicyStatus `json:"status"`
		Reason         string       `json:"reason"`
		AddedBy        string       `json:"added_by"`
		CreatedAt      int64        `json:"created_at"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.Entity.ID = raw.EntityID
	p.Entity.Platform = Platform(raw.EntityPlatform)
	p.Status = raw.Status
	p.Reason = raw.Reason
	p.AddedBy = raw.AddedBy
	p.CreatedAt = time.Unix(raw.CreatedAt, 0).UTC()
	return nil
}
