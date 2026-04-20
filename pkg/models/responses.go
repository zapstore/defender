// Package models defines the core domain types shared across the server, client, and storage layers.
package models

import (
	"errors"

	"github.com/nbd-wtf/go-nostr"
	"github.com/pippellia-btc/blossom"
)

// HealthResponse is the response body for GET /v1/health.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
	Uptime  string `json:"uptime"`
}

// Decision represents the decision made for an event in the check endpoint.
type Decision string

const (
	DecisionAccept Decision = "accept"
	DecisionReject Decision = "reject"
)

func (d Decision) IsValid() bool {
	return d == DecisionAccept || d == DecisionReject
}

// CheckResponse represents the response returned by the /v1/events/check and /v1/blobs/check endpoints.
type CheckResponse struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
}

// BlobMeta represents the blob metadata sent in the /v1/blobs/check request.
type BlobMeta struct {
	Pubkey string       `json:"pubkey"`
	Hash   blossom.Hash `json:"hash"`
	Size   int64        `json:"size"`
	Type   string       `json:"type"`
}

func (b BlobMeta) Validate() error {
	if b.Pubkey == "" {
		return errors.New("pubkey is required")
	}
	if !nostr.IsValidPublicKey(b.Pubkey) {
		return errors.New("invalid pubkey")
	}
	if b.Hash.IsZero() {
		return errors.New("hash is required")
	}
	if b.Size <= 0 {
		return errors.New("size is required")
	}
	return nil
}
