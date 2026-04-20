// Package models defines the core domain types shared across the server, client, and storage layers.
package models

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

// CheckResponse represents the response to a /v1/events/check request.
type CheckResponse struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
}
