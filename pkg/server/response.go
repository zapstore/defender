package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/nbd-wtf/go-nostr"
	"github.com/zapstore/defender/pkg/server/sqlite"
)

type Decision string

const (
	Accept Decision = "accept"
	Reject Decision = "reject"
)

type CheckResponse struct {
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
}

func (s *T) HandleCheck(w http.ResponseWriter, r *http.Request) {
	var event nostr.Event
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		slog.Error("checkHandler: invalid event JSON", "err", err)
		writeJSON(w, http.StatusBadRequest, CheckResponse{
			Decision: Reject,
			Reason:   fmt.Sprintf("invalid event payload: %s", err),
		})
		return
	}

	if !event.CheckID() {
		slog.Error("checkHandler: invalid event id", "event", event)
		writeJSON(w, http.StatusBadRequest, CheckResponse{
			Decision: Reject,
			Reason:   "invalid event id",
		})
		return
	}

	if ok, err := event.CheckSignature(); err != nil || !ok {
		slog.Error("checkHandler: invalid event signature", "event", event)
		writeJSON(w, http.StatusBadRequest, CheckResponse{
			Decision: Reject,
			Reason:   "invalid event signature",
		})
		return
	}

	response, err := s.checkEvent(r.Context(), event)
	if err != nil {
		slog.Error("checkHandler: failed to check event", "err", err)
		writeJSON(w, http.StatusInternalServerError, CheckResponse{
			Decision: Reject,
			Reason:   "internal error while checking event",
		})
		return
	}

	writeJSON(w, http.StatusOK, response)
}

// checkEvent evaluates a valid event and returns the appropriate CheckResponse.
// It is the caller's responsibility to ensure the event is valid before calling this function.
func (s *T) checkEvent(ctx context.Context, event nostr.Event) (CheckResponse, error) {
	// Fast path: check local DB policy first.
	policy, err := s.db.PolicyOf(ctx, event.PubKey)
	if err != nil && !errors.Is(err, sqlite.ErrPolicyNotFound) {
		return CheckResponse{}, err
	}

	if err == nil {
		switch policy.Status {
		case sqlite.StatusBlocked:
			return CheckResponse{
				Decision: Reject,
				Reason:   fmt.Sprintf("pubkey is blocked: %s", policy.Reason),
			}, nil
		case sqlite.StatusAllowed:
			return CheckResponse{
				Decision: Accept,
				Reason:   fmt.Sprintf("pubkey is explicitly allowed: %s", policy.Reason),
			}, nil
		}
	}

	// Slow path: fall back to Vertex reputation check.
	allowed, err := s.vertex.Allow(ctx, event.PubKey)
	if err != nil {
		return CheckResponse{}, err
	}

	if !allowed {
		return CheckResponse{
			Decision: Reject,
			Reason:   "pubkey does not meet the minimum reputation threshold",
		}, nil
	}

	return CheckResponse{
		Decision: Accept,
		Reason:   "pubkey meets the minimum reputation threshold",
	}, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writeJSON: failed to encode response", "err", err)
	}
}
