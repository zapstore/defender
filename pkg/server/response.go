package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/zapstore/defender/pkg/models"
	"github.com/zapstore/defender/pkg/server/sqlite"
)

const maxEventBytes = 1024 * 1024 // 1 MB

func (s *T) HandleCheck(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxEventBytes)
	var event nostr.Event

	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		slog.Error("checkHandler: invalid event JSON", "err", err)
		writeJSON(w, http.StatusBadRequest, models.CheckResponse{
			Decision: models.DecisionReject,
			Reason:   fmt.Sprintf("invalid event payload: %s", err),
		})
		return
	}

	if !event.CheckID() {
		slog.Error("checkHandler: invalid event id", "event", event)
		writeJSON(w, http.StatusBadRequest, models.CheckResponse{
			Decision: models.DecisionReject,
			Reason:   "invalid event id",
		})
		return
	}

	if ok, err := event.CheckSignature(); err != nil || !ok {
		slog.Error("checkHandler: invalid event signature", "event", event)
		writeJSON(w, http.StatusBadRequest, models.CheckResponse{
			Decision: models.DecisionReject,
			Reason:   "invalid event signature",
		})
		return
	}

	response, err := s.checkEvent(r.Context(), event)
	if err != nil {
		slog.Error("checkHandler: failed to check event", "err", err)
		writeJSON(w, http.StatusInternalServerError, models.CheckResponse{
			Decision: models.DecisionReject,
			Reason:   "internal error while checking event",
		})
		return
	}

	writeJSON(w, http.StatusOK, response)

	decision := sqlite.EventDecision{
		CheckedAt: time.Now(),
		EventID:   event.ID,
		Pubkey:    event.PubKey,
		Decision:  response.Decision,
		Reason:    response.Reason,
	}

	if err := s.db.RecordDecision(context.Background(), decision); err != nil {
		slog.Error("checkHandler: failed to record decision", "err", err)
	}
}

// checkEvent evaluates a valid event and returns the appropriate models.CheckResponse.
// It is the caller's responsibility to ensure the event is valid before calling this function.
func (s *T) checkEvent(ctx context.Context, event nostr.Event) (models.CheckResponse, error) {
	// Fast path: check local DB policy first.
	policy, err := s.db.PolicyOf(ctx, event.PubKey)
	if err != nil && !errors.Is(err, sqlite.ErrPolicyNotFound) {
		return models.CheckResponse{}, err
	}

	if err == nil {
		switch policy.Status {
		case models.StatusBlocked:
			return models.CheckResponse{
				Decision: models.DecisionReject,
				Reason:   fmt.Sprintf("pubkey is blocked: %s", policy.Reason),
			}, nil
		case models.StatusAllowed:
			return models.CheckResponse{
				Decision: models.DecisionAccept,
				Reason:   fmt.Sprintf("pubkey is explicitly allowed: %s", policy.Reason),
			}, nil
		}
	}

	// Slow path: fall back to Vertex reputation check.
	allowed, err := s.vertex.Allow(ctx, event.PubKey)
	if err != nil {
		return models.CheckResponse{}, err
	}

	if !allowed {
		return models.CheckResponse{
			Decision: models.DecisionReject,
			Reason:   "pubkey does not meet the minimum reputation threshold",
		}, nil
	}

	return models.CheckResponse{
		Decision: models.DecisionAccept,
		Reason:   "pubkey meets the minimum reputation threshold",
	}, nil
}
