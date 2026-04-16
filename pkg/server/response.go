package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/zapstore/defender/pkg/models"
	"github.com/zapstore/defender/pkg/server/sqlite"
)

func (s *T) CheckEvent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.config.HTTP.MaxBodyBytes)
	event, err := parseEvent(r.Body)
	if err != nil {
		slog.Error("CheckEvent: invalid event", "err", err)
		writeJSON(w, http.StatusBadRequest, models.CheckResponse{
			Decision: models.DecisionReject,
			Reason:   err.Error(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	response, err := s.checkEvent(ctx, event)
	if err != nil {
		slog.Error("CheckEvent: failed to check event", "err", err)
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

	// use a background context because we want to record the decision, even if the client doesn't need it anymore.
	if err := s.db.RecordDecision(context.Background(), decision); err != nil {
		slog.Error("checkHandler: failed to record decision", "err", err)
	}
}

func parseEvent(r io.Reader) (*nostr.Event, error) {
	var event nostr.Event
	if err := json.NewDecoder(r).Decode(&event); err != nil {
		return nil, fmt.Errorf("invalid event payload: %w", err)
	}
	if !event.CheckID() {
		return nil, fmt.Errorf("invalid event id")
	}
	if ok, err := event.CheckSignature(); err != nil || !ok {
		return nil, fmt.Errorf("invalid event signature")
	}
	return &event, nil
}

// checkEvent evaluates a valid event and returns the appropriate models.CheckResponse.
// It is the caller's responsibility to ensure the event is valid before calling this function.
func (s *T) checkEvent(ctx context.Context, event *nostr.Event) (models.CheckResponse, error) {
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

func (s *T) ListPolicies(w http.ResponseWriter, r *http.Request) {
	status := models.PolicyStatus(r.URL.Query().Get("status"))
	if status != "" && status != models.StatusAllowed && status != models.StatusBlocked {
		http.Error(w, `invalid status filter: must be "allowed" or "blocked"`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	policies, err := s.db.Policies(ctx, status)
	if err != nil {
		slog.Error("ListPolicies failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func (s *T) GetPolicy(w http.ResponseWriter, r *http.Request) {
	pubkey := r.PathValue("pubkey")
	if pubkey == "" {
		http.Error(w, "missing pubkey", http.StatusBadRequest)
		return
	}
	if !nostr.IsValidPublicKey(pubkey) {
		http.Error(w, "invalid pubkey", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()

	policy, err := s.db.PolicyOf(ctx, pubkey)
	if errors.Is(err, sqlite.ErrPolicyNotFound) {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("GetPolicy failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *T) SetPolicy(w http.ResponseWriter, r *http.Request) {
	pubkey := r.PathValue("pubkey")
	r.Body = http.MaxBytesReader(w, r.Body, s.config.HTTP.MaxBodyBytes)

	var policy models.Policy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %s", err), http.StatusBadRequest)
		return
	}

	// overwrite fields
	policy.Pubkey = pubkey
	policy.CreatedAt = time.Now().UTC()

	if err := policy.Validate(); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %s", err), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := s.db.SetPolicy(ctx, policy); err != nil {
		slog.Error("SetPolicy failed", "pubkey", pubkey, "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *T) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	pubkey := r.PathValue("pubkey")
	if pubkey == "" || !nostr.IsValidPublicKey(pubkey) {
		http.Error(w, "invalid pubkey", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()

	if _, err := s.db.DeletePolicy(ctx, pubkey); err != nil {
		slog.Error("DeletePolicy failed", "pubkey", pubkey, "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
