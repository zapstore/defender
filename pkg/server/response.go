package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
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

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	response, err := s.checkEvent(ctx, event)
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

	// use a background context because we want to record the decision, even if the client doesn't need it anymore.
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

func (s *T) HandleListPubkeys(w http.ResponseWriter, r *http.Request) {
	status := models.PolicyStatus(r.URL.Query().Get("status"))
	if status != "" && status != models.StatusAllowed && status != models.StatusBlocked {
		http.Error(w, `invalid status filter: must be "allowed" or "blocked"`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	policies, err := s.db.Policies(ctx, status)
	if err != nil {
		slog.Error("HandleListPubkeys: failed to fetch policies", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func (s *T) HandleGetPubkey(w http.ResponseWriter, r *http.Request) {
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
		slog.Error("HandleGetPubkeys: failed to fetch policy", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *T) HandlePutPubkey(w http.ResponseWriter, r *http.Request) {
	pubkey := strings.TrimPrefix(r.URL.Path, "/v1/pubkeys/")
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
		slog.Error("HandlePutPubkey: failed to set policy", "pubkey", pubkey, "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *T) HandleDeletePubkey(w http.ResponseWriter, r *http.Request) {
	pubkey := strings.TrimPrefix(r.URL.Path, "/v1/pubkeys/")
	if pubkey == "" || !nostr.IsValidPublicKey(pubkey) {
		http.Error(w, "invalid pubkey", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()

	if _, err := s.db.RemovePolicy(ctx, pubkey); err != nil {
		slog.Error("HandleDeletePubkey: failed to delete policy", "pubkey", pubkey, "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
