package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/zapstore/defender/pkg/models"
	"github.com/zapstore/defender/pkg/server/repo"
	"github.com/zapstore/defender/pkg/server/sqlite"
)

// Health handles GET /v1/health returning a [models.HealthResponse].
func (s *T) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, models.HealthResponse{
		Status:  "ok",
		Version: Version,
		Uptime:  time.Since(s.started).Round(time.Second).String(),
	})
}

// CheckEvent handles the /v1/events/check endpoint, returning a [models.CheckResponse].
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
		slog.Error("CheckEvent: failed to check event", "err", err, "id", event.ID)
		writeJSON(w, http.StatusInternalServerError, models.CheckResponse{
			Decision: models.DecisionReject,
			Reason:   "internal error while checking event",
		})
		return
	}
	writeJSON(w, http.StatusOK, response)

	audit := sqlite.Audit{
		Type:      sqlite.AuditEvent,
		Hash:      event.ID,
		Pubkey:    event.PubKey,
		Decision:  response.Decision,
		Reason:    response.Reason,
		CheckedAt: time.Now().UTC(),
	}

	// use a background context because we want to record the decision, even if the client doesn't need it anymore.
	if err := s.db.Record(context.Background(), audit); err != nil {
		slog.Error("CheckEvent: failed to record check event audit", "err", err)
	}
}

// parseEvent parses a JSON-encoded event from a reader, validating ID and signature.
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
// It is the caller's responsibility to ensure the event is valid.
func (s *T) checkEvent(ctx context.Context, e *nostr.Event) (models.CheckResponse, error) {
	entity := models.Entity{Platform: models.PlatformNostr, ID: e.PubKey}
	isRestricted := slices.Contains(s.config.RestrictedKinds, e.Kind)

	if !isRestricted {
		// events with open kinds are accepted unless the pubkey is blocked.
		blocked, err := s.db.IsBlocked(ctx, entity)
		if err != nil {
			return models.CheckResponse{}, fmt.Errorf("failed to check if the pubkey %s is blocked: %w", e.PubKey, err)
		}
		if blocked {
			return models.CheckResponse{
				Decision: models.DecisionReject,
				Reason:   "pubkey is blocked",
			}, nil
		}
		return models.CheckResponse{
			Decision: models.DecisionAccept,
			Reason:   "event kind is not restricted, and pubkey is not blocked",
		}, nil
	}

	// full verification for restricted event kinds
	policy, err := s.db.PolicyOf(ctx, entity)
	if err != nil && !errors.Is(err, sqlite.ErrPolicyNotFound) {
		return models.CheckResponse{}, err
	}

	if err == nil {
		// a policy exists, so we use it
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

	if e.Kind == models.KindApp {
		if result := s.checkAppRepo(ctx, e); result != nil {
			return *result, nil
		}
	}

	allowed, err := s.vertex.Allow(ctx, e.PubKey)
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

// checkAppRepo checks the repository declared in a KindApp event's "repository" tag.
// It fetches the pubkey in the zapstore.yaml and auto-allows it.
// If the pubkey matches the event pubkey, it returns an accept response, otherwise nil.
func (s *T) checkAppRepo(ctx context.Context, e *nostr.Event) *models.CheckResponse {
	tag := e.Tags.Find("repository")
	if tag == nil || tag[1] == "" {
		return nil
	}

	repo, err := repo.Parse(tag[1])
	if err != nil {
		return nil
	}

	pubkey, err := s.allowRepo(ctx, repo)
	if err != nil {
		return nil
	}

	// if the pubkey matches the event pubkey, return an accept response.
	if pubkey == e.PubKey {
		return &models.CheckResponse{
			Decision: models.DecisionAccept,
			Reason:   fmt.Sprintf("pubkey %s allowed by repo validation", e.PubKey),
		}
	}
	return nil
}

// allowRepo auto-allow the pubkey in the zapstore.yaml of the specified repo.
func (s *T) allowRepo(ctx context.Context, repo repo.Parsed) (pubkey string, err error) {
	if err := repo.Validate(); err != nil {
		return "", err
	}

	// if the repo platform entity is blocked, this strategy does not apply
	blocked, err := s.db.IsBlocked(ctx, repo.Entity)
	if err != nil {
		slog.Error("allowRepo: failed to check if repo entity is blocked", "error", err)
		return "", err
	}
	if blocked {
		return "", errors.New("repo entity is blocked")
	}

	pubkey, err = s.repo.Fetch(ctx, repo)
	if err != nil {
		return "", err
	}
	nostrEntity := models.Entity{
		Platform: models.PlatformNostr,
		ID:       pubkey,
	}
	if err := nostrEntity.Validate(); err != nil {
		return "", err
	}

	// if the pubkey is blocked, this strategy does not apply
	blocked, err = s.db.IsBlocked(ctx, nostrEntity)
	if err != nil {
		slog.Error("allowRepo: failed to check if pubkey is blocked", "error", err)
		return "", err
	}
	if blocked {
		return "", errors.New("pubkey is blocked")
	}

	// auto-allow the pubkey in the zapstore.yaml.
	policy := models.Policy{
		Entity:    nostrEntity,
		Status:    models.StatusAllowed,
		Reason:    fmt.Sprintf("allowed via zapstore.yaml in %s/%s", repo.Entity.Platform, repo.Repo),
		AddedBy:   "repo-validation",
		CreatedAt: time.Now().UTC(),
	}

	if err := s.db.SetPolicy(ctx, policy); err != nil {
		slog.Error("allowRepo: failed to set policy", "error", err)
		return "", err
	}
	return pubkey, nil
}

// CheckBlob handles the /v1/blobs/check endpoint, returning a [models.CheckResponse].
func (s *T) CheckBlob(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.config.HTTP.MaxBodyBytes)
	blob, err := parseBlob(r.Body)
	if err != nil {
		slog.Error("CheckBlob: invalid blob", "err", err)
		writeJSON(w, http.StatusBadRequest, models.CheckResponse{
			Decision: models.DecisionReject,
			Reason:   err.Error(),
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	response, err := s.checkBlob(ctx, blob)
	if err != nil {
		slog.Error("CheckBlob: failed to check blob", "err", err, "hash", blob.Hash)
		writeJSON(w, http.StatusInternalServerError, models.CheckResponse{
			Decision: models.DecisionReject,
			Reason:   "internal error while checking blob",
		})
		return
	}
	writeJSON(w, http.StatusOK, response)

	audit := sqlite.Audit{
		Type:      sqlite.AuditBlob,
		Hash:      blob.Hash.Hex(),
		Pubkey:    blob.Pubkey,
		Decision:  response.Decision,
		Reason:    response.Reason,
		CheckedAt: time.Now().UTC(),
	}

	// use a background context because we want to record the decision, even if the client doesn't need it anymore.
	if err := s.db.Record(context.Background(), audit); err != nil {
		slog.Error("CheckBlob: failed to record check blob audit", "err", err)
	}
}

// parseBlob parses a blob metadata from the request body and validates it.
func parseBlob(r io.Reader) (*models.BlobMeta, error) {
	var blob models.BlobMeta
	if err := json.NewDecoder(r).Decode(&blob); err != nil {
		return nil, err
	}

	if err := blob.Validate(); err != nil {
		return nil, err
	}
	return &blob, nil
}

func (s *T) checkBlob(ctx context.Context, blob *models.BlobMeta) (models.CheckResponse, error) {
	entity := models.Entity{Platform: models.PlatformNostr, ID: blob.Pubkey}

	policy, err := s.db.PolicyOf(ctx, entity)
	if err != nil && !errors.Is(err, sqlite.ErrPolicyNotFound) {
		return models.CheckResponse{}, err
	}

	if err == nil {
		// a policy exists, so we use it
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

	allowed, err := s.vertex.Allow(ctx, blob.Pubkey)
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
	if status != "" && !status.IsValid() {
		http.Error(w, `invalid status filter: must be "allowed" or "blocked"`, http.StatusBadRequest)
		return
	}

	platform := models.Platform(r.URL.Query().Get("platform"))
	if platform != "" && !platform.IsValid() {
		http.Error(w, `invalid platform filter"`, http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	policies, err := s.db.Policies(ctx, platform, status)
	if err != nil {
		slog.Error("ListPolicies failed", "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func (s *T) GetPolicy(w http.ResponseWriter, r *http.Request) {
	entity := models.Entity{
		ID:       r.PathValue("id"),
		Platform: models.Platform(r.PathValue("platform")),
	}

	if err := entity.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()

	policy, err := s.db.PolicyOf(ctx, entity)
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
	entity := models.Entity{
		ID:       r.PathValue("id"),
		Platform: models.Platform(r.PathValue("platform")),
	}

	if err := entity.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.config.HTTP.MaxBodyBytes)
	var policy models.Policy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		http.Error(w, fmt.Sprintf("invalid request body: %s", err), http.StatusBadRequest)
		return
	}

	// overwrite fields
	policy.Entity = entity
	policy.CreatedAt = time.Now().UTC()

	if err := policy.Validate(); err != nil {
		http.Error(w, fmt.Sprintf("invalid request: %s", err), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := s.db.SetPolicy(ctx, policy); err != nil {
		slog.Error("SetPolicy failed", "id", entity.ID, "platform", entity.Platform, "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *T) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	entity := models.Entity{
		ID:       r.PathValue("id"),
		Platform: models.Platform(r.PathValue("platform")),
	}

	if err := entity.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()

	if _, err := s.db.DeletePolicy(ctx, entity); err != nil {
		slog.Error("DeletePolicy failed", "id", entity.ID, "platform", entity.Platform, "err", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
