// Package client provides a client for the defender API.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/zapstore/defender/pkg/models"
)

const (
	defaultTimeout = 2 * time.Second
)

var (
	ErrPolicyNotFound = errors.New("policy not found")
)

type T struct {
	url  string
	http *http.Client
}

// New returns a new defender client that wraps the given HTTP client.
func New(c *http.Client, url string) (T, error) {
	url, err := normalizeURL(url)
	if err != nil {
		return T{}, err
	}
	return T{http: c, url: url}, nil
}

// Default returns a new defender client with a default HTTP client.
func Default(url string) (T, error) {
	url, err := normalizeURL(url)
	if err != nil {
		return T{}, err
	}

	return T{
		http: &http.Client{
			Timeout: defaultTimeout,
		},
		url: url,
	}, nil
}

// Health calls the server "GET /v1/health" endpoint and returns the health response.
func (c T) Health(ctx context.Context) (models.HealthResponse, error) {
	endpoint := c.url + "/v1/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return models.HealthResponse{}, fmt.Errorf("failed to get health: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return models.HealthResponse{}, fmt.Errorf("failed to get health: %w", err)
	}
	defer resp.Body.Close()

	var health models.HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return models.HealthResponse{}, fmt.Errorf("failed to decode health response: %w", err)
	}
	return health, nil
}

// CheckEvent calls the server "POST /v1/events/check" endpoint with the provided event.
func (c T) CheckEvent(ctx context.Context, event *nostr.Event) (models.CheckResponse, error) {
	b, err := json.Marshal(event)
	if err != nil {
		return models.CheckResponse{}, fmt.Errorf("failed to check event: %w", err)
	}

	endpoint := c.url + "/v1/events/check"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return models.CheckResponse{}, fmt.Errorf("failed to check event: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return models.CheckResponse{}, fmt.Errorf("failed to check event: %w", err)
	}
	defer resp.Body.Close()

	var check models.CheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&check); err != nil {
		return models.CheckResponse{}, fmt.Errorf("failed to decode response: %w", err)
	}
	return check, nil
}

func (c T) CheckBlob(ctx context.Context, blob models.BlobMeta) (models.CheckResponse, error) {
	b, err := json.Marshal(blob)
	if err != nil {
		return models.CheckResponse{}, fmt.Errorf("failed to check blob: %w", err)
	}

	endpoint := c.url + "/v1/blobs/check"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return models.CheckResponse{}, fmt.Errorf("failed to check blob: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return models.CheckResponse{}, fmt.Errorf("failed to check blob: %w", err)
	}
	defer resp.Body.Close()

	var check models.CheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&check); err != nil {
		return models.CheckResponse{}, fmt.Errorf("failed to decode response: %w", err)
	}
	return check, nil
}

// ListPolicies calls the server "GET /v1/policies" endpoint.
// If the platform is not empty, it filters the results by platform.
// If the status is not empty, it filters the results by status.
func (c T) ListPolicies(ctx context.Context, platform models.Platform, status models.PolicyStatus) ([]models.Policy, error) {
	endpoint := c.url + "/v1/policies"
	params := url.Values{}
	if platform != "" {
		params.Set("platform", string(platform))
	}
	if status != "" {
		params.Set("status", string(status))
	}
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get pubkey policies: %w", err)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get pubkey policies: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", res.StatusCode, body)
	}

	var pubkeys []models.Policy
	if err := json.NewDecoder(res.Body).Decode(&pubkeys); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return pubkeys, nil
}

// GetPolicy calls the server "GET /v1/policies/:pubkey" endpoint.
func (c T) GetPolicy(ctx context.Context, entity models.Entity) (models.Policy, error) {
	endpoint := fmt.Sprintf("%s/v1/policies/%s/%s", c.url, entity.Platform, entity.ID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return models.Policy{}, fmt.Errorf("failed to get pubkey policy: %w", err)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return models.Policy{}, fmt.Errorf("failed to get pubkey policy: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotFound {
		return models.Policy{}, ErrPolicyNotFound
	}
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return models.Policy{}, fmt.Errorf("unexpected status %d: %s", res.StatusCode, body)
	}

	var policy models.Policy
	if err := json.NewDecoder(res.Body).Decode(&policy); err != nil {
		return models.Policy{}, fmt.Errorf("failed to decode response: %w", err)
	}
	return policy, nil
}

// SetPolicy calls the server "PUT /v1/policies/:pubkey" endpoint.
func (c T) SetPolicy(ctx context.Context, policy models.Policy) error {
	endpoint := fmt.Sprintf("%s/v1/policies/%s/%s", c.url, policy.Entity.Platform, policy.Entity.ID)
	body, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to set pubkey policy: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("failed to set pubkey policy: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("unexpected status %d: %s", res.StatusCode, body)
	}
	return nil
}

// DeletePolicy calls the server "DELETE /v1/policies/:pubkey" endpoint.
func (c T) DeletePolicy(ctx context.Context, entity models.Entity) error {
	endpoint := fmt.Sprintf("%s/v1/policies/%s/%s", c.url, entity.Platform, entity.ID)

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to delete pubkey policy: %w", err)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete pubkey policy: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("unexpected status %d: %s", res.StatusCode, body)
	}
	return nil
}

func normalizeURL(u string) (string, error) {
	if len(u) == 0 {
		return "", fmt.Errorf("url is empty")
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return "", fmt.Errorf("url is invalid: %w", err)
	}
	if parsed.Scheme == "" {
		return "", fmt.Errorf("url must have a scheme")
	}
	return strings.TrimSuffix(u, "/"), nil
}
