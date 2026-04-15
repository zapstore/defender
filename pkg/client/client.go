package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

// Check sends an event to the defender server and returns the server's response.
func (c T) Check(ctx context.Context, event *nostr.Event) (models.CheckResponse, error) {
	b, err := json.Marshal(event)
	if err != nil {
		return models.CheckResponse{}, fmt.Errorf("failed to check event: %w", err)
	}

	endpoint, err := url.JoinPath(c.url, "/v1/events/check")
	if err != nil {
		return models.CheckResponse{}, fmt.Errorf("failed to check event: %w", err)
	}

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
