// The vertex package exposes a configurable [Filter] struct that allows or rejects a pubkey
// based on its reputation. It maintains a LRU with configurable size and TTL for caching.
package vertex

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"
)

const (
	DVMEndpoint     = "https://relay.vertexlab.io/api/v1/dvms"
	CreditsEndpoint = "https://relay.vertexlab.io/api/v1/credits"
)

const (
	KindVerifyReputation = 5312
	KindRecommendFollows = 5313
	KindRankProfiles     = 5314
	KindSearchProfiles   = 5315
	KindDVMError         = 7000
	KindCredits          = 22243
)

// Filter is responsible for allowing based on the reputation of a pubkey.
// It stores ranks in a LRU cache with size and time to live specified in the config.
type Filter struct {
	http   *http.Client
	cache  *expirable.LRU[string, float64]
	config Config
}

// NewFilter creates a new Filter with the given config.
func NewFilter(c Config) Filter {
	return Filter{
		http:   &http.Client{Timeout: c.Timeout},
		cache:  expirable.NewLRU[string, float64](c.CacheSize, nil, c.CacheExpiration),
		config: c,
	}
}

type ProfileResponse struct {
	Pubkey    string  `json:"pubkey"`
	Rank      float64 `json:"rank"`
	Follows   int     `json:"follows"`
	Followers int     `json:"followers"`

	// present only if the profile leaked its key
	Leak *Leak `json:"leak,omitempty"`
}

type Leak struct {
	Status     string `json:"status"`
	Proof      string `json:"proof,omitempty"`
	DetectedAt int64  `json:"detected_at,omitempty"`
}

// Allow returns true if the pubkey is considered trustworthy, otherwise false.
// It returns an error if the request to Vertex fails.
func (f Filter) Allow(ctx context.Context, pubkey string) (bool, error) {
	if f.config.Algorithm.Threshold <= 0 {
		return true, nil
	}

	if rank, ok := f.cache.Get(pubkey); ok {
		return rank >= f.config.Algorithm.Threshold, nil
	}

	payload := nostr.Event{
		Kind:      KindVerifyReputation,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"param", "target", pubkey},
			{"param", "sort", string(f.config.Algorithm.Sort)},
			{"param", "source", f.config.Algorithm.Source},
			{"param", "limit", "0"}, // don't need top followers
		},
	}

	response, err := f.DVM(ctx, payload)
	if err != nil {
		return false, fmt.Errorf("vertex.Filter.Allow: %w", err)
	}

	var profiles []ProfileResponse
	if err := json.Unmarshal([]byte(response.Content), &profiles); err != nil {
		return false, fmt.Errorf("vertex.Filter: failed to unmarshal the response event content: %w", err)
	}

	if len(profiles) == 0 {
		return false, fmt.Errorf("vertex.Filter: received an empty response")
	}

	target := profiles[0]
	if target.Pubkey != pubkey {
		return false, fmt.Errorf("vertex.Filter: received a response for a different pubkey: expected %s, got %s", pubkey, target.Pubkey)
	}
	if target.Leak != nil {
		// a leaked key is by definition not trustworthy. We cache it to avoid repeated lookups.
		f.cache.Add(target.Pubkey, -1)
		return false, nil
	}

	f.cache.Add(target.Pubkey, target.Rank)
	return target.Rank >= f.config.Algorithm.Threshold, nil
}

// CreditResponse holds the credits and last request time returned by the Vertex API.
type CreditResponse struct {
	Credits     int64
	LastRequest time.Time
}

func (c CreditResponse) String() string {
	return fmt.Sprintf("Credits: %d, LastRequest: %s", c.Credits, c.LastRequest)
}

// CheckCredits returns the number of credits remaining for the pubkey associated with the configured secret key.
// It uses NIP-98 HTTP authentication to prove ownership of the pubkey to the Vertex API.
func (f Filter) CheckCredits(ctx context.Context) (CreditResponse, error) {
	auth, err := f.nip98Auth(CreditsEndpoint, http.MethodGet)
	if err != nil {
		return CreditResponse{}, fmt.Errorf("vertex.Filter.CheckCredits: %w", err)
	}

	b, err := json.Marshal(auth)
	if err != nil {
		return CreditResponse{}, fmt.Errorf("vertex.Filter.CheckCredits: failed to marshal NIP-98 auth event: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, CreditsEndpoint, nil)
	if err != nil {
		return CreditResponse{}, fmt.Errorf("vertex.Filter.CheckCredits: failed to create request: %w", err)
	}
	request.Header.Set("Authorization", "Nostr "+base64.RawURLEncoding.EncodeToString(b))

	response, err := f.http.Do(request)
	if err != nil {
		return CreditResponse{}, fmt.Errorf("vertex.Filter.CheckCredits: failed to send request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		return CreditResponse{}, fmt.Errorf("vertex.Filter.CheckCredits: unexpected status code: %d, body: %s", response.StatusCode, string(body))
	}

	var result nostr.Event
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return CreditResponse{}, fmt.Errorf("vertex.Filter.CheckCredits: failed to decode response: %w", err)
	}

	credits, err := parseCredits(result)
	if err != nil {
		return CreditResponse{}, fmt.Errorf("vertex.Filter.CheckCredits: %w", err)
	}
	return credits, nil
}

// parseCredits parses the credits and lastRequest tags from the credits endpoint response event.
func parseCredits(e nostr.Event) (CreditResponse, error) {
	if e.Kind != KindCredits {
		return CreditResponse{}, fmt.Errorf("expected kind %d, got %d", KindCredits, e.Kind)
	}

	creditsTag := e.Tags.Find("credits")
	if creditsTag == nil {
		return CreditResponse{}, fmt.Errorf("credits tag missing from response")
	}

	credits, err := strconv.ParseInt(creditsTag[1], 10, 64)
	if err != nil {
		return CreditResponse{}, fmt.Errorf("failed to parse credits value %q: %w", creditsTag[1], err)
	}

	lastRequestTag := e.Tags.Find("lastRequest")
	if lastRequestTag == nil {
		return CreditResponse{}, fmt.Errorf("lastRequest tag missing from response")
	}

	lastRequest, err := strconv.ParseInt(lastRequestTag[1], 10, 64)
	if err != nil {
		return CreditResponse{}, fmt.Errorf("failed to parse lastRequest value %q: %w", lastRequestTag[1], err)
	}

	return CreditResponse{
		Credits:     credits,
		LastRequest: time.Unix(lastRequest, 0),
	}, nil
}

func (f Filter) nip98Auth(endpoint, method string) (nostr.Event, error) {
	auth := nostr.Event{
		Kind:      nostr.KindHTTPAuth,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"u", endpoint},
			{"method", method},
		},
	}
	if err := auth.Sign(f.config.SecretKey); err != nil {
		return nostr.Event{}, fmt.Errorf("failed to sign NIP-98 auth event: %w", err)
	}
	return auth, nil
}

// DVM makes an API call to the Vertex API /dvms endpoint, writing the specified nostr event into the body.
// It returns the DVM response or an error if any. Kind 7000 are considered errors.
func (f Filter) DVM(ctx context.Context, payload nostr.Event) (nostr.Event, error) {
	if err := payload.Sign(f.config.SecretKey); err != nil {
		return nostr.Event{}, fmt.Errorf("failed to sign the request: %w", err)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nostr.Event{}, fmt.Errorf("failed to marshal the API payload: %w", err)
	}

	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, DVMEndpoint, bytes.NewReader(body),
	)
	if err != nil {
		return nostr.Event{}, fmt.Errorf("failed to create the API request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := f.http.Do(request)
	if err != nil {
		return nostr.Event{}, fmt.Errorf("failed to send the API request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(response.Body)
		return nostr.Event{}, fmt.Errorf("unexpected status code: %d, body: %s", response.StatusCode, string(body))
	}

	var result nostr.Event
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nostr.Event{}, fmt.Errorf("failed to decode the API response: %w", err)
	}

	switch result.Kind {
	case KindDVMError:
		msg := "unknown error"
		status := result.Tags.Find("status")
		if len(status) > 2 {
			msg = status[2]
		}
		return nostr.Event{}, fmt.Errorf("received a DVM error: %s", msg)

	case payload.Kind + 1000:
		return result, nil

	default:
		return nostr.Event{}, fmt.Errorf("received an unknown kind: expected %d, got %d", payload.Kind+1000, result.Kind)
	}
}
