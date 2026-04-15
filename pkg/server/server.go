package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/zapstore/defender/pkg/server/sqlite"
	"github.com/zapstore/defender/pkg/server/vertex"
)

// T is the main server type. It implements http.Handler and can be started with Start.
type T struct {
	db     sqlite.DB
	vertex vertex.Filter
	config Config
}

// New returns a new server instance with the given configuration and dependencies.
func New(c Config, db sqlite.DB, filter vertex.Filter) *T {
	return &T{
		db:     db,
		vertex: filter,
		config: c,
	}
}

// ServeHTTP implements http.Handler.
func (s *T) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/events/check":
		s.HandleCheck(w, r)

	case r.Method == http.MethodGet && r.URL.Path == "/v1/pubkeys":
		s.HandlePubkeys(w, r)

	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v1/pubkeys/"):
		s.HandlePutPubkey(w, r)

	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// Start runs the HTTP server and blocks until the context is cancelled, then performs a graceful shutdown.
// It returns a non-nil error if the HTTP server fails.
func (s *T) Start(ctx context.Context) error {
	server := &http.Server{
		Addr:         s.config.HTTP.Addr,
		Handler:      s,
		ReadTimeout:  s.config.HTTP.ReadTimeout,
		WriteTimeout: s.config.HTTP.WriteTimeout,
		IdleTimeout:  s.config.HTTP.IdleTimeout,
	}

	exit := make(chan error, 1)
	go func() {
		slog.Info("server listening", "addr", s.config.HTTP.Addr)
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			exit <- err
		}
	}()

	select {
	case err := <-exit:
		return err

	case <-ctx.Done():
		slog.Info("server shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), s.config.HTTP.ShutdownTimeout)
		defer cancel()
		return server.Shutdown(ctx)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("writeJSON: failed to encode response", "err", err)
	}
}
