package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/zapstore/defender/pkg/server/sqlite"
	"github.com/zapstore/defender/pkg/server/vertex"
)

// T is the main server type. It can be started with Start.
type T struct {
	mux    *http.ServeMux
	db     sqlite.DB
	vertex vertex.Filter
	config Config
}

// New returns a new server instance with the given configuration and dependencies.
func New(c Config, db sqlite.DB, filter vertex.Filter) *T {
	s := &T{
		mux:    http.NewServeMux(),
		db:     db,
		vertex: filter,
		config: c,
	}

	s.mux.HandleFunc("GET /v1/policies", s.ListPolicies)
	s.mux.HandleFunc("GET /v1/policies/{pubkey}", s.GetPolicy)
	s.mux.HandleFunc("PUT /v1/policies/{pubkey}", s.SetPolicy)
	s.mux.HandleFunc("DELETE /v1/policies/{pubkey}", s.DeletePolicy)

	s.mux.HandleFunc("POST /v1/events/check", s.CheckEvent)
	return s
}

// Start runs the HTTP server and blocks until the context is cancelled, then performs a graceful shutdown.
// It returns a non-nil error if the HTTP server fails.
func (s *T) Start(ctx context.Context) error {
	server := &http.Server{
		Addr:         s.config.HTTP.Addr,
		Handler:      s.mux,
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
