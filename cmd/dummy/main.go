// Command dummy is an allow-all defender for local development.
//
// It speaks the defender HTTP API so the relay can run unmodified with
// DEFENDER_URL pointing at it: every event and blob check is accepted, the
// policy list is empty, and policy writes succeed without storing anything.
// Never deploy it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	addr := flag.String("addr", "localhost:8080", "listen address")
	flag.Parse()

	if err := run(*addr); err != nil {
		slog.Error("dummy defender exited", "error", err)
		os.Exit(1)
	}
}

func run(addr string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	server := &http.Server{
		Addr:              addr,
		Handler:           handler(time.Now()),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	exit := make(chan error, 1)
	go func() {
		slog.Info("dummy defender listening; every check is accepted", "addr", addr)
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			exit <- err
		}
	}()

	select {
	case err := <-exit:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	}
}

func handler(started time.Time) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{
			"status":  "ok",
			"version": "dummy",
			"uptime":  time.Since(started).Round(time.Second).String(),
		})
	})

	accept := func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{
			"decision": "accept",
			"reason":   "dummy defender accepts everything",
		})
	}
	mux.HandleFunc("POST /v1/events/check", accept)
	mux.HandleFunc("POST /v1/blobs/check", accept)

	mux.HandleFunc("GET /v1/policies", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, []struct{}{})
	})
	mux.HandleFunc("GET /v1/audits", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, []struct{}{})
	})
	mux.HandleFunc("GET /v1/policies/{platform}/{id}", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, fmt.Sprintf("no policy for %s/%s", r.PathValue("platform"), r.PathValue("id")), http.StatusNotFound)
	})
	mux.HandleFunc("PUT /v1/policies/{platform}/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /v1/policies/{platform}/{id}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("write response", "error", err)
	}
}
