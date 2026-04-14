package server

import (
	"net/http"

	"github.com/zapstore/defender/pkg/server/sqlite"
	"github.com/zapstore/defender/pkg/server/vertex"
)

// Setup registers all routes and returns a configured *http.Server ready to be started.
func Setup(c Config, db sqlite.DB, vertex vertex.Filter) *http.Server {
	mux := http.NewServeMux()

	// TODO: register routes

	return &http.Server{
		Addr:         c.HTTP.Addr,
		Handler:      mux,
		ReadTimeout:  c.HTTP.ReadTimeout,
		WriteTimeout: c.HTTP.WriteTimeout,
		IdleTimeout:  c.HTTP.IdleTimeout,
	}
}
