package server

import (
	"net/http"

	"github.com/zapstore/defender/pkg/server/config"
	"github.com/zapstore/defender/pkg/server/db"
	"github.com/zapstore/defender/pkg/server/vertex"
)

// Setup registers all routes and returns a configured *http.Server ready to be started.
func Setup(cfg config.T, database db.DB, filter vertex.Filter) *http.Server {
	mux := http.NewServeMux()

	// TODO: register routes

	return &http.Server{
		Addr:         cfg.HTTP.Addr,
		Handler:      mux,
		ReadTimeout:  cfg.HTTP.ReadTimeout,
		WriteTimeout: cfg.HTTP.WriteTimeout,
		IdleTimeout:  cfg.HTTP.IdleTimeout,
	}
}
