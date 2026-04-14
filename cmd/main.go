package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/zapstore/defender/pkg/server"
	"github.com/zapstore/defender/pkg/server/sqlite"
	"github.com/zapstore/defender/pkg/server/vertex"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	slog.Info("-------------------defender startup-------------------")
	defer slog.Info("-------------------defender shutdown-------------------")

	config, err := server.LoadConfig()
	if err != nil {
		panic(err)
	}

	if err := config.Validate(); err != nil {
		panic(err)
	}

	db, err := sqlite.New(config.DB)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	vertex := vertex.NewFilter(config.Vertex)
	server := server.Setup(config, db, vertex)

	slog.Info("starting http server", "addr", config.HTTP.Addr)

	exitErr := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			exitErr <- err
		}
	}()

	select {
	case <-ctx.Done():
		slog.Info("signal received, shutting down the server")

		ctx, cancel := context.WithTimeout(context.Background(), config.HTTP.ShutdownTimeout)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			panic(err)
		}

	case err := <-exitErr:
		panic(err)
	}
}
