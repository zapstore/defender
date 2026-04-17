package main

import (
	"context"
	"log/slog"
	"os/signal"
	"syscall"

	"github.com/zapstore/defender/pkg/server"
	"github.com/zapstore/defender/pkg/server/repo"
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

	vertex := vertex.NewClient(config.Vertex)
	repo := repo.NewFetcher(config.Repo)

	server := server.New(config, db, vertex, repo)
	if err := server.Start(ctx); err != nil {
		panic(err)
	}
}
