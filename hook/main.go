package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))

	var exit int
	func() {
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := run(ctx, logger); err != nil {
			logger.With("error", err).ErrorContext(ctx, "application exiting unsuccessfully")
			exit = 1
		}
	}()
	os.Exit(exit)
}

func run(ctx context.Context, logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	x509Source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		return fmt.Errorf("failed to create X509 source: %w", err)
	}
	defer func() { _ = x509Source.Close() }()

	server := newServer(cfg.path, cfg.claimsPatch, logger)

	return server.run(ctx, x509Source, cfg.allowedClientSpiffeIDs, cfg.listenAddr, cfg.healthAddr, cfg.shutdownTimeout)
}
