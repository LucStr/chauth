package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/LucStr/chauth/internal/chconfig"
	"github.com/LucStr/chauth/internal/rbac"
	"github.com/LucStr/chauth/internal/telemetry"
	"github.com/LucStr/chauth/internal/token"
)

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", "/etc/chauth/config.yaml", "path to the config file")
	_ = fs.Parse(args)

	log := telemetry.Logger(os.Stdout, nil)
	cfg, err := chconfig.Load(*path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	verifier := token.NewVerifier(cfg.OIDC)
	store := rbac.NewStore(cfg.Databases(), cfg.Roles(), log)
	return runServe(ctx, cfg, verifier, store, log)
}

func runServe(ctx context.Context, cfg *chconfig.Config, verifier *token.Verifier, store *rbac.Store, log *slog.Logger) error {
	return errors.New("serve is not implemented yet")
}
