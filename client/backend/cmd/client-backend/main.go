package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/api"
	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/config"
	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/registry"
	"github.com/natsumezjr/attack-trace-analyzer/client/backend/internal/state"
)

func main() {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		slog.Error("config error", "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	st, err := state.NewManager(cfg.StatePath)
	if err != nil {
		slog.Error("state init error", "error", err)
		os.Exit(1)
	}
	if err := st.Load(); err != nil {
		slog.Warn("state load failed, continue with empty state", "error", err)
	}

	if cfg.CenterBaseURL != "" && !cfg.RegisterDisable {
		go registry.RunRegisterLoop(ctx, cfg, st)
	}

	server := &http.Server{
		Addr:              cfg.BindAddr,
		Handler:           api.NewRouter(cfg, st),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		slog.Info("client-backend listening", "addr", cfg.BindAddr, "client_id", cfg.ClientID)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			stop()
		}
	}()

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}
