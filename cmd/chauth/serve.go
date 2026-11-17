package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/LucStr/chauth/internal/chconfig"
	"github.com/LucStr/chauth/internal/chproxy"
	"github.com/LucStr/chauth/internal/rbac"
	"github.com/LucStr/chauth/internal/telemetry"
	"github.com/LucStr/chauth/internal/token"
)

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := fs.String("config", "/etc/chauth/config.yaml", "path to the config file")
	_ = fs.Parse(args)

	cfg, err := chconfig.Load(*path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	shutdownTelemetry, logs, err := telemetry.Setup(ctx)
	if err != nil {
		return err
	}
	defer shutdownTelemetry()
	log := telemetry.Logger(os.Stdout, logs)

	verifier := token.NewVerifier(cfg.OIDC)
	store, err := rbacStore(cfg, log)
	if err != nil {
		return err
	}
	return runServe(ctx, cfg, verifier, store, log)
}

// runServe serves until ctx ends, then closes both listeners, cuts open connections and drops the
// temp users this process created.
func runServe(ctx context.Context, cfg *chconfig.Config, verifier *token.Verifier, store *rbac.Store, log *slog.Logger) error {
	certs := &certReloader{certFile: cfg.TLS.CertFile, keyFile: cfg.TLS.KeyFile}
	if _, err := certs.get(nil); err != nil {
		return err
	}
	tlsConfig := &tls.Config{GetCertificate: certs.get, MinVersion: tls.VersionTLS12}
	srv, err := chproxy.New(cfg, verifier, store, tlsConfig, log)
	if err != nil {
		return err
	}
	nativeLn, err := net.Listen("tcp", cfg.Listen.Native)
	if err != nil {
		return err
	}
	httpLn, err := net.Listen("tcp", cfg.Listen.HTTP)
	if err != nil {
		nativeLn.Close()
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go verifier.Start(ctx, log)
	go store.WatchDir(ctx, cfg.RBAC.Dir, time.Duration(cfg.RBAC.ReloadInterval))
	srv.Start(ctx)
	if cfg.Listen.Health != "" {
		go serveHealth(ctx, cfg.Listen.Health, srv, store, log)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	hs := srv.NewHTTPServer()
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := hs.ServeTLS(httpLn, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("https: %w", err)
			cancel()
		}
	}()
	go func() {
		defer wg.Done()
		if err := srv.ServeNative(ctx, nativeLn); err != nil {
			errs <- fmt.Errorf("native: %w", err)
			cancel()
		}
	}()
	log.Info("chauth listening", "native", cfg.Listen.Native, "http", cfg.Listen.HTTP, "version", version)
	<-ctx.Done()
	shutdownCtx, done := context.WithTimeout(context.Background(), 30*time.Second)
	defer done()
	_ = hs.Shutdown(shutdownCtx)
	wg.Wait()
	srv.Close(shutdownCtx)
	log.Info("chauth stopped")
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
}

// rbacStore records every load of the access rules as metrics: a counter by result and a gauge
// that is 1 while the last change was rejected.
func rbacStore(cfg *chconfig.Config, log *slog.Logger) (*rbac.Store, error) {
	meter := otel.Meter("github.com/LucStr/chauth/cmd/chauth")
	loads, err := meter.Int64Counter("chauth.rbac.loads", metric.WithDescription("Access-rule loads by result"))
	if err != nil {
		return nil, err
	}
	rejected, err := meter.Int64Gauge("chauth.rbac.rejected", metric.WithDescription("1 while the last access-rule change was rejected"))
	if err != nil {
		return nil, err
	}
	store := rbac.NewStore(cfg.Databases(), cfg.Roles(), log)
	store.OnLoad = func(err error) {
		ctx := context.Background()
		if err != nil {
			loads.Add(ctx, 1, metric.WithAttributes(attribute.String("result", "rejected")))
			rejected.Record(ctx, 1)
			return
		}
		loads.Add(ctx, 1, metric.WithAttributes(attribute.String("result", "ok")))
		rejected.Record(ctx, 0)
	}
	return store, nil
}

func serveHealth(ctx context.Context, addr string, srv *chproxy.Server, store *rbac.Store, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if err := srv.Ready(ctx); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ready")
		if st := store.Status(); st.Rejected != nil {
			fmt.Fprintf(w, "access rules: change rejected at %s, still serving the set loaded at %s:\n%v\n",
				st.RejectedAt.Format(time.RFC3339), st.LoadedAt.Format(time.RFC3339), st.Rejected)
		}
	})
	hs := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = hs.Close()
	}()
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("health server", "error", err)
	}
}

// certReloader rereads the certificate when its file changes, so a renewed certificate needs no restart.
type certReloader struct {
	certFile, keyFile string
	mu                sync.Mutex
	mod               time.Time
	cert              *tls.Certificate
}

func (c *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := os.Stat(c.certFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, err
	}
	if c.cert == nil || !st.ModTime().Equal(c.mod) {
		cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
		if err != nil {
			if c.cert != nil {
				return c.cert, nil
			}
			return nil, err
		}
		c.cert, c.mod = &cert, st.ModTime()
	}
	return c.cert, nil
}
