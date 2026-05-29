// Command signerd is the CoinDock signer/deriver service.
//
// This build implements Phase 1 of api/03-signer-service-api.md: watch-only
// MLRT deposit-address derivation from an account xpub. It holds NO private
// keys. The /v1/sign endpoint returns 501 until the gated signing phase.
//
// Bind it to a PRIVATE interface only. Configuration is via environment
// variables documented in cmd/signerd/README.md.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/computervirtualservices/malairte/internal/signer"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := signer.LoadConfig()
	if err != nil {
		log.Fatalf("signerd: config error: %v", err)
	}

	svc, err := signer.New(cfg)
	if err != nil {
		log.Fatalf("signerd: init error: %v", err)
	}

	srv := &http.Server{
		Addr:              cfg.BindAddr,
		Handler:           svc.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	idleClosed := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("signerd: graceful shutdown error: %v", err)
		}
		close(idleClosed)
	}()

	log.Printf("signerd: listening on %s (MLRT derive-only; /v1/sign disabled)", cfg.BindAddr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("signerd: server error: %v", err)
	}
	<-idleClosed
	log.Print("signerd: stopped")
}
