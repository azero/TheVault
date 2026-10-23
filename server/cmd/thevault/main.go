// Command thevault is the TheVault server: `thevault serve` plus small admin helpers.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/azero/thevault/server/internal/app"
	"github.com/azero/thevault/server/internal/config"
	"github.com/azero/thevault/server/internal/store"
)

var version = "dev"

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "healthcheck":
		err = healthcheck()
	case "backup":
		err = backup()
	case "version", "-v", "--version":
		fmt.Println("thevault", version)
	default:
		fmt.Fprintf(os.Stderr, "usage: thevault [serve|healthcheck|backup|version]\n")
		os.Exit(2)
	}
	if err != nil {
		log.Fatalf("thevault %s: %v", cmd, err)
	}
}

func serve() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	a, err := app.New(cfg, st, version)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           a.Handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       90 * time.Second, // imports and key rotations upload several MB of ciphertext
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go a.Run(ctx)
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	if cfg.TrustedIPHeader == "" && strings.HasPrefix(cfg.PublicURL, "https://") {
		log.Printf("warning: VAULT_PUBLIC_URL is https but VAULT_TRUSTED_IP_HEADER is empty; behind a reverse proxy every client will look like the proxy (rate limits, audit and SkyNet will see one address)")
	}
	log.Printf("thevault %s listening on %s, data in %s, skynet=%v extensions=%d", version, cfg.Listen, cfg.DataDir, a.Sky != nil, len(cfg.ExtensionIDs))
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

func healthcheck() error {
	listen := os.Getenv("VAULT_LISTEN")
	if listen == "" {
		listen = ":8444"
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	c := http.Client{Timeout: 4 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func backup() error {
	dir := os.Getenv("VAULT_DATA_DIR")
	if dir == "" {
		dir = "/data"
	}
	st, err := store.Open(dir)
	if err != nil {
		return err
	}
	defer st.Close()
	p, err := st.Backup(context.Background())
	if err != nil {
		return err
	}
	fmt.Println("wrote", p)
	return nil
}
