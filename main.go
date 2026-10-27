package main

import (
	"context"
	"embed"
	"flag"
	"io/fs"
	"log"
	"os/signal"
	"syscall"

	"github.com/elliottech/threshold-signature/internal/coordinator"
)

//go:embed static
var staticFS embed.FS

func main() {
	if err := runServer(); err != nil {
		log.Fatal(err)
	}
}

func runServer() error {
	addr := flag.String("addr", "127.0.0.1:9000", "listen address (use a TLS reverse proxy for remote access)")
	dbPath := flag.String("db", "tsig.db", "sqlite database path")
	flag.Parse()
	assets, err := fs.Sub(staticFS, "static")
	if err != nil {
		return err
	}
	server, err := coordinator.New(coordinator.Config{Addr: *addr, DBPath: *dbPath}, assets)
	if err != nil {
		return err
	}
	defer server.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("starting coordinator on %s", *addr)
	return server.Run(ctx)
}
