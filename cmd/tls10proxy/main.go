package main

import (
	"net/http"
	"time"

	"tls10proxy/internal/ca"
	"tls10proxy/internal/config"
	"tls10proxy/internal/handler"
	"tls10proxy/internal/logger"
)

func main() {
	var err error
	caCert, caKey, err := ca.Init()
	if err != nil {
		logger.Fatal(err)
	}

	cfg := config.LoadConfig()

	h, err := handler.NewProxyHandler(cfg, caCert, caKey)
	if err != nil {
		logger.Fatal(err)
	}

	server := &http.Server{
		Addr:              cfg.BindAddress,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	logger.Infof("Proxy server running on %s\n", cfg.BindAddress)

	if err = server.ListenAndServe(); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}
