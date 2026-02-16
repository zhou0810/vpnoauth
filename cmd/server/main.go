package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/acme/autocert"

	"github.com/jzhou/vpnoauth/internal/auth"
	"github.com/jzhou/vpnoauth/internal/config"
	"github.com/jzhou/vpnoauth/internal/wg"
)

type registerRequest struct {
	Token  string `json:"token"`
	PubKey string `json:"pubkey"`
}

type registerResponse struct {
	ServerPubKey string `json:"server_pubkey"`
	Endpoint     string `json:"endpoint"`
	AllowedIPs   string `json:"allowed_ips"`
	DNS          string `json:"dns"`
	ClientIP     string `json:"client_ip"`
	Expiry       string `json:"expiry"`
}

func main() {
	configPath := flag.String("config", "server.yaml", "path to server config")
	devMode := flag.Bool("dev", false, "run in dev mode (self-signed TLS)")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	peerTTL, err := cfg.WireGuard.ParsePeerTTL()
	if err != nil {
		log.Fatalf("Invalid peer_ttl: %v", err)
	}

	// Initialize WireGuard manager
	wgMgr, err := wg.NewManager(cfg.WireGuard.Interface, cfg.WireGuard.ListenPort, cfg.WireGuard.Address)
	if err != nil {
		log.Fatalf("Failed to initialize WireGuard manager: %v", err)
	}

	// Initialize auth handler
	authHandler := auth.NewHandler(
		cfg.Google.ClientID,
		cfg.Google.ClientSecret,
		cfg.Google.AllowedDomain,
		cfg.Domain,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go wgMgr.StartCleanup(ctx)
	go authHandler.StartCleanup(ctx.Done())

	// Routes
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", authHandler.HandleLogin)
	mux.HandleFunc("/auth/callback", authHandler.HandleCallback)
	mux.HandleFunc("/api/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req registerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if req.Token == "" || req.PubKey == "" {
			http.Error(w, "missing token or pubkey", http.StatusBadRequest)
			return
		}

		// Validate one-time token
		email, ok := authHandler.ValidateAndConsumeToken(req.Token)
		if !ok {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		log.Printf("Registering peer for %s", email)

		// Add WireGuard peer
		peer, err := wgMgr.AddPeer(req.PubKey, peerTTL)
		if err != nil {
			log.Printf("Failed to add peer: %v", err)
			http.Error(w, "failed to register peer", http.StatusInternalServerError)
			return
		}

		resp := registerResponse{
			ServerPubKey: cfg.WireGuard.PublicKey,
			Endpoint:     cfg.WireGuard.Endpoint,
			AllowedIPs:   cfg.WireGuard.AllowedIPs,
			DNS:          cfg.WireGuard.DNS,
			ClientIP:     peer.AllowedIP, // includes /32
			Expiry:       peer.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// Health check
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	var server *http.Server

	if *devMode {
		// Dev mode: plain HTTP
		server = &http.Server{
			Addr:    cfg.ListenAddr,
			Handler: mux,
		}
		log.Printf("Starting server in dev mode on %s", cfg.ListenAddr)
	} else {
		// Production: autocert TLS
		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.Domain),
			Cache:      autocert.DirCache("/var/lib/vpnoauth/certs"),
		}

		server = &http.Server{
			Addr:    cfg.ListenAddr,
			Handler: mux,
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
			},
		}

		// Start HTTP-01 challenge listener
		go http.ListenAndServe(":80", certManager.HTTPHandler(nil))

		log.Printf("Starting server on %s with TLS for %s", cfg.ListenAddr, cfg.Domain)
	}

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		log.Println("Shutting down...")
		cancel()
		server.Shutdown(context.Background())
	}()

	if *devMode {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	} else {
		if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}
}
