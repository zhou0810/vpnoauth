package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	qrcode "github.com/skip2/go-qrcode"

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
	tlsCert := flag.String("tls-cert", "", "path to TLS certificate (for self-signed)")
	tlsKey := flag.String("tls-key", "", "path to TLS private key (for self-signed)")
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

	// Web flow: entry point redirects to OAuth with mode=web
	mux.HandleFunc("/web/connect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/auth/login?mode=web", http.StatusFound)
	})

	// Web flow: result page with QR code
	mux.HandleFunc("/web/result", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}

		email, ok := authHandler.ValidateAndConsumeToken(token)
		if !ok {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Generate WireGuard keypair server-side
		privKeyBytes, err := exec.Command("wg", "genkey").Output()
		if err != nil {
			log.Printf("wg genkey failed: %v", err)
			http.Error(w, "failed to generate keypair", http.StatusInternalServerError)
			return
		}
		privKey := strings.TrimSpace(string(privKeyBytes))

		pubKeyCmd := exec.Command("wg", "pubkey")
		pubKeyCmd.Stdin = strings.NewReader(privKey)
		pubKeyBytes, err := pubKeyCmd.Output()
		if err != nil {
			log.Printf("wg pubkey failed: %v", err)
			http.Error(w, "failed to generate keypair", http.StatusInternalServerError)
			return
		}
		pubKey := strings.TrimSpace(string(pubKeyBytes))

		log.Printf("Web flow: registering peer for %s", email)

		peer, err := wgMgr.AddPeer(pubKey, peerTTL)
		if err != nil {
			log.Printf("Failed to add peer: %v", err)
			http.Error(w, "failed to register peer", http.StatusInternalServerError)
			return
		}

		// Build WireGuard config (same format as CLI client)
		clientAddr := strings.Replace(peer.AllowedIP, "/32", "/24", 1)
		wgConf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = %s

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = 25
`, privKey, clientAddr, cfg.WireGuard.DNS, cfg.WireGuard.PublicKey, cfg.WireGuard.Endpoint, cfg.WireGuard.AllowedIPs)

		// Generate QR code
		qrPNG, err := qrcode.Encode(wgConf, qrcode.Medium, 512)
		if err != nil {
			log.Printf("QR code generation failed: %v", err)
			http.Error(w, "failed to generate QR code", http.StatusInternalServerError)
			return
		}
		qrBase64 := base64.StdEncoding.EncodeToString(qrPNG)

		expiryStr := peer.ExpiresAt.Local().Format(time.RFC3339)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, webResultPage, qrBase64, wgConf, expiryStr)
	})

	var server *http.Server

	if *tlsCert != "" && *tlsKey != "" {
		// Self-signed TLS mode
		server = &http.Server{
			Addr:    cfg.ListenAddr,
			Handler: mux,
		}
		log.Printf("Starting server on %s with self-signed TLS", cfg.ListenAddr)
	} else if *devMode {
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

	if *tlsCert != "" && *tlsKey != "" {
		if err := server.ListenAndServeTLS(*tlsCert, *tlsKey); err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	} else if *devMode {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	} else {
		if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}
}

const webResultPage = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VPN Configuration</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; background: #f5f5f5; }
  .card { background: white; border-radius: 12px; padding: 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
  h1 { color: #333; font-size: 1.5em; margin-top: 0; }
  .qr { text-align: center; margin: 20px 0; }
  .qr img { max-width: 100%%; width: 300px; height: 300px; }
  .config { background: #f8f8f8; border: 1px solid #e0e0e0; border-radius: 8px; padding: 16px; font-family: monospace; font-size: 13px; white-space: pre-wrap; word-break: break-all; position: relative; }
  .expiry { color: #666; font-size: 0.9em; margin-top: 16px; }
  .copy-btn { position: absolute; top: 8px; right: 8px; background: #007aff; color: white; border: none; border-radius: 6px; padding: 6px 12px; cursor: pointer; font-size: 13px; }
  .copy-btn:hover { background: #005ec4; }
  .instructions { color: #555; font-size: 0.95em; line-height: 1.5; }
  ol { padding-left: 20px; }
</style>
</head>
<body>
<div class="card">
  <h1>WireGuard VPN Configuration</h1>
  <p class="instructions">Scan this QR code with the WireGuard app:</p>
  <div class="qr"><img src="data:image/png;base64,%s" alt="WireGuard QR Code"></div>
  <ol class="instructions">
    <li>Open the WireGuard app on your device</li>
    <li>Tap <strong>+</strong> then <strong>Create from QR code</strong></li>
    <li>Scan the QR code above</li>
    <li>Name the tunnel and activate it</li>
  </ol>
  <p class="instructions">Or copy the configuration manually:</p>
  <div class="config"><button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('conf').textContent)">Copy</button><span id="conf">%s</span></div>
  <p class="expiry">Expires: %s</p>
</div>
</body>
</html>`

