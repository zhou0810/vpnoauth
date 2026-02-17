package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const wgInterface = "vpnoauth"

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
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <connect|disconnect> [options]\n", os.Args[0])
		os.Exit(1)
	}

	switch os.Args[1] {
	case "connect":
		if len(os.Args) < 4 || os.Args[2] != "--server" {
			fmt.Fprintf(os.Stderr, "Usage: %s connect --server <host> [--insecure]\n", os.Args[0])
			os.Exit(1)
		}
		server := os.Args[3]
		insecure := len(os.Args) > 4 && os.Args[4] == "--insecure"
		connect(server, insecure)
	case "disconnect":
		disconnect()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func connect(server string, insecure bool) {
	// Generate WireGuard keypair
	privKey, pubKey, err := generateKeypair()
	if err != nil {
		log.Fatalf("Failed to generate WireGuard keypair: %v", err)
	}
	log.Printf("Generated ephemeral WireGuard keypair")

	// Start local callback server
	tokenCh := make(chan string, 1)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to start local callback server: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	callbackSrv := &http.Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "missing token", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body><h2>Authentication successful!</h2><p>You can close this window. The VPN is being configured...</p></body></html>")
		tokenCh <- token
	})
	callbackSrv.Handler = mux

	go callbackSrv.Serve(listener)
	defer callbackSrv.Shutdown(context.Background())

	// Open browser
	loginURL := fmt.Sprintf("https://%s/auth/login?redirect_port=%d", server, port)
	log.Printf("Opening browser for authentication...")
	if !openBrowser(loginURL) {
		log.Printf("Failed to open browser automatically.")
	}
	log.Printf("If the browser didn't open, visit:\n  %s", loginURL)

	// Wait for token
	log.Printf("Waiting for authentication...")
	var token string
	select {
	case token = <-tokenCh:
		log.Printf("Received auth token")
	case <-time.After(5 * time.Minute):
		log.Fatalf("Authentication timed out")
	}

	// Register with server
	log.Printf("Registering WireGuard peer with server...")
	regResp, err := registerPeer(server, token, pubKey, insecure)
	if err != nil {
		log.Fatalf("Failed to register peer: %v", err)
	}

	// Parse client IP (remove /32 suffix for interface address, use /32 as-is for routing)
	clientAddr := strings.Replace(regResp.ClientIP, "/32", "/24", 1)

	// Write WireGuard config
	wgConf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = %s

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = 25
`, privKey, clientAddr, regResp.DNS, regResp.ServerPubKey, regResp.Endpoint, regResp.AllowedIPs)

	confPath := fmt.Sprintf("/etc/wireguard/%s.conf", wgInterface)
	if err := os.WriteFile(confPath, []byte(wgConf), 0600); err != nil {
		log.Fatalf("Failed to write WireGuard config (try running with sudo): %v", err)
	}
	log.Printf("Wrote WireGuard config to %s", confPath)

	// Bring up interface
	cmd := exec.Command("wg-quick", "up", wgInterface)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to bring up WireGuard interface: %v", err)
	}

	expiry, _ := time.Parse(time.RFC3339, regResp.Expiry)
	log.Printf("VPN connected! Interface: %s, Expires: %s", wgInterface, expiry.Local().Format("2006-01-02 15:04:05"))
}

func disconnect() {
	cmd := exec.Command("wg-quick", "down", wgInterface)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to bring down WireGuard interface: %v", err)
	}
	log.Printf("VPN disconnected")

	// Clean up config
	confPath := fmt.Sprintf("/etc/wireguard/%s.conf", wgInterface)
	os.Remove(confPath)
}

func openBrowser(url string) bool {
	// When running under sudo, xdg-open as root won't have a display session.
	// Try running as the original user instead.
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		cmd := exec.Command("sudo", "-u", sudoUser, "xdg-open", url)
		if err := cmd.Start(); err == nil {
			return true
		}
	}
	if err := exec.Command("xdg-open", url).Start(); err == nil {
		return true
	}
	return false
}

func generateKeypair() (privKey, pubKey string, err error) {
	privKeyBytes, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", "", fmt.Errorf("wg genkey: %w", err)
	}
	privKey = strings.TrimSpace(string(privKeyBytes))

	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privKey)
	pubKeyBytes, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("wg pubkey: %w", err)
	}
	pubKey = strings.TrimSpace(string(pubKeyBytes))

	return privKey, pubKey, nil
}

func registerPeer(server, token, pubKey string, insecure bool) (*registerResponse, error) {
	reqBody, err := json.Marshal(registerRequest{
		Token:  token,
		PubKey: pubKey,
	})
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://%s/api/register", server)

	client := &http.Client{Timeout: 10 * time.Second}
	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := client.Post(url, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var body bytes.Buffer
		body.ReadFrom(resp.Body)
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, body.String())
	}

	var regResp registerResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	return &regResp, nil
}
