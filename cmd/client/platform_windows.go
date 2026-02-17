//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const wireguardDir = `C:\Program Files\WireGuard`

func wgExePath() string {
	return filepath.Join(wireguardDir, "wg.exe")
}

func wireguardExePath() string {
	return filepath.Join(wireguardDir, "wireguard.exe")
}

func openBrowser(url string) bool {
	if err := exec.Command("cmd", "/c", "start", url).Start(); err == nil {
		return true
	}
	return false
}

func generateKeypair() (privKey, pubKey string, err error) {
	wg := wgExePath()

	privKeyBytes, err := exec.Command(wg, "genkey").Output()
	if err != nil {
		return "", "", fmt.Errorf("wg genkey: %w", err)
	}
	privKey = strings.TrimSpace(string(privKeyBytes))

	cmd := exec.Command(wg, "pubkey")
	cmd.Stdin = strings.NewReader(privKey)
	pubKeyBytes, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("wg pubkey: %w", err)
	}
	pubKey = strings.TrimSpace(string(pubKeyBytes))

	return privKey, pubKey, nil
}

func setupTunnel(privKey, clientAddr, dns, serverPubKey, endpoint, allowedIPs string) error {
	wgConf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = %s

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = 25
`, privKey, clientAddr, dns, serverPubKey, endpoint, allowedIPs)

	confDir := os.TempDir()
	confPath := filepath.Join(confDir, wgInterface+".conf")
	if err := os.WriteFile(confPath, []byte(wgConf), 0600); err != nil {
		return fmt.Errorf("failed to write WireGuard config: %w", err)
	}
	fmt.Printf("Wrote WireGuard config to %s\n", confPath)

	cmd := exec.Command(wireguardExePath(), "/installtunnelservice", confPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install WireGuard tunnel service: %w", err)
	}
	return nil
}

func teardownTunnel() error {
	cmd := exec.Command(wireguardExePath(), "/uninstalltunnelservice", wgInterface)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to uninstall WireGuard tunnel service: %w", err)
	}
	return nil
}
