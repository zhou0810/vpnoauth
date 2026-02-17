//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

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

	confPath := fmt.Sprintf("/etc/wireguard/%s.conf", wgInterface)
	if err := os.WriteFile(confPath, []byte(wgConf), 0600); err != nil {
		return fmt.Errorf("failed to write WireGuard config (try running with sudo): %w", err)
	}
	fmt.Printf("Wrote WireGuard config to %s\n", confPath)

	cmd := exec.Command("wg-quick", "up", wgInterface)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring up WireGuard interface: %w", err)
	}
	return nil
}

func teardownTunnel() error {
	cmd := exec.Command("wg-quick", "down", wgInterface)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring down WireGuard interface: %w", err)
	}

	confPath := fmt.Sprintf("/etc/wireguard/%s.conf", wgInterface)
	os.Remove(confPath)
	return nil
}
