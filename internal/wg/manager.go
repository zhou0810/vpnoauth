package wg

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"
)

type PeerInfo struct {
	PublicKey  string
	AllowedIP string
	ExpiresAt time.Time
}

type Manager struct {
	mu sync.Mutex

	iface      string
	listenPort int
	serverAddr string // e.g. "10.0.0.1/24"
	subnet     *net.IPNet
	nextIP     net.IP

	peers map[string]*PeerInfo // keyed by public key
}

func NewManager(iface string, listenPort int, address string) (*Manager, error) {
	ip, subnet, err := net.ParseCIDR(address)
	if err != nil {
		return nil, fmt.Errorf("parsing address %q: %w", address, err)
	}

	// Start allocating from server IP + 1
	nextIP := make(net.IP, len(ip.To4()))
	copy(nextIP, ip.To4())
	incrementIP(nextIP)

	return &Manager{
		iface:      iface,
		listenPort: listenPort,
		serverAddr: address,
		subnet:     subnet,
		nextIP:     nextIP,
		peers:      make(map[string]*PeerInfo),
	}, nil
}

func (m *Manager) AddPeer(pubkey string, ttl time.Duration) (*PeerInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if peer already exists
	if _, exists := m.peers[pubkey]; exists {
		return nil, fmt.Errorf("peer already registered")
	}

	// Allocate IP
	allocatedIP, err := m.allocateIP()
	if err != nil {
		return nil, err
	}
	allowedIP := allocatedIP + "/32"

	// Add peer via wg command
	if err := m.wgSetPeer(pubkey, allowedIP); err != nil {
		return nil, fmt.Errorf("wg set peer: %w", err)
	}

	peer := &PeerInfo{
		PublicKey:  pubkey,
		AllowedIP: allowedIP,
		ExpiresAt: time.Now().Add(ttl),
	}
	m.peers[pubkey] = peer

	log.Printf("Added peer %s with IP %s, expires at %s", pubkey[:8]+"...", allowedIP, peer.ExpiresAt.Format(time.RFC3339))
	return peer, nil
}

func (m *Manager) RemovePeer(pubkey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.removePeerLocked(pubkey)
}

func (m *Manager) removePeerLocked(pubkey string) error {
	if _, exists := m.peers[pubkey]; !exists {
		return fmt.Errorf("peer not found")
	}

	cmd := exec.Command("wg", "set", m.iface, "peer", pubkey, "remove")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wg remove peer: %s: %w", string(out), err)
	}

	log.Printf("Removed peer %s", pubkey[:8]+"...")
	delete(m.peers, pubkey)
	return nil
}

func (m *Manager) StartCleanup(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.cleanExpired()
		}
	}
}

func (m *Manager) cleanExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for pubkey, peer := range m.peers {
		if now.After(peer.ExpiresAt) {
			log.Printf("Peer %s expired, removing", pubkey[:8]+"...")
			if err := m.removePeerLocked(pubkey); err != nil {
				log.Printf("Error removing expired peer: %v", err)
			}
		}
	}
}

func (m *Manager) allocateIP() (string, error) {
	// Find an unused IP in the subnet
	for i := 0; i < 253; i++ {
		candidate := m.nextIP.String()
		if !m.subnet.Contains(m.nextIP) {
			// Wrapped around, reset
			baseIP := m.subnet.IP.To4()
			m.nextIP = make(net.IP, 4)
			copy(m.nextIP, baseIP)
			incrementIP(m.nextIP)
			candidate = m.nextIP.String()
		}

		// Check if IP is in use
		inUse := false
		for _, peer := range m.peers {
			if peer.AllowedIP == candidate+"/32" {
				inUse = true
				break
			}
		}

		incrementIP(m.nextIP)

		if !inUse {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no available IPs in subnet")
}

func (m *Manager) wgSetPeer(pubkey, allowedIP string) error {
	cmd := exec.Command("wg", "set", m.iface, "peer", pubkey, "allowed-ips", allowedIP)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w", string(out), err)
	}
	return nil
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
