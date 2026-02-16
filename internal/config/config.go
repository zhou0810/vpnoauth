package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Domain     string          `yaml:"domain"`
	ListenAddr string          `yaml:"listen_addr"`
	Google     GoogleConfig    `yaml:"google"`
	WireGuard  WireGuardConfig `yaml:"wireguard"`
}

type GoogleConfig struct {
	ClientID      string `yaml:"client_id"`
	ClientSecret  string `yaml:"client_secret"`
	AllowedDomain string `yaml:"allowed_domain"`
}

type WireGuardConfig struct {
	Interface  string `yaml:"interface"`
	Address    string `yaml:"address"`
	ListenPort int    `yaml:"listen_port"`
	PrivateKey string `yaml:"private_key"`
	PublicKey  string `yaml:"public_key"`
	Endpoint   string `yaml:"endpoint"`
	DNS        string `yaml:"dns"`
	PeerTTL    string `yaml:"peer_ttl"`
	AllowedIPs string `yaml:"allowed_ips"`
}

func (c *WireGuardConfig) ParsePeerTTL() (time.Duration, error) {
	return time.ParseDuration(c.PeerTTL)
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg ServerConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}
