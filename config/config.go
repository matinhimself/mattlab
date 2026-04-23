package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config is the top-level configuration structure.
type Config struct {
	ListenHost      string     `json:"listen_host"`
	LogLevel        string     `json:"log_level"`
	Inbounds        Inbounds   `json:"inbounds"`
	Outbounds       []Outbound `json:"outbounds"`
	Routes          []Route    `json:"routes"`
	DefaultOutbound string     `json:"default_outbound"`
}

// Inbounds holds configuration for each inbound server.
type Inbounds struct {
	SNIProxy   InboundServer `json:"sni_proxy"`
	HTTPProxy  InboundServer `json:"http_proxy"`
	SOCKS5     InboundServer `json:"socks5"`
	CertServer InboundServer `json:"cert_server"`
}

// InboundServer is a single inbound server configuration.
type InboundServer struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}

// Outbound defines how traffic exits the proxy.
type Outbound struct {
	Tag  string `json:"tag"`
	Type string `json:"type"` // "domain_front", "relay", "direct", "block"

	// domain_front fields
	TargetIP   string `json:"target_ip,omitempty"`
	TargetPort int    `json:"target_port,omitempty"`
	FrontSNI   string `json:"front_sni,omitempty"`

	// relay fields
	ScriptIDs    []string `json:"script_ids,omitempty"`
	AuthKey      string   `json:"auth_key,omitempty"`
	RelayDomain  string   `json:"relay_domain,omitempty"`
	Format       string   `json:"format,omitempty"` // "form" or "json"
	BatchEnabled bool     `json:"batch_enabled,omitempty"`
	H2Enabled    bool     `json:"h2_enabled,omitempty"`
}

// Route maps domain lists to outbound tags.
type Route struct {
	Domains  string `json:"domains"`  // path to .txt file
	Outbound string `json:"outbound"` // tag of an outbound
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfgDir := filepath.Dir(path)
	if err := cfg.Validate(cfgDir); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Validate checks config consistency.
func (c *Config) Validate(cfgDir string) error {
	if c.ListenHost == "" {
		c.ListenHost = "0.0.0.0"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}

	// At least one inbound must be enabled
	anyEnabled := c.Inbounds.SNIProxy.Enabled ||
		c.Inbounds.HTTPProxy.Enabled ||
		c.Inbounds.SOCKS5.Enabled ||
		c.Inbounds.CertServer.Enabled
	if !anyEnabled {
		return fmt.Errorf("at least one inbound must be enabled")
	}

	// Build outbound tag set
	tags := make(map[string]*Outbound)
	for i := range c.Outbounds {
		ob := &c.Outbounds[i]
		if ob.Tag == "" {
			return fmt.Errorf("outbound missing tag")
		}
		if _, exists := tags[ob.Tag]; exists {
			return fmt.Errorf("duplicate outbound tag: %s", ob.Tag)
		}
		tags[ob.Tag] = ob

		switch ob.Type {
		case "domain_front":
			if ob.TargetIP == "" || ob.FrontSNI == "" {
				return fmt.Errorf("domain_front outbound %q requires target_ip and front_sni", ob.Tag)
			}
			if ob.TargetPort == 0 {
				ob.TargetPort = 443
			}
		case "relay":
			if ob.TargetIP == "" || ob.FrontSNI == "" {
				return fmt.Errorf("relay outbound %q requires target_ip and front_sni", ob.Tag)
			}
			if len(ob.ScriptIDs) == 0 {
				return fmt.Errorf("relay outbound %q requires at least one script_id", ob.Tag)
			}
			if ob.TargetPort == 0 {
				ob.TargetPort = 443
			}
			if ob.RelayDomain == "" {
				ob.RelayDomain = "script.google.com"
			}
			if ob.Format == "" {
				ob.Format = "form"
			}
		case "direct", "block":
			// no extra fields needed
		default:
			return fmt.Errorf("unknown outbound type: %s", ob.Type)
		}
	}

	// Validate routes
	for _, r := range c.Routes {
		if _, ok := tags[r.Outbound]; !ok {
			return fmt.Errorf("route references unknown outbound tag: %s", r.Outbound)
		}
		domainPath := filepath.Join(cfgDir, r.Domains)
		if _, err := os.Stat(domainPath); err != nil {
			return fmt.Errorf("route domain file %q not found: %w", r.Domains, err)
		}
	}

	// Validate default_outbound
	if c.DefaultOutbound == "" {
		c.DefaultOutbound = "direct"
	}
	if _, ok := tags[c.DefaultOutbound]; !ok {
		return fmt.Errorf("default_outbound %q not found in outbounds", c.DefaultOutbound)
	}

	return nil
}
