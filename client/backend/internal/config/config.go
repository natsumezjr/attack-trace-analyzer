package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ClientID      string
	ClientVersion string

	HostID   string
	HostName string

	CenterBaseURL string
	ListenURL     string
	BindAddr      string

	SQLitePath string
	StatePath  string

	AuthDisable     bool
	RegisterDisable bool

	FilebeatEventsJSON string

	FalcoEventsJSON   string
	SuricataEveJSON   string
	SuricataFastLog   string
	SuricataStatsJSON string

	CapFilebeat bool
	CapFalco    bool
	CapSuricata bool
}

func LoadFromEnv() (Config, error) {
	var cfg Config

	cfg.ClientID = strings.TrimSpace(os.Getenv("CLIENT_ID"))
	cfg.ClientVersion = strings.TrimSpace(os.Getenv("CLIENT_VERSION"))
	if cfg.ClientVersion == "" {
		cfg.ClientVersion = "0.1.0"
	}

	cfg.HostID = strings.TrimSpace(os.Getenv("HOST_ID"))
	cfg.HostName = strings.TrimSpace(os.Getenv("HOST_NAME"))

	cfg.CenterBaseURL = strings.TrimSpace(os.Getenv("CENTER_BASE_URL"))
	cfg.ListenURL = strings.TrimSpace(os.Getenv("CLIENT_LISTEN_URL"))
	cfg.BindAddr = strings.TrimSpace(os.Getenv("CLIENT_BIND_ADDR"))
	if cfg.BindAddr == "" {
		cfg.BindAddr = "0.0.0.0:18080"
	}

	cfg.SQLitePath = strings.TrimSpace(os.Getenv("ATA_SQLITE_PATH"))
	if cfg.SQLitePath == "" {
		cfg.SQLitePath = "/var/lib/ata/buffer.sqlite"
	}
	cfg.StatePath = strings.TrimSpace(os.Getenv("ATA_STATE_PATH"))
	if cfg.StatePath == "" {
		cfg.StatePath = "/var/lib/ata/state.json"
	}

	cfg.AuthDisable = parseBool(os.Getenv("CLIENT_AUTH_DISABLE"))
	cfg.RegisterDisable = parseBool(os.Getenv("CLIENT_REGISTER_DISABLE"))

	cfg.FilebeatEventsJSON = strings.TrimSpace(os.Getenv("ATA_FILEBEAT_EVENTS_JSON"))
	cfg.FalcoEventsJSON = strings.TrimSpace(os.Getenv("ATA_FALCO_EVENTS_JSON"))
	cfg.SuricataEveJSON = strings.TrimSpace(os.Getenv("ATA_SURICATA_EVE_JSON"))
	cfg.SuricataFastLog = strings.TrimSpace(os.Getenv("ATA_SURICATA_FAST_LOG"))
	cfg.SuricataStatsJSON = strings.TrimSpace(os.Getenv("ATA_SURICATA_STATS_JSON"))

	cfg.CapFilebeat = cfg.FilebeatEventsJSON != ""
	cfg.CapFalco = cfg.FalcoEventsJSON != ""
	cfg.CapSuricata = cfg.SuricataEveJSON != "" || cfg.SuricataFastLog != "" || cfg.SuricataStatsJSON != ""

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	var missing []string
	if c.ClientID == "" {
		missing = append(missing, "CLIENT_ID")
	}
	if c.HostID == "" {
		missing = append(missing, "HOST_ID")
	}
	if c.HostName == "" {
		missing = append(missing, "HOST_NAME")
	}
	if c.ListenURL == "" {
		missing = append(missing, "CLIENT_LISTEN_URL")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required env: %s", strings.Join(missing, ", "))
	}
	if c.BindAddr == "" {
		return errors.New("CLIENT_BIND_ADDR is empty")
	}
	if !strings.HasPrefix(c.ListenURL, "http://") && !strings.HasPrefix(c.ListenURL, "https://") {
		return fmt.Errorf("CLIENT_LISTEN_URL must start with http:// or https://, got %q", c.ListenURL)
	}
	if c.CenterBaseURL != "" && !strings.HasPrefix(c.CenterBaseURL, "http://") && !strings.HasPrefix(c.CenterBaseURL, "https://") {
		return fmt.Errorf("CENTER_BASE_URL must start with http:// or https://, got %q", c.CenterBaseURL)
	}
	return nil
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}
