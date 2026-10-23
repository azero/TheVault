// Package config reads the server's settings from environment variables.
// Secrets arrive only via the environment, never a committed file.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DataDir      string
	Listen       string
	PublicURL    string // no trailing slash
	SecureCookie bool

	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string

	// ExtensionIDs are the Chrome extension ids allowed to call the API (CORS) and to start the sign-in flow.
	ExtensionIDs []string

	TrustedIPHeader string // e.g. X-Forwarded-For; only the right-most entry is trusted

	// SkyNet (all optional): events go out, signed block_ip commands come in.
	SkyNetURL         string
	SkyNetKey         string // "<agent id>.<secret>" from a SkyNet enrollment
	SkyNetEnrollToken string // alternative to SkyNetKey: enroll on first start and keep the key under /data/keys
	SkyNetCommandKey  string // base64 Ed25519 public key SkyNet signs commands with (learned automatically when enrolling)
	SkyNetHost        string // the "host" field on events
	ResponseAllowlist string // CIDRs/IPs that SkyNet may never make us block

	// Policy
	AuditRetentionDays int
	MaxItemsPerUser    int
	AllowPlainExport   bool
	UnlockIdleMinutes  int // default idle lock for the server-side unlock grant
}

func (c *Config) SkyNetEnabled() bool {
	return c.SkyNetURL != "" && (c.SkyNetKey != "" || c.SkyNetEnrollToken != "")
}

var extID = regexp.MustCompile(`^[a-p]{32}$`)

// Load builds a Config from getenv (os.Getenv in production).
func Load(getenv func(string) string) (*Config, error) {
	c := &Config{
		DataDir:           orDefault(getenv("VAULT_DATA_DIR"), "/data"),
		Listen:            orDefault(getenv("VAULT_LISTEN"), ":8444"),
		PublicURL:         strings.TrimRight(strings.TrimSpace(getenv("VAULT_PUBLIC_URL")), "/"),
		OIDCIssuer:        strings.TrimRight(strings.TrimSpace(getenv("VAULT_OIDC_ISSUER")), "/"),
		OIDCClientID:      strings.TrimSpace(getenv("VAULT_OIDC_CLIENT_ID")),
		OIDCClientSecret:  getenv("VAULT_OIDC_CLIENT_SECRET"),
		TrustedIPHeader:   strings.TrimSpace(getenv("VAULT_TRUSTED_IP_HEADER")),
		SkyNetURL:         strings.TrimRight(strings.TrimSpace(getenv("VAULT_SKYNET_URL")), "/"),
		SkyNetKey:         strings.TrimSpace(getenv("VAULT_SKYNET_KEY")),
		SkyNetEnrollToken: strings.TrimSpace(getenv("VAULT_SKYNET_ENROLL_TOKEN")),
		SkyNetCommandKey:  strings.TrimSpace(getenv("VAULT_SKYNET_COMMAND_PUBKEY")),
		SkyNetHost:        strings.TrimSpace(getenv("VAULT_SKYNET_HOST")),
		ResponseAllowlist: strings.TrimSpace(getenv("VAULT_RESPONSE_ALLOWLIST")),
	}
	for _, id := range strings.Split(getenv("VAULT_EXTENSION_IDS"), ",") {
		if id = strings.TrimSpace(id); id == "" {
			continue
		}
		if !extID.MatchString(id) {
			return nil, fmt.Errorf("VAULT_EXTENSION_IDS: %q is not a Chrome extension id (32 letters a-p)", id)
		}
		c.ExtensionIDs = append(c.ExtensionIDs, id)
	}
	var err error
	if c.AuditRetentionDays, err = intEnv(getenv, "VAULT_AUDIT_RETENTION_DAYS", 365, 30, 3650); err != nil {
		return nil, err
	}
	if c.MaxItemsPerUser, err = intEnv(getenv, "VAULT_MAX_ITEMS_PER_USER", 20000, 100, 1000000); err != nil {
		return nil, err
	}
	if c.UnlockIdleMinutes, err = intEnv(getenv, "VAULT_UNLOCK_IDLE_MINUTES", 15, 1, 480); err != nil {
		return nil, err
	}
	c.AllowPlainExport = getenv("VAULT_DISABLE_PLAIN_EXPORT") != "1"

	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.Path != "" {
		return nil, errors.New("VAULT_PUBLIC_URL must be an absolute origin such as https://vault.example.com")
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return nil, errors.New("VAULT_PUBLIC_URL must be https (http is allowed only for localhost)")
	}
	c.SecureCookie = u.Scheme == "https"

	if c.OIDCIssuer == "" || c.OIDCClientID == "" || c.OIDCClientSecret == "" {
		return nil, errors.New("VAULT_OIDC_ISSUER, VAULT_OIDC_CLIENT_ID and VAULT_OIDC_CLIENT_SECRET are all required: sign-in is through ClosedDoor")
	}
	if iu, err := url.Parse(c.OIDCIssuer); err != nil || iu.Host == "" || (iu.Scheme != "https" && !(iu.Scheme == "http" && isLoopback(iu.Hostname()))) {
		return nil, errors.New("VAULT_OIDC_ISSUER must be an https URL")
	}
	if c.SkyNetURL != "" {
		su, err := url.Parse(c.SkyNetURL)
		if err != nil || su.Host == "" || (su.Scheme != "https" && !(su.Scheme == "http" && isLoopback(su.Hostname()))) {
			return nil, errors.New("VAULT_SKYNET_URL must be an https URL")
		}
		if c.SkyNetKey == "" && c.SkyNetEnrollToken == "" && !hasKeyFile(c.DataDir) {
			return nil, errors.New("VAULT_SKYNET_URL needs VAULT_SKYNET_KEY or a one-time VAULT_SKYNET_ENROLL_TOKEN")
		}
	}
	if c.SkyNetHost == "" {
		c.SkyNetHost = "thevault"
	}
	if c.SkyNetKey != "" && !strings.Contains(c.SkyNetKey, ".") {
		return nil, errors.New("VAULT_SKYNET_KEY must look like <agent id>.<secret>")
	}
	return c, nil
}

func hasKeyFile(dataDir string) bool {
	_, err := os.Stat(dataDir + "/keys/skynet.json")
	return err == nil
}

// UnlockIdle is the default sliding idle timeout of an unlocked session.
func (c *Config) UnlockIdle() time.Duration { return time.Duration(c.UnlockIdleMinutes) * time.Minute }

func orDefault(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}

func IsLoopbackHost(h string) bool { return isLoopback(h) }

func isLoopback(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func intEnv(getenv func(string) string, key string, def, min, max int) (int, error) {
	v := strings.TrimSpace(getenv(key))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%s must be a number between %d and %d", key, min, max)
	}
	return n, nil
}
