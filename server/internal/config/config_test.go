package config

import (
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func base() map[string]string {
	return map[string]string{
		"VAULT_PUBLIC_URL": "https://vault.example.com", "VAULT_OIDC_ISSUER": "https://sso.example.com",
		"VAULT_OIDC_CLIENT_ID": "app_x", "VAULT_OIDC_CLIENT_SECRET": "cds_x",
	}
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(base()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8444" || c.DataDir != "/data" || !c.SecureCookie || c.UnlockIdleMinutes != 15 || c.SkyNetEnabled() || !c.AllowPlainExport {
		t.Fatalf("unexpected defaults: %+v", c)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]func(m map[string]string){
		"http public url":    func(m map[string]string) { m["VAULT_PUBLIC_URL"] = "http://vault.example.com" },
		"path in public url": func(m map[string]string) { m["VAULT_PUBLIC_URL"] = "https://vault.example.com/app" },
		"missing oidc":       func(m map[string]string) { delete(m, "VAULT_OIDC_CLIENT_SECRET") },
		"http issuer":        func(m map[string]string) { m["VAULT_OIDC_ISSUER"] = "http://sso.example.com" },
		"bad extension id":   func(m map[string]string) { m["VAULT_EXTENSION_IDS"] = "not-an-id" },
		"skynet without key": func(m map[string]string) { m["VAULT_SKYNET_URL"] = "https://skynet.example.com" },
		"skynet plain http": func(m map[string]string) {
			m["VAULT_SKYNET_URL"] = "http://skynet.example.com"
			m["VAULT_SKYNET_KEY"] = "a.b"
		},
		"skynet malformed key": func(m map[string]string) {
			m["VAULT_SKYNET_URL"] = "https://s.example.com"
			m["VAULT_SKYNET_KEY"] = "nodot"
		},
		"idle out of range":  func(m map[string]string) { m["VAULT_UNLOCK_IDLE_MINUTES"] = "0" },
		"api flag garbage":   func(m map[string]string) { m["VAULT_API_ENABLED"] = "maybe" },
		"api cache too big":  func(m map[string]string) { m["VAULT_API_CACHE_SECONDS"] = "301" },
		"api cache negative": func(m map[string]string) { m["VAULT_API_CACHE_SECONDS"] = "-1" },
		"api rate zero":      func(m map[string]string) { m["VAULT_API_RATE_PER_MINUTE"] = "0" },
		"api without client": func(m map[string]string) {
			m["VAULT_API_ENABLED"] = "true"
			delete(m, "VAULT_OIDC_CLIENT_SECRET")
		},
	}
	for name, mut := range cases {
		m := base()
		mut(m)
		if _, err := Load(env(m)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLoopbackAllowed(t *testing.T) {
	m := base()
	m["VAULT_PUBLIC_URL"] = "http://localhost:8444"
	m["VAULT_OIDC_ISSUER"] = "http://127.0.0.1:9000"
	c, err := Load(env(m))
	if err != nil || c.SecureCookie {
		t.Fatalf("loopback http should be allowed without secure cookies: %v", err)
	}
}

func TestExtensionIDs(t *testing.T) {
	m := base()
	m["VAULT_EXTENSION_IDS"] = " abcdefghijklmnopabcdefghijklmnop , ,"
	c, err := Load(env(m))
	if err != nil || len(c.ExtensionIDs) != 1 || strings.Contains(c.ExtensionIDs[0], " ") {
		t.Fatalf("%v %v", c, err)
	}
}

func TestAutomationAPISettings(t *testing.T) {
	c, err := Load(env(base()))
	if err != nil || c.APIEnabled || c.APICacheSeconds != 0 || c.APIRatePerMinute != 120 {
		t.Fatalf("defaults: off, no cache, 120/min: %+v %v", c, err)
	}
	m := base()
	m["VAULT_API_ENABLED"] = "TRUE"
	m["VAULT_API_CACHE_SECONDS"] = "20"
	m["VAULT_API_RATE_PER_MINUTE"] = "30"
	c, err = Load(env(m))
	if err != nil || !c.APIEnabled || c.APICacheSeconds != 20 || c.APIRatePerMinute != 30 {
		t.Fatalf("%+v %v", c, err)
	}
	m["VAULT_API_ENABLED"] = "0"
	if c, err = Load(env(m)); err != nil || c.APIEnabled {
		t.Fatalf("0 must switch it off: %+v %v", c, err)
	}
}
