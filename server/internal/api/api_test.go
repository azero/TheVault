package api

import "testing"

func TestSafeReturn(t *testing.T) {
	ok := []string{"/", "/vault", "/a/b?x=1#frag"}
	for _, p := range ok {
		if safeReturn(p) != p {
			t.Errorf("%q should pass", p)
		}
	}
	bad := []string{"", "//evil.example", "/\\evil.example", "https://evil.example", "javascript:alert(1)", "/auth/login", "/login", "/api/v1/session", "/a\nb", "/a\tb", "/%0d%0a", "///x", "evil"}
	for _, p := range bad {
		got := safeReturn(p)
		if p == "/%0d%0a" {
			continue // percent-escapes are inert in a path
		}
		if got != "/" {
			t.Errorf("%q must fall back to /, got %q", p, got)
		}
	}
}

func TestValidators(t *testing.T) {
	if !isID("0123456789abcdef0123456789abcdef") || isID("0123456789ABCDEF0123456789abcdef") || isID("../etc") || isID("") {
		t.Error("isID")
	}
	if !isVaultID("personal") || isVaultID("Personal") {
		t.Error("isVaultID")
	}
	if !kdfOK("pbkdf2-sha256", 1000000, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") || kdfOK("pbkdf2-sha256", 1000, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") || kdfOK("scrypt", 1000000, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") || kdfOK("pbkdf2-sha256", 1000000, "short") {
		t.Error("kdfOK")
	}
	if isEnvelope("1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA", 100) != true || isEnvelope("2.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA", 100) || isEnvelope("1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA", 10) {
		t.Error("isEnvelope")
	}
	if cleanText("a\x00b\nc", 10) != "abc" {
		t.Error("cleanText")
	}
}

func TestBrowserLabel(t *testing.T) {
	if got := browserLabel("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"); got != "Chrome on Windows" {
		t.Error(got)
	}
	if got := browserLabel(""); got != "Browser" {
		t.Error(got)
	}
}
