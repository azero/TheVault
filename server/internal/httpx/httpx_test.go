package httpx

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.5:4444"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 198.51.100.9")
	if got := ClientIP(r, ""); got != "10.0.0.5" {
		t.Errorf("no trusted header: %s", got)
	}
	if got := ClientIP(r, "X-Forwarded-For"); got != "198.51.100.9" {
		t.Errorf("only the right-most entry is trusted: %s", got)
	}
	r.Header.Set("X-Forwarded-For", "garbage")
	if got := ClientIP(r, "X-Forwarded-For"); got != "10.0.0.5" {
		t.Errorf("garbage header: %s", got)
	}
	r.Header.Set("X-Forwarded-For", "::ffff:203.0.113.5")
	if got := ClientIP(r, "X-Forwarded-For"); got != "203.0.113.5" {
		t.Errorf("mapped IPv4: %s", got)
	}
}
