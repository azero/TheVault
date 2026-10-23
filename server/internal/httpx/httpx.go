// Package httpx holds small HTTP helpers shared by the API and the web UI.
package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
)

// ClientIP returns the peer address, or the right-most entry of trustedHeader when the deployment sits behind a
// proxy that sets it. Only the right-most entry is trusted: anything to its left is client-controlled.
func ClientIP(r *http.Request, trustedHeader string) string {
	if trustedHeader != "" {
		if v := r.Header.Get(trustedHeader); v != "" {
			parts := strings.Split(v, ",")
			ip := strings.TrimSpace(parts[len(parts)-1])
			if net.ParseIP(ip) != nil {
				return NormalizeIP(ip)
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return NormalizeIP(host)
}

// NormalizeIP maps IPv4-mapped IPv6 (::ffff:1.2.3.4) to plain IPv4 so deny lists and rate limits agree.
func NormalizeIP(s string) string {
	ip := net.ParseIP(s)
	if ip == nil {
		return s
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func Error(w http.ResponseWriter, status int, code, msg string) {
	JSON(w, status, map[string]string{"error": code, "message": msg})
}

// Decode reads a small JSON body (strict content type, bounded size, unknown fields rejected).
func Decode(w http.ResponseWriter, r *http.Request, v any, max int64) error {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	if strings.TrimSpace(strings.ToLower(ct)) != "application/json" {
		return errors.New("content type must be application/json")
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid request body")
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("invalid request body")
	}
	return nil
}

// CSP is the policy every HTML response carries. form-action is deliberately absent: Chrome would block the
// post-logout redirect to the SSO if it were set. require-trusted-types-for makes innerHTML-style sinks throw, which
// is a second wall behind our "never build HTML from strings" rule.
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; manifest-src 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'; object-src 'none'; require-trusted-types-for 'script'"

// SecureHeaders applies the response headers every page gets.
func SecureHeaders(secure bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", CSP)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-write=(self)")
		if secure {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
