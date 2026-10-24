// Package web serves the pages that are not JSON: the sign-in page, the single-page app shell, static files (CSS, JS
// modules, icons, logo), and the extension download. Everything is embedded in the binary.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
)

//go:embed templates/*.html static
var assets embed.FS

type Options struct {
	Version    string
	HasSession func(*http.Request) bool
	// PublicURL is written into the downloaded extension as a suggested vault address (see extension.go).
	PublicURL string
	// ExtensionZip replaces the package embedded by the Docker build; tests use it.
	ExtensionZip []byte
}

type Server struct {
	Options
	pages  map[string]*template.Template
	static fs.FS
	etags  map[string]string

	extOnce sync.Once
	ext     *extPackage
}

func New(o Options) (*Server, error) {
	s := &Server{Options: o, pages: map[string]*template.Template{}, etags: map[string]string{}}
	entries, err := fs.Glob(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := strings.TrimSuffix(strings.TrimPrefix(e, "templates/"), ".html")
		if name == "base" {
			continue
		}
		t, err := template.ParseFS(assets, "templates/base.html", e)
		if err != nil {
			return nil, err
		}
		s.pages[name] = t
	}
	s.static, _ = fs.Sub(assets, "static")
	// Content hashes for ETags: static files change only with a new binary, so revalidation is a cheap 304.
	fs.WalkDir(s.static, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, err := fs.ReadFile(s.static, p)
		if err == nil {
			h := sha256.Sum256(b)
			s.etags[p] = `"` + hex.EncodeToString(h[:8]) + `"`
		}
		return nil
	})
	return s, nil
}

func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /static/", s.serveStatic)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("GET /{$}", s.shell)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/brand/favicon.png", http.StatusFound)
	})
	mux.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("User-agent: *\nDisallow: /\n"))
	})
	mux.HandleFunc("GET /download/extension.zip", s.extensionZip)
	mux.HandleFunc("GET /download/extension.json", s.extensionInfo)
}

func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/static/")
	etag, ok := s.etags[p]
	if !ok || strings.HasPrefix(p, "downloads/") {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("ETag", etag)
	h.Set("Cache-Control", "no-cache")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	http.ServeFileFS(w, r, s.static, p)
}

type page struct {
	Title, Msg, Version string
	Status              int
}

func (s *Server) render(w http.ResponseWriter, name string, status int, p page) {
	t := s.pages[name]
	if t == nil {
		http.Error(w, "template missing", http.StatusInternalServerError)
		return
	}
	p.Version = s.Version
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := t.ExecuteTemplate(w, "base", p); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

// ErrorPage is handed to the api package for SSO failures.
func (s *Server) ErrorPage(w http.ResponseWriter, status int, msg string) {
	s.render(w, "error", status, page{Title: "Something went wrong", Msg: msg, Status: status})
}

var knownMessages = map[string]bool{
	"Your session ended. Sign in again.":        true,
	"Your access was removed in ClosedDoor.":    true,
	"Too many sign-in attempts. Wait a minute.": true,
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.HasSession != nil && s.HasSession(r) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// Only our own messages: /login?msg=... is a link anyone can craft, and free text on our domain is phishing copy.
	msg := r.URL.Query().Get("msg")
	if !knownMessages[msg] {
		msg = ""
	}
	s.render(w, "login", http.StatusOK, page{Title: "Sign in", Msg: msg})
}

func (s *Server) shell(w http.ResponseWriter, r *http.Request) {
	if s.HasSession == nil || !s.HasSession(r) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.render(w, "app", http.StatusOK, page{Title: "Vault"})
}
