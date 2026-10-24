package web

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"strconv"
)

const (
	extZipPath  = "downloads/thevault-extension.zip"
	extZipName  = "thevault-extension.zip"
	extHintFile = "vault.json" // read by the popup at first run to suggest the vault address; never trusted without the person's "Continue"
	extMaxFile  = 1 << 20      // manifest.json inside the package is read with this cap
)

// extPackage is the extension zip exactly as it is served: the build's package plus the address hint.
type extPackage struct {
	data     []byte
	sum      string
	version  string
	prefill  bool
	missing  bool // the build has no package (plain `go build`)
	buildErr error
}

// buildExtension copies every entry of the build's zip unchanged and adds vault.json with the address people should
// type. The entry has a fixed timestamp so the same server always serves the same bytes (and the same SHA-256).
func buildExtension(raw []byte, publicURL string) (*extPackage, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("extension package: %w", err)
	}
	var version string
	hasHint := false
	for _, f := range zr.File {
		switch f.Name {
		case "manifest.json":
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("extension manifest: %w", err)
			}
			b, err := io.ReadAll(io.LimitReader(rc, extMaxFile))
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("extension manifest: %w", err)
			}
			var m struct {
				Version string `json:"version"`
			}
			if err := json.Unmarshal(b, &m); err != nil {
				return nil, fmt.Errorf("extension manifest: %w", err)
			}
			version = m.Version
		case extHintFile:
			hasHint = true
		}
	}
	if version == "" {
		return nil, errors.New("extension package has no manifest.json with a version")
	}
	p := &extPackage{version: version}
	if publicURL == "" || hasHint {
		p.data = raw
	} else {
		var out bytes.Buffer
		zw := zip.NewWriter(&out)
		var stamp = zr.File[0].Modified
		for _, f := range zr.File {
			if err := zw.Copy(f); err != nil {
				return nil, fmt.Errorf("extension package: %w", err)
			}
		}
		hint, _ := json.Marshal(map[string]string{"server": publicURL})
		w, err := zw.CreateHeader(&zip.FileHeader{Name: extHintFile, Method: zip.Deflate, Modified: stamp})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(hint); err != nil {
			return nil, err
		}
		if err := zw.Close(); err != nil {
			return nil, err
		}
		p.data, p.prefill = out.Bytes(), true
	}
	sum := sha256.Sum256(p.data)
	p.sum = hex.EncodeToString(sum[:])
	return p, nil
}

func (s *Server) extensionPackage() *extPackage {
	s.extOnce.Do(func() {
		raw := s.ExtensionZip
		if raw == nil {
			b, err := fs.ReadFile(s.static, extZipPath)
			if err != nil {
				s.ext = &extPackage{missing: true}
				return
			}
			raw = b
		}
		// A server whose address is not a clean http(s) origin gets the plain package rather than a wrong hint.
		pub := s.PublicURL
		if u, err := url.Parse(pub); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			pub = ""
		}
		p, err := buildExtension(raw, pub)
		if err != nil {
			log.Printf("web: extension package unusable, download disabled: %v", err)
			s.ext = &extPackage{buildErr: err}
			return
		}
		s.ext = p
	})
	return s.ext
}

func (s *Server) signedIn(w http.ResponseWriter, r *http.Request) bool {
	if s.HasSession == nil || !s.HasSession(r) {
		http.Error(w, "sign in first", http.StatusUnauthorized)
		return false
	}
	return true
}

// extensionInfo tells the settings page whether this build carries the extension and what the download is.
func (s *Server) extensionInfo(w http.ResponseWriter, r *http.Request) {
	if !s.signedIn(w, r) {
		return
	}
	p := s.extensionPackage()
	info := map[string]any{"available": p.data != nil}
	if p.data != nil {
		info["version"], info["size"], info["sha256"], info["filename"], info["prefilled"] = p.version, len(p.data), p.sum, extZipName, p.prefill
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(info)
}

func (s *Server) extensionZip(w http.ResponseWriter, r *http.Request) {
	if !s.signedIn(w, r) {
		return
	}
	p := s.extensionPackage()
	if p.data == nil {
		http.Error(w, "The extension package is not part of this build. Load the extension/ folder unpacked, or run `npm run build:extension`.", http.StatusNotFound)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Disposition", `attachment; filename="`+extZipName+`"`)
	h.Set("Content-Length", strconv.Itoa(len(p.data)))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.Write(p.data)
}
