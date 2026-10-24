package web

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, name := range []string{"manifest.json", "popup.html", "core/a.js", "vault.json"} {
		body, ok := files[name]
		if !ok {
			continue
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: when})
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func readZip(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name] = string(b)
	}
	return out
}

const manifestJSON = `{"manifest_version":3,"version":"1.4.2"}`

func TestBuildExtensionAddsOnlyTheAddressHint(t *testing.T) {
	raw := makeZip(t, map[string]string{"manifest.json": manifestJSON, "popup.html": "<html>", "core/a.js": "export {}"})
	p, err := buildExtension(raw, "https://vault.example.com")
	if err != nil {
		t.Fatal(err)
	}
	got := readZip(t, p.data)
	if got["vault.json"] != `{"server":"https://vault.example.com"}` || got["popup.html"] != "<html>" || got["core/a.js"] != "export {}" || got["manifest.json"] != manifestJSON || len(got) != 4 {
		t.Fatalf("unexpected package: %v", got)
	}
	sum := sha256.Sum256(p.data)
	if !p.prefill || p.version != "1.4.2" || p.sum != hex.EncodeToString(sum[:]) {
		t.Fatalf("metadata does not describe the served bytes: %+v", p)
	}
	again, _ := buildExtension(raw, "https://vault.example.com")
	if again.sum != p.sum {
		t.Fatal("the same server must always serve the same bytes")
	}
}

func TestBuildExtensionLeavesThePlainPackageAlone(t *testing.T) {
	raw := makeZip(t, map[string]string{"manifest.json": manifestJSON, "popup.html": "<html>"})
	if p, err := buildExtension(raw, ""); err != nil || p.prefill || !bytes.Equal(p.data, raw) {
		t.Fatalf("no address: %v %+v", err, p)
	}
	// a package that already carries a hint is never rewritten
	withHint := makeZip(t, map[string]string{"manifest.json": manifestJSON, "vault.json": `{"server":"https://other.example"}`})
	if p, err := buildExtension(withHint, "https://vault.example.com"); err != nil || p.prefill || !bytes.Equal(p.data, withHint) {
		t.Fatalf("existing hint: %v %+v", err, p)
	}
	for name, bad := range map[string][]byte{"not a zip": []byte("nope"), "no manifest": makeZip(t, map[string]string{"popup.html": "x"}), "no version": makeZip(t, map[string]string{"manifest.json": `{"name":"x"}`}), "bad manifest": makeZip(t, map[string]string{"manifest.json": "{"})} {
		if _, err := buildExtension(bad, "https://vault.example.com"); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func extServer(t *testing.T, signedIn bool, o Options) *httptest.Server {
	t.Helper()
	o.HasSession = func(*http.Request) bool { return signedIn }
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.Routes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func fetch(t *testing.T, url string) (int, http.Header, []byte) {
	t.Helper()
	res, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, b
}

func TestExtensionRoutes(t *testing.T) {
	raw := makeZip(t, map[string]string{"manifest.json": manifestJSON, "popup.html": "<html>"})
	anon := extServer(t, false, Options{ExtensionZip: raw, PublicURL: "https://vault.example.com"})
	for _, p := range []string{"/download/extension.zip", "/download/extension.json"} {
		if st, _, _ := fetch(t, anon.URL+p); st != http.StatusUnauthorized {
			t.Errorf("anonymous %s: %d", p, st)
		}
	}
	// the embedded copy is never reachable as a static file
	if st, _, _ := fetch(t, anon.URL+"/static/downloads/thevault-extension.zip"); st != http.StatusNotFound {
		t.Errorf("static download: %d", st)
	}

	in := extServer(t, true, Options{ExtensionZip: raw, PublicURL: "https://vault.example.com"})
	st, h, body := fetch(t, in.URL+"/download/extension.zip")
	if st != 200 || h.Get("Content-Type") != "application/zip" || h.Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(h.Get("Content-Disposition"), "attachment") || h.Get("Cache-Control") != "no-store" {
		t.Fatalf("zip: %d %v", st, h)
	}
	_, _, js := fetch(t, in.URL+"/download/extension.json")
	var info map[string]any
	if err := json.Unmarshal(js, &info); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if info["available"] != true || info["version"] != "1.4.2" || info["sha256"] != hex.EncodeToString(sum[:]) || int(info["size"].(float64)) != len(body) || info["prefilled"] != true {
		t.Fatalf("info does not describe the download: %v", info)
	}
}

// An unusable package (the same path as a build without one, which cannot be tested once the Docker build embeds a package).
func TestExtensionRoutesWithoutAUsablePackage(t *testing.T) {
	in := extServer(t, true, Options{ExtensionZip: []byte{}})
	st, _, body := fetch(t, in.URL+"/download/extension.zip")
	if st != http.StatusNotFound || !strings.Contains(string(body), "build:extension") {
		t.Fatalf("a build without the package must say what to do: %d %s", st, body)
	}
	_, _, js := fetch(t, in.URL+"/download/extension.json")
	if strings.TrimSpace(string(js)) != `{"available":false}` {
		t.Fatalf("info: %s", js)
	}
}

func TestExtensionIgnoresAnUnusableAddress(t *testing.T) {
	raw := makeZip(t, map[string]string{"manifest.json": manifestJSON})
	for _, pub := range []string{"javascript:alert(1)", "vault.example.com", "ftp://x.example"} {
		in := extServer(t, true, Options{ExtensionZip: raw, PublicURL: pub})
		_, _, body := fetch(t, in.URL+"/download/extension.zip")
		if _, ok := readZip(t, body)["vault.json"]; ok {
			t.Errorf("%q must not become an address hint", pub)
		}
	}
}
