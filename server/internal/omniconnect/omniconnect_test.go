// Vendored from OmniCore reference/go/omniconnect; change upstream, not here.

package omniconnect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type vectors struct {
	Secret string `json:"secret"`
	Cases  []struct {
		Name      string `json:"name"`
		KeyID     string `json:"key_id"`
		Method    string `json:"method"`
		Target    string `json:"target"`
		Nonce     string `json:"nonce"`
		User      string `json:"user"`
		Canonical string `json:"canonical"`
		Signature string `json:"signature"`
		Timestamp int64  `json:"timestamp"`
	} `json:"cases"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/testvectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// The vectors were produced by an independent (Python) implementation: every port must reproduce them.
func TestVectors(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Cases {
		canon := Canonical(c.Method, c.Target, c.Timestamp, c.Nonce, c.User, EmptyBodySHA256)
		if canon != c.Canonical {
			t.Fatalf("%s: canonical\n got %q\nwant %q", c.Name, canon, c.Canonical)
		}
		if sig := Signature([]byte(v.Secret), canon); sig != c.Signature {
			t.Fatalf("%s: signature %s want %s", c.Name, sig, c.Signature)
		}
		req := httptest.NewRequest(c.Method, c.Target, nil)
		req.Header.Set(HeaderKey, c.KeyID)
		req.Header.Set(HeaderTimestamp, itoa(c.Timestamp))
		req.Header.Set(HeaderNonce, c.Nonce)
		if c.User != "" {
			req.Header.Set(HeaderUser, c.User)
		}
		req.Header.Set(HeaderSignature, c.Signature)
		ver := NewVerifier(Key{ID: c.KeyID, Secret: []byte(v.Secret)})
		ver.SetClock(func() time.Time { return time.Unix(c.Timestamp+5, 0) })
		got, err := ver.Verify(req)
		if err != nil || got != c.User {
			t.Fatalf("%s: verify = %q, %v", c.Name, got, err)
		}
		// the same request again is a replay
		if _, err := ver.Verify(req); err == nil {
			t.Fatalf("%s: replay accepted", c.Name)
		}
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func signed(t *testing.T, k Key, target, user string, now time.Time) *http.Request {
	t.Helper()
	req := httptest.NewRequest("GET", target, nil)
	SignRequest(k, req, user, now)
	return req
}

func TestVerifyRejects(t *testing.T) {
	k := Key{ID: "k1", Secret: []byte("0123456789abcdef0123")}
	now := time.Unix(1_800_000_000, 0)
	ver := NewVerifier(k)
	ver.SetClock(func() time.Time { return now })
	good := func() *http.Request { return signed(t, k, Prefix+"/widgets/x?cfg.a=1", "u1", now) }

	if _, err := ver.Verify(good()); err != nil {
		t.Fatal(err)
	}
	mut := map[string]func(r *http.Request){
		"wrong key id":    func(r *http.Request) { r.Header.Set(HeaderKey, "other") },
		"tampered query":  func(r *http.Request) { r.URL.RawQuery = "cfg.a=2" },
		"tampered path":   func(r *http.Request) { r.URL.Path = Prefix + "/widgets/y" },
		"swapped user":    func(r *http.Request) { r.Header.Set(HeaderUser, "u2") },
		"dropped user":    func(r *http.Request) { r.Header.Del(HeaderUser) },
		"bad signature":   func(r *http.Request) { r.Header.Set(HeaderSignature, "v1="+strings.Repeat("0", 64)) },
		"no signature":    func(r *http.Request) { r.Header.Del(HeaderSignature) },
		"stale":           func(r *http.Request) { r.Header.Set(HeaderTimestamp, itoa(now.Add(-3*time.Minute).Unix())) },
		"future":          func(r *http.Request) { r.Header.Set(HeaderTimestamp, itoa(now.Add(3*time.Minute).Unix())) },
		"short nonce":     func(r *http.Request) { r.Header.Set(HeaderNonce, "abc") },
		"POST":            func(r *http.Request) { r.Method = "POST" },
		"hostile user":    func(r *http.Request) { r.Header.Set(HeaderUser, "u1\r\nX: y") },
		"empty timestamp": func(r *http.Request) { r.Header.Set(HeaderTimestamp, "") },
	}
	for name, f := range mut {
		r := good()
		f(r)
		if _, err := ver.Verify(r); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A request that fails the signature must not burn its nonce.
	r := good()
	nonce := r.Header.Get(HeaderNonce)
	r.Header.Set(HeaderSignature, "v1="+strings.Repeat("1", 64))
	_, _ = ver.Verify(r)
	if len(ver.nonce) != 1 { // only the first good() call
		t.Errorf("nonce table has %d entries (nonce %s)", len(ver.nonce), nonce)
	}
	// short secrets are never accepted as keys
	if _, err := NewVerifier(Key{ID: "k", Secret: []byte("short")}).Verify(signed(t, Key{ID: "k", Secret: []byte("short")}, Prefix+"/manifest", "", now)); err == nil {
		t.Error("short secret accepted")
	}
}

type fake struct{}

func (fake) Manifest() Manifest {
	return Manifest{App: AppInfo{ID: "fake", Name: "Fake", PublicURL: "https://fake.example.com", Version: "1.0"},
		Widgets: []WidgetSpec{{ID: "n", Title: "N", Kind: KindStat, Default: Size{3, 2}}, {ID: "boom", Title: "B", Kind: KindStat, Default: Size{3, 2}}, {ID: "away", Title: "A", Kind: KindStat, Default: Size{3, 2}}}}
}

func (fake) Widget(_ context.Context, u User, id string, cfg map[string]string) (Widget, error) {
	switch id {
	case "boom":
		return Widget{}, os.ErrDeadlineExceeded
	case "away":
		return Widget{}, ErrNotLinked
	}
	return Widget{Kind: KindStat, Title: "Hi " + u.Sub, Value: cfg["n"], Link: "javascript:alert(1)", Tone: "weird"}, nil
}

func (fake) Search(_ context.Context, u User, q string) ([]SearchResult, error) {
	return []SearchResult{{Title: q, Link: "/x"}}, nil
}

func TestHandler(t *testing.T) {
	k := Key{ID: "k1", Secret: []byte("0123456789abcdef0123")}
	var denied []string
	mux := http.NewServeMux()
	Mount(mux, fake{}, NewVerifier(k), Hooks{Denied: func(_ *http.Request, reason string) { denied = append(denied, reason) }})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	do := func(target, user string, sign bool) (int, map[string]any) {
		req, _ := http.NewRequest("GET", srv.URL+target, nil)
		if sign {
			SignRequest(k, req, user, time.Now())
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", target, res.Header.Get("Cache-Control"))
		}
		var m map[string]any
		_ = json.NewDecoder(res.Body).Decode(&m)
		return res.StatusCode, m
	}
	if c, m := do(Prefix+"/manifest", "", true); c != 200 || m["protocol"].(float64) != 1 {
		t.Fatalf("manifest %d %v", c, m)
	}
	if c, _ := do(Prefix+"/manifest", "", false); c != 401 {
		t.Fatalf("unsigned manifest %d", c)
	}
	c, m := do(Prefix+"/widgets/n?cfg.n=7&other=1", "u1", true)
	if c != 200 || m["title"] != "Hi u1" || m["value"] != "7" {
		t.Fatalf("widget %d %v", c, m)
	}
	if _, has := m["link"]; has {
		t.Error("javascript: link survived sanitising")
	}
	if _, has := m["tone"]; has {
		t.Error("unknown tone survived sanitising")
	}
	if c, _ := do(Prefix+"/widgets/n", "", true); c != 401 {
		t.Errorf("widget without user: %d", c) // widgets always need a person
	}
	if c, m := do(Prefix+"/widgets/away", "u1", true); c != 403 || m["error"] != "not_linked" {
		t.Errorf("not linked: %d %v", c, m)
	}
	if c, m := do(Prefix+"/widgets/boom", "u1", true); c != 502 || m["error"] != "unavailable" {
		t.Errorf("failure must not leak details: %d %v", c, m)
	}
	if c, _ := do(Prefix+"/widgets/nope", "u1", true); c != 404 {
		t.Errorf("unknown widget %d", c)
	}
	if c, m := do(Prefix+"/search?q=report", "u1", true); c != 200 || len(m["results"].([]any)) != 1 {
		t.Errorf("search %d %v", c, m)
	}
	if len(denied) != 2 {
		t.Errorf("Denied hook calls = %v", denied)
	}
}

func TestSanitize(t *testing.T) {
	long := strings.Repeat("é", 1000)
	f := 5.0
	w, err := Sanitize(Widget{Kind: KindList, Title: "a\x00b\x1b[31m" + long, Fraction: &f,
		Items: make([]Item, 80), Days: []Day{{Date: "2026-01-01", Events: []Event{{Title: "t", Start: "2026-01-01", Color: "red", Link: "//evil.com"}}}},
		Action: &Action{Label: "x", Link: "data:text/html,hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(w.Title, "\x00\x1b") || len([]rune(w.Title)) > MaxString {
		t.Errorf("title not cleaned: %d runes", len([]rune(w.Title)))
	}
	if len(w.Items) != MaxItems || *w.Fraction != 1 || w.Days[0].Events[0].Color != "" || w.Days[0].Events[0].Link != "" || w.Action != nil {
		t.Errorf("sanitize result %+v", w)
	}
	if _, err := Sanitize(Widget{Kind: "iframe"}); err == nil {
		t.Error("unknown kind accepted")
	}
	if _, err := Sanitize(Widget{Kind: KindError}); err == nil {
		t.Error("providers must not send kind=error")
	}
}

func TestPointJSON(t *testing.T) {
	b, _ := json.Marshal([]Point{{T: 100, V: 1.5}, {Label: "mon", V: 2, Cat: true}})
	if string(b) != `[[100,1.5],["mon",2]]` {
		t.Fatal(string(b))
	}
	var ps []Point
	if err := json.Unmarshal(b, &ps); err != nil || ps[0].T != 100 || !ps[1].Cat || ps[1].Label != "mon" {
		t.Fatalf("%v %+v", err, ps)
	}
}
