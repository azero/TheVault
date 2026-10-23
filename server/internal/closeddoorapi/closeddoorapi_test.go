package closeddoorapi

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSSO answers like ClosedDoor's /api/introspect for one service ("app_x"/"cds_y") and one key.
func fakeSSO(t *testing.T, calls *int32, answer string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("app_x:cds_y"))
		if r.Method != http.MethodPost || r.URL.Path != "/api/introspect" || r.Header.Get("Authorization") != want {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.PostForm.Get("token") == "cdk_good" {
			_, _ = w.Write([]byte(answer))
			return
		}
		_, _ = w.Write([]byte(`{"active":false}`))
	}))
}

const goodAnswer = `{"active":true,"token_kind":"api_key","sub":"svc_1","principal":"service","key_id":"key_1","key_name":"Nightly","scope":"reports:read reports:write","roles":[]}`

func newVerifier(t *testing.T, srv *httptest.Server, ttl time.Duration) *Verifier {
	t.Helper()
	v, err := New(Config{Issuer: srv.URL + "/", ClientID: "app_x", ClientSecret: "cds_y", CacheTTL: ttl})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerify(t *testing.T) {
	var calls int32
	srv := fakeSSO(t, &calls, goodAnswer)
	defer srv.Close()
	v := newVerifier(t, srv, 0)

	who, err := v.Verify(context.Background(), "cdk_good")
	if err != nil || who == nil || who.Subject != "svc_1" || !who.Can("reports:write") || who.Can("reports") || who.HasRole("x") {
		t.Fatalf("good key: %+v %v", who, err)
	}
	if who, err := v.Verify(context.Background(), "cdk_bad"); who != nil || err != nil {
		t.Fatalf("bad key must be (nil, nil), got %+v %v", who, err)
	}
	if who, err := v.Verify(context.Background(), ""); who != nil || err != nil || atomic.LoadInt32(&calls) != 2 {
		t.Fatal("an empty token must not even reach the SSO server")
	}
}

func TestWrongServiceCredentialsAreAnError(t *testing.T) {
	var calls int32
	srv := fakeSSO(t, &calls, goodAnswer)
	defer srv.Close()
	v, _ := New(Config{Issuer: srv.URL, ClientID: "app_x", ClientSecret: "wrong"})
	if who, err := v.Verify(context.Background(), "cdk_good"); who != nil || err == nil {
		t.Fatal("rejected service credentials must be an error, not an 'invalid key'")
	}
}

func TestUnreachableFailsClosed(t *testing.T) {
	var calls int32
	srv := fakeSSO(t, &calls, goodAnswer)
	url := srv.URL
	srv.Close()
	v, _ := New(Config{Issuer: url, ClientID: "app_x", ClientSecret: "cds_y"})
	if who, err := v.Verify(context.Background(), "cdk_good"); who != nil || err == nil {
		t.Fatal("an unreachable SSO server must be an error")
	}
	h := v.Middleware("reports:read")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("handler must not run") }))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer cdk_good")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestSpecialCharactersInCredentialsAreEncoded(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"active":false}`))
	}))
	defer srv.Close()
	v, _ := New(Config{Issuer: srv.URL, ClientID: "app_x", ClientSecret: "a:b c+d"})
	_, _ = v.Verify(context.Background(), "t")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("app_x:"+url.QueryEscape("a:b c+d")))
	if got != want {
		t.Fatalf("credentials must be form-urlencoded before base64: %q", got)
	}
}

func TestCache(t *testing.T) {
	var calls int32
	srv := fakeSSO(t, &calls, goodAnswer)
	defer srv.Close()
	v := newVerifier(t, srv, time.Minute)
	for i := 0; i < 3; i++ {
		if who, _ := v.Verify(context.Background(), "cdk_good"); who == nil {
			t.Fatal("expected a principal")
		}
	}
	if _, _ = v.Verify(context.Background(), "cdk_bad"); atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("answers must be cached per token: %d calls", calls)
	}
	// A key that expires sooner than the cache TTL must not outlive its own expiry.
	short := `{"active":true,"scope":"a","roles":[],"exp":` + strconv.FormatInt(time.Now().Add(-time.Second).Unix(), 10) + `}`
	var c2 int32
	srv2 := fakeSSO(t, &c2, short)
	defer srv2.Close()
	v2 := newVerifier(t, srv2, time.Minute)
	_, _ = v2.Verify(context.Background(), "cdk_good")
	_, _ = v2.Verify(context.Background(), "cdk_good")
	if atomic.LoadInt32(&c2) != 2 {
		t.Fatal("a cached answer must not be used past the key's own expiry")
	}
}

func TestCacheIsBounded(t *testing.T) {
	var calls int32
	srv := fakeSSO(t, &calls, goodAnswer)
	defer srv.Close()
	v, _ := New(Config{Issuer: srv.URL, ClientID: "app_x", ClientSecret: "cds_y", CacheTTL: time.Minute, CacheSize: 3})
	for i := 0; i < 10; i++ {
		_, _ = v.Verify(context.Background(), "tok"+strconv.Itoa(i))
	}
	if len(v.cache) > 3 {
		t.Fatalf("cache grew to %d", len(v.cache))
	}
}

func TestMiddleware(t *testing.T) {
	var calls int32
	srv := fakeSSO(t, &calls, goodAnswer)
	defer srv.Close()
	v := newVerifier(t, srv, 0)
	var seen *Principal
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = FromContext(r.Context()); w.WriteHeader(204) })

	do := func(h http.Handler, header, value string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if header != "" {
			req.Header.Set(header, value)
		}
		h.ServeHTTP(rec, req)
		return rec
	}
	read := v.Middleware("reports:read")(next)
	both := v.Middleware("reports:read", "reports:admin")(next)

	if rec := do(read, "", ""); rec.Code != 401 || rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no credential: %d", rec.Code)
	}
	if rec := do(read, "Authorization", "Bearer cdk_bad"); rec.Code != 401 {
		t.Fatalf("bad key: %d", rec.Code)
	}
	if rec := do(read, "Authorization", "Basic abc"); rec.Code != 401 {
		t.Fatalf("other scheme: %d", rec.Code)
	}
	if rec := do(both, "Authorization", "Bearer cdk_good"); rec.Code != 403 {
		t.Fatalf("missing permission: %d", rec.Code)
	}
	if rec := do(read, "Authorization", "bearer cdk_good"); rec.Code != 204 || seen == nil || seen.KeyName != "Nightly" {
		t.Fatalf("good key: %d %+v", rec.Code, seen)
	}
	seen = nil
	if rec := do(read, "X-API-Key", "cdk_good"); rec.Code != 204 || seen == nil {
		t.Fatalf("X-API-Key: %d", rec.Code)
	}
}
