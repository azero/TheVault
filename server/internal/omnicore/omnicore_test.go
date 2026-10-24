package omnicore

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/azero/thevault/server/internal/audit"
	"github.com/azero/thevault/server/internal/config"
	oc "github.com/azero/thevault/server/internal/omniconnect"
	"github.com/azero/thevault/server/internal/store"
)

func TestReasonWordsAreAFixedVocabulary(t *testing.T) {
	for in, want := range map[string]string{
		"omniconnect: unauthorized (signature)": "signature", "omniconnect: unauthorized (unknown key)": "unknown_key",
		"omniconnect: unauthorized (clock skew)": "clock_skew", "no user": "no_user", "something with ocs_secret": "other",
	} {
		if got := reasonWord(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func TestNewReturnsNilWithoutKeysAndMountIsSafe(t *testing.T) {
	var p *Provider
	p.Mount(http.NewServeMux()) // must not panic
	if New(Options{Cfg: &config.Config{}}) != nil {
		t.Fatal("no keys, no provider")
	}
}

func TestRequestsAreRateLimitedPerAddressAndNonGetIsUnauthorized(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p := New(Options{Cfg: &config.Config{OmniCoreKeys: []config.OmniCoreKey{{ID: "k", Secret: strings.Repeat("s", 40)}}}, Store: st, Audit: audit.New(st)})
	mux := http.NewServeMux()
	p.Mount(mux)
	do := func(method string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest(method, oc.Prefix+"/manifest", nil)
		r.RemoteAddr = "203.0.113.5:1234"
		mux.ServeHTTP(rec, r)
		return rec
	}
	if rec := do("DELETE"); rec.Code != 401 || strings.TrimSpace(rec.Body.String()) != `{"error":"unauthorized"}` {
		t.Fatalf("DELETE: %d %s", rec.Code, rec.Body)
	}
	var last int
	for i := 0; i < requestsPerMinute+5; i++ {
		last = do("GET").Code
	}
	if last != 429 {
		t.Fatalf("the per-address limit never kicked in: %d", last)
	}
}
