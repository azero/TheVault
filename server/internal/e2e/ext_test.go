package e2e

import (
	"crypto/sha256"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type extFlow struct {
	verifier, state, redirect string
}

// startExt runs /ext/auth through the fake SSO and returns the redirect the extension would receive.
func startExt(t *testing.T, e *env, redirect string, challenge string, extra string) (*http.Response, *url.URL) {
	t.Helper()
	c := e.newClient()
	c.hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if strings.HasSuffix(req.URL.Host, ".chromiumapp.org") {
			return http.ErrUseLastResponse // the browser would hand this to the extension
		}
		return nil
	}
	u := e.srv.URL + "/ext/auth?code_challenge_method=S256&code_challenge=" + challenge + "&state=st4te&redirect_uri=" + url.QueryEscape(redirect) + extra
	resp, err := c.hc.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := resp.Location()
	return resp, loc
}

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64(sum[:])
}

func TestExtensionSignIn(t *testing.T) {
	e := newEnv(t)
	e.sso.set(func() { e.sso.Sub, e.sso.Email, e.sso.Roles = subAna, "ana@example.com", nil })
	redirect := "https://" + extID + ".chromiumapp.org/cb"
	verifier := b64(randBytes(48))

	// only configured extension ids may receive codes; nothing is redirected to an unvalidated address
	for _, bad := range []string{"https://evil.example/cb", "https://" + strings.Repeat("a", 32) + ".chromiumapp.org/cb", "http://" + extID + ".chromiumapp.org/cb", "https://" + extID + ".chromiumapp.org.evil.io/cb", "javascript:alert(1)"} {
		resp, loc := startExt(t, e, bad, challengeFor(verifier), "")
		if resp.StatusCode != 400 || loc != nil {
			t.Fatalf("redirect %q must be refused with a page, got %d %v", bad, resp.StatusCode, loc)
		}
	}
	if resp, _ := startExt(t, e, redirect, "short", ""); resp.StatusCode != 400 {
		t.Fatalf("bad challenge: %d", resp.StatusCode)
	}

	resp, loc := startExt(t, e, redirect, challengeFor(verifier), "")
	if resp.StatusCode != 302 || loc == nil || loc.Host != extID+".chromiumapp.org" || loc.Query().Get("state") != "st4te" || loc.Query().Get("code") == "" {
		t.Fatalf("expected a redirect to the extension with a code: %d %v", resp.StatusCode, loc)
	}
	code := loc.Query().Get("code")

	x := e.newClient()
	post := func(body map[string]any, hdr map[string]string) (int, map[string]any) {
		st, b, _ := x.do("POST", "/api/v1/ext/token", body, hdr)
		m := map[string]any{}
		jsonUnmarshal(b, &m)
		return st, m
	}
	// wrong verifier burns nothing the attacker can reuse, but the code is gone afterwards
	if st, _ := post(map[string]any{"code": code, "verifier": b64(randBytes(48)), "redirect_uri": redirect}, nil); st != 400 {
		t.Fatalf("wrong verifier: %d", st)
	}
	if st, _ := post(map[string]any{"code": code, "verifier": verifier, "redirect_uri": redirect}, nil); st != 400 {
		t.Fatalf("a code is single use even after a failed attempt: %d", st)
	}
	_, loc = startExt(t, e, redirect, challengeFor(verifier), "")
	code = loc.Query().Get("code")
	if st, _ := post(map[string]any{"code": code, "verifier": verifier, "redirect_uri": "https://" + extID + ".chromiumapp.org/other"}, nil); st != 400 {
		t.Fatalf("redirect_uri must match: %d", st)
	}
	_, loc = startExt(t, e, redirect, challengeFor(verifier), "")
	code = loc.Query().Get("code")
	// a foreign origin may not exchange codes
	if st, _ := post(map[string]any{"code": code, "verifier": verifier, "redirect_uri": redirect}, map[string]string{"Origin": "https://evil.example"}); st != 403 {
		t.Fatalf("foreign origin: %d", st)
	}
	_, loc = startExt(t, e, redirect, challengeFor(verifier), "")
	code = loc.Query().Get("code")
	st, tok := post(map[string]any{"code": code, "verifier": verifier, "redirect_uri": redirect, "label": "Chrome on Test"}, map[string]string{"Origin": "chrome-extension://" + extID})
	if st != 200 || !strings.HasPrefix(tok["token"].(string), "vxs_") {
		t.Fatalf("token exchange: %d %v", st, tok)
	}
	token := tok["token"].(string)

	// the bearer token works with the extension's origin, with CORS for exactly that origin
	ext := e.newClient()
	ext.bearer = token
	hdr := map[string]string{"Origin": "chrome-extension://" + extID}
	st, b, h := ext.do("GET", "/api/v1/session", nil, hdr)
	if st != 200 || h.Get("Access-Control-Allow-Origin") != "chrome-extension://"+extID || h.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("extension session: %d %s %v", st, b, h)
	}
	if st, _, h := ext.do("GET", "/api/v1/session", nil, map[string]string{"Origin": "https://evil.example"}); st != 403 || h.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("a bearer token from a foreign origin: %d", st)
	}
	// preflight
	if st, _, h := ext.do("OPTIONS", "/api/v1/sync", nil, map[string]string{"Origin": "chrome-extension://" + extID, "Access-Control-Request-Method": "GET"}); st != 204 || !strings.Contains(h.Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("preflight: %d %v", st, h)
	}
	if st, _, _ := ext.do("OPTIONS", "/api/v1/sync", nil, map[string]string{"Origin": "https://evil.example"}); st != 403 {
		t.Fatalf("preflight for a foreign origin: %d", st)
	}
	// a bearer session is not a cookie session and vice versa
	web := e.login(subAna, "ana@example.com")
	web.bearer = token
	web.call("GET", "/api/v1/session", nil, 200, nil)
	mixed := e.newClient()
	mixed.bearer = "vxs_" + b64(randBytes(32))
	if st, _ := mixed.status("GET", "/api/v1/session", nil); st != 401 {
		t.Fatalf("unknown bearer: %d", st)
	}
	mixed.bearer = "Bearer"
	if st, _ := mixed.status("GET", "/api/v1/session", nil); st != 401 {
		t.Fatalf("junk bearer: %d", st)
	}

	// vault flow over bearer: setup, unlock state survives a renewal, the old token dies
	m := newMaterial()
	ext.call("POST", "/api/v1/vault/setup", m.Setup, 200, nil)
	ext.call("GET", "/api/v1/sync", nil, 200, nil)
	_, loc = startExt(t, e, redirect, challengeFor(verifier), "&prompt=none")
	code = loc.Query().Get("code")
	x2 := e.newClient()
	x2.bearer = token // proves possession of the old token
	st2, b2, _ := x2.do("POST", "/api/v1/ext/token", map[string]any{"code": code, "verifier": verifier, "redirect_uri": redirect}, nil)
	if st2 != 200 {
		t.Fatalf("renewal: %d %s", st2, b2)
	}
	m2 := map[string]any{}
	jsonUnmarshal(b2, &m2)
	renewed := m2["token"].(string)
	if st, _ := ext.status("GET", "/api/v1/session", nil); st != 401 {
		t.Fatalf("the replaced token must stop working: %d", st)
	}
	ext.bearer = renewed
	ext.call("GET", "/api/v1/sync", nil, 200, nil) // still unlocked: the renewal carried the unlock over

	// without proof of the old token, a new sign-in starts locked
	_, loc = startExt(t, e, redirect, challengeFor(verifier), "")
	fresh := e.newClient()
	_, b3, _ := fresh.do("POST", "/api/v1/ext/token", map[string]any{"code": loc.Query().Get("code"), "verifier": verifier, "redirect_uri": redirect}, nil)
	m3 := map[string]any{}
	jsonUnmarshal(b3, &m3)
	fresh.bearer = m3["token"].(string)
	if st, _ := fresh.status("GET", "/api/v1/sync", nil); st != 423 {
		t.Fatalf("a new device starts locked: %d", st)
	}
	fresh.call("POST", "/api/v1/vault/unlock", map[string]any{"auth": m.Auth}, 200, nil)
	fresh.call("GET", "/api/v1/sync", nil, 200, nil)

	// the device list shows it and the user can revoke it from the web UI
	var list struct {
		Sessions []struct{ ID, Kind, Label string }
	}
	web.bearer = ""
	web.call("GET", "/api/v1/sessions", nil, 200, &list)
	var extIDs []string
	for _, s := range list.Sessions {
		if s.Kind == "ext" {
			extIDs = append(extIDs, s.ID)
		}
	}
	if len(extIDs) != 2 {
		t.Fatalf("expected two extension sessions: %+v", list)
	}
	web.call("DELETE", "/api/v1/sessions/"+extIDs[0], nil, 200, nil)
	if !auditNames(e)["ext_device_added"] {
		t.Error("ext_device_added not audited")
	}
}

func TestExtensionSilentSignInWithoutSSOSession(t *testing.T) {
	e := newEnv(t)
	e.sso.set(func() { e.sso.Login = false })
	redirect := "https://" + extID + ".chromiumapp.org/cb"
	resp, loc := startExt(t, e, redirect, challengeFor("v"+b64(randBytes(48))), "&prompt=none")
	if resp.StatusCode != 302 || loc == nil || loc.Query().Get("error") != "login_required" || loc.Query().Get("code") != "" {
		t.Fatalf("silent flow without an SSO session: %d %v", resp.StatusCode, loc)
	}
}

func TestExtensionLockedUserDenied(t *testing.T) {
	e := newEnv(t)
	e.sso.set(func() { e.sso.Sub, e.sso.Email = subAna, "ana@example.com" })
	web := e.login(subAna, "ana@example.com")
	_ = web
	e.st.SetUserLocked(e.ctx, subAna, true)
	resp, loc := startExt(t, e, "https://"+extID+".chromiumapp.org/cb", challengeFor("x"), "")
	if resp.StatusCode != 302 || loc.Query().Get("error") != "access_denied" || loc.Query().Get("code") != "" {
		t.Fatalf("locked user: %d %v", resp.StatusCode, loc)
	}
}

var _ = time.Now
