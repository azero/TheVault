package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// fakeKey is one ClosedDoor API key as the fake introspection endpoint knows it.
type fakeKey struct {
	Principal string // "user" | "service"
	Sub       string
	KeyID     string
	KeyName   string
	Scope     string // space separated, already limited to what was granted for this application
	Roles     []string
	Name      string
	Email     string
	Exp       int64  // unix seconds; 0 = never
	Disabled  bool   // revoked, user disabled, grant removed...: all answer {"active": false}
	Kind      string // "" = api_key
}

// introspect answers like ClosedDoor's POST /api/introspect (RFC 7662): client authentication by HTTP Basic or by
// form fields, {"active":false} for anything wrong with the token, 401 invalid_client for bad application credentials.
func (f *fakeSSO) introspect(w http.ResponseWriter, r *http.Request, base string) {
	f.Introspects++
	w.Header().Set("Content-Type", "application/json")
	if f.IntrospectDown {
		http.Error(w, `{"error":"server_error"}`, 503)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"invalid_request"}`, 405)
		return
	}
	r.ParseForm()
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != "app_test" || secret != "cds_secret" {
		http.Error(w, `{"error":"invalid_client"}`, 401)
		return
	}
	token := r.PostForm.Get("token")
	if token == "" {
		http.Error(w, `{"error":"invalid_request"}`, 400)
		return
	}
	k := f.keys[token]
	if k == nil || k.Disabled || (k.Exp > 0 && k.Exp < time.Now().Unix()) {
		w.Write([]byte(`{"active":false}`))
		return
	}
	kind := k.Kind
	if kind == "" {
		kind = "api_key"
	}
	roles := k.Roles
	if roles == nil {
		roles = []string{}
	}
	out := map[string]any{"active": true, "token_kind": kind, "iss": base, "aud": "app_test", "sub": k.Sub, "principal": k.Principal,
		"key_id": k.KeyID, "key_name": k.KeyName, "scope": k.Scope, "roles": roles, "iat": time.Now().Unix() - 60}
	if k.Principal == "user" {
		out["name"], out["email"] = k.Name, k.Email
	}
	if k.Exp > 0 {
		out["exp"] = k.Exp
	}
	json.NewEncoder(w).Encode(out)
}

// addKey registers a key under a fresh token and returns the token.
func (f *fakeSSO) addKey(k fakeKey) string {
	token := "cdk_" + strings.TrimRight(b64(randBytes(32)), "=")
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := k
	f.keys[token] = &cp
	return token
}

// changeKey edits a registered key at run time (revoke, disable the user, remove a scope...).
func (f *fakeSSO) changeKey(token string, fn func(*fakeKey)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f.keys[token])
}

func (f *fakeSSO) introspectCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Introspects
}
