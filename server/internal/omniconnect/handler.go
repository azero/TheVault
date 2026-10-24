// Vendored from OmniCore reference/go/omniconnect; change upstream, not here.

package omniconnect

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Prefix is where an app mounts the protocol.
const Prefix = "/integrations/omnicore/v1"

var (
	// ErrNotLinked: the person is allowed in ClosedDoor but has never signed in to this app, so it has no
	// account to read data for. OmniCore shows "open <app> once to connect".
	ErrNotLinked = errors.New("omniconnect: user not linked")
	// ErrForbidden: the person's role in this app does not allow this widget.
	ErrForbidden = errors.New("omniconnect: forbidden")
	ErrNotFound  = errors.New("omniconnect: not found")
)

// User is the person a request is for: only the ClosedDoor subject. The app maps it to its own account
// (and that account's role) itself; OmniCore's word is never taken for roles or names.
type User struct{ Sub string }

// Provider is what an app implements.
type Provider interface {
	// Manifest describes the app. It is the same for everyone; widgets whose Roles exclude a person are
	// refused at Widget time.
	Manifest() Manifest
	// Widget returns the payload for widget id with the person's settings (cfg, from cfg.<key> parameters).
	// Return ErrNotLinked, ErrForbidden or ErrNotFound for the matching statuses; any other error is a 502
	// with a generic message (details belong in your log).
	Widget(ctx context.Context, u User, id string, cfg map[string]string) (Widget, error)
}

// Optioner provides dynamic select options (GET /options/{widget}/{key}).
type Optioner interface {
	Options(ctx context.Context, u User, widget, key string) ([]Option, error)
}

// Searcher provides the optional global search (GET /search?q=).
type Searcher interface {
	Search(ctx context.Context, u User, q string) ([]SearchResult, error)
}

// Hooks lets the app audit what happens (and ship it to SkyNet). All fields are optional.
type Hooks struct {
	// Denied is called for every request that failed authentication. reason is for logs only.
	Denied func(r *http.Request, reason string)
	// Served is called after an authenticated call (user may be "").
	Served func(r *http.Request, user, what string)
	// Failed is called when the provider returned an error that is not ErrNotLinked/ErrForbidden/ErrNotFound
	// (the client only ever sees a generic 502); log err here, never send it to the client.
	Failed func(r *http.Request, what string, err error)
}

// Mount registers the protocol on mux. Responses are JSON with Cache-Control: no-store; every failure of
// authentication is the same 401 {"error":"unauthorized"}.
func Mount(mux *http.ServeMux, p Provider, v *Verifier, h Hooks) {
	wrapH := func(what string, needUser bool, fn func(w http.ResponseWriter, r *http.Request, u User)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			user, err := v.Verify(r)
			if err != nil || (needUser && user == "") {
				if h.Denied != nil {
					reason := "no user"
					if err != nil {
						reason = err.Error()
					}
					h.Denied(r, reason)
				}
				writeErr(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if h.Served != nil {
				h.Served(r, user, what)
			}
			ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
			defer cancel()
			fn(w, r.WithContext(ctx), User{Sub: user})
		}
	}
	// Everything else under the prefix (other methods, unknown paths) is answered by the same verifier, so an
	// unauthenticated caller always gets the identical 401 and never learns which routes exist.
	mux.HandleFunc(Prefix+"/", wrapH("unknown", false, func(w http.ResponseWriter, r *http.Request, _ User) {
		writeErr(w, http.StatusNotFound, "not_found")
	}))
	mux.HandleFunc("GET "+Prefix+"/manifest", wrapH("manifest", false, func(w http.ResponseWriter, r *http.Request, _ User) {
		m := p.Manifest()
		m.Protocol = ProtocolVersion
		writeJSON(w, http.StatusOK, m)
	}))
	mux.HandleFunc("GET "+Prefix+"/status", wrapH("status", false, func(w http.ResponseWriter, r *http.Request, _ User) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "protocol": ProtocolVersion, "version": p.Manifest().App.Version})
	}))
	mux.HandleFunc("GET "+Prefix+"/widgets/{id}", wrapH("widget", true, func(w http.ResponseWriter, r *http.Request, u User) {
		id := r.PathValue("id")
		if !known(p.Manifest(), id) {
			writeErr(w, http.StatusNotFound, "not_found")
			return
		}
		out, err := p.Widget(r.Context(), u, id, ConfigFromQuery(r))
		if err == nil {
			out, err = Sanitize(out)
		}
		switch {
		case err == nil:
			if out.UpdatedAt == 0 {
				out.UpdatedAt = time.Now().Unix()
			}
			writeJSON(w, http.StatusOK, out)
		case errors.Is(err, ErrNotLinked):
			writeErr(w, http.StatusForbidden, "not_linked")
		case errors.Is(err, ErrForbidden):
			writeErr(w, http.StatusForbidden, "forbidden")
		case errors.Is(err, ErrNotFound):
			writeErr(w, http.StatusNotFound, "not_found")
		default:
			if h.Failed != nil {
				h.Failed(r, "widget "+id, err)
			}
			writeErr(w, http.StatusBadGateway, "unavailable")
		}
	}))
	if o, ok := p.(Optioner); ok {
		mux.HandleFunc("GET "+Prefix+"/options/{widget}/{key}", wrapH("options", true, func(w http.ResponseWriter, r *http.Request, u User) {
			opts, err := o.Options(r.Context(), u, r.PathValue("widget"), r.PathValue("key"))
			if err != nil {
				if h.Failed != nil && status2(err) == http.StatusBadGateway {
					h.Failed(r, "options", err)
				}
				status, msg := statusOf(err)
				writeErr(w, status, msg)
				return
			}
			if len(opts) > 200 {
				opts = opts[:200]
			}
			for i := range opts {
				opts[i].Value, opts[i].Label = clean(opts[i].Value, 120), clean(opts[i].Label, MaxString)
			}
			writeJSON(w, http.StatusOK, map[string]any{"options": opts})
		}))
	}
	if sr, ok := p.(Searcher); ok {
		mux.HandleFunc("GET "+Prefix+"/search", wrapH("search", true, func(w http.ResponseWriter, r *http.Request, u User) {
			q := strings.TrimSpace(r.URL.Query().Get("q"))
			if len(q) < 2 || len(q) > 200 {
				writeJSON(w, http.StatusOK, map[string]any{"results": []SearchResult{}})
				return
			}
			res, err := sr.Search(r.Context(), u, q)
			if err != nil {
				if h.Failed != nil && status2(err) == http.StatusBadGateway {
					h.Failed(r, "search", err)
				}
				status, msg := statusOf(err)
				writeErr(w, status, msg)
				return
			}
			if len(res) > 10 {
				res = res[:10]
			}
			for i := range res {
				res[i] = SearchResult{Title: clean(res[i].Title, MaxString), Subtitle: clean(res[i].Subtitle, MaxString),
					Icon: clean(res[i].Icon, 30), Link: link(res[i].Link)}
			}
			writeJSON(w, http.StatusOK, map[string]any{"results": res})
		}))
	}
}

// ConfigFromQuery extracts the widget settings: every cfg.<key>=value parameter (keys [a-z0-9_]{1,40}, values
// up to 200 characters, at most 20 of them).
func ConfigFromQuery(r *http.Request) map[string]string {
	cfg := map[string]string{}
	for k, vs := range r.URL.Query() {
		if !strings.HasPrefix(k, "cfg.") || len(vs) == 0 || len(cfg) >= 20 {
			continue
		}
		key := k[4:]
		if len(key) == 0 || len(key) > 40 || len(vs[0]) > 200 {
			continue
		}
		ok := true
		for _, c := range key {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
				ok = false
			}
		}
		if ok {
			cfg[key] = vs[0]
		}
	}
	return cfg
}

func known(m Manifest, id string) bool {
	for _, w := range m.Widgets {
		if w.ID == id {
			return true
		}
	}
	return false
}

func statusOf(err error) (int, string) {
	switch {
	case errors.Is(err, ErrNotLinked):
		return http.StatusForbidden, "not_linked"
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden, "forbidden"
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound, "not_found"
	}
	return http.StatusBadGateway, "unavailable"
}

func status2(err error) int { s, _ := statusOf(err); return s }

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
