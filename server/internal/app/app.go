// Package app wires config, store, SSO, audit, SkyNet, API and web UI into one http.Handler. main and the
// end-to-end tests both build the server here.
package app

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/azero/thevault/server/internal/alerts"
	"github.com/azero/thevault/server/internal/api"
	"github.com/azero/thevault/server/internal/audit"
	"github.com/azero/thevault/server/internal/auth"
	"github.com/azero/thevault/server/internal/automation"
	"github.com/azero/thevault/server/internal/config"
	"github.com/azero/thevault/server/internal/httpx"
	"github.com/azero/thevault/server/internal/keys"
	"github.com/azero/thevault/server/internal/notify"
	"github.com/azero/thevault/server/internal/omnicore"
	"github.com/azero/thevault/server/internal/skynet"
	"github.com/azero/thevault/server/internal/store"
	"github.com/azero/thevault/server/internal/web"
)

type App struct {
	Handler http.Handler
	Sky     *skynet.Client
	Audit   *audit.Auditor
	Notify  *notify.Notifier // nil when Beacon is not configured
	alerts  *alerts.Alerts
	cfg     *config.Config
	st      *store.Store
	ticks   int
}

func New(cfg *config.Config, st *store.Store, version string) (*App, error) {
	pepper, err := keys.LoadPepper(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	sigKey, err := keys.LoadSessionKey(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	au := auth.New(auth.Config{Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID, ClientSecret: cfg.OIDCClientSecret,
		RedirectURL: cfg.PublicURL + "/auth/callback", Secure: cfg.SecureCookie, SigningKey: sigKey})
	aud := audit.New(st)

	a := &App{cfg: cfg, st: st, Audit: aud}
	var skyStatus func(context.Context) any
	if cfg.SkyNetURL != "" {
		sky, err := skynet.New(skynet.Config{URL: cfg.SkyNetURL, Key: cfg.SkyNetKey, EnrollToken: cfg.SkyNetEnrollToken, CommandKey: cfg.SkyNetCommandKey,
			Host: cfg.SkyNetHost, Version: version, DataDir: cfg.DataDir, Allowlist: cfg.ResponseAllowlist}, st, aud)
		if err != nil {
			return nil, err
		}
		a.Sky = sky
		skyStatus = sky.Status
	}

	// Notifications through Beacon (off unless VAULT_BEACON_URL and _KEY are set). They hang off the audit trail, so they
	// never run inside a request's critical path and cannot change what is audited or sent to SkyNet.
	min, _ := notify.ParseLevel(cfg.NotifyMinLevel)
	a.Notify = notify.New(alerts.Config(cfg.BeaconURL, cfg.BeaconKey, min, log.Printf))
	a.alerts = alerts.New(alerts.Options{Notifier: a.Notify, Store: st, PublicURL: cfg.PublicURL, AdminGroup: cfg.NotifyAdminGroup})
	aud.AddSink(a.alerts.Sink)
	if a.Sky != nil {
		a.Sky.OnResponse(a.alerts.OnResponse)
	}

	var webSrv *web.Server
	var apiSrv *api.Server
	webSrv, err = web.New(web.Options{Version: version, PublicURL: cfg.PublicURL, HasSession: func(r *http.Request) bool { return apiSrv != nil && apiSrv.HasWebSession(r) }})
	if err != nil {
		return nil, err
	}
	apiSrv = api.New(api.Options{Cfg: cfg, Store: st, Auth: au, Audit: aud, Pepper: pepper, Version: version, ErrorPage: webSrv.ErrorPage, SkyNetStatus: skyStatus})

	mux := http.NewServeMux()
	webSrv.Routes(mux)
	apiSrv.Routes(mux)
	if cfg.APIEnabled {
		// Off by default: when disabled none of these routes exist. It uses the sign-in's own ClosedDoor client to verify keys.
		auto, err := automation.New(automation.Options{Cfg: cfg, Store: st, Audit: aud, Version: version, SkyNetStatus: skyStatus})
		if err != nil {
			return nil, err
		}
		auto.Routes(mux)
	}
	// OmniCore widgets: signed, read-only, not mounted at all without VAULT_OMNICORE_KEYS. Own authentication, so outside the
	// session/CSRF guard of the API; still behind the deny list and the security headers below.
	omnicore.New(omnicore.Options{Cfg: cfg, Store: st, Audit: aud, Version: version}).Mount(mux)
	var h http.Handler = httpx.SecureHeaders(cfg.SecureCookie, mux)
	h = a.denyMiddleware(h)
	a.Handler = h
	return a, nil
}

// denyMiddleware enforces SkyNet's block_ip commands: a denied address gets a bare 403 before anything else runs.
// /healthz is exempt so the container health check (loopback, never blockable anyway) cannot be affected.
func (a *App) denyMiddleware(next http.Handler) http.Handler {
	noisy := auth.NewLimiter(1, time.Minute)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.Sky != nil && r.URL.Path != "/healthz" {
			ip := httpx.ClientIP(r, a.cfg.TrustedIPHeader)
			if a.Sky.Denied(ip) {
				if noisy.Allow(ip) {
					a.Audit.Log(r.Context(), audit.Event{Name: "blocked_request", IP: ip, UA: r.UserAgent(), Outcome: "failure", Details: map[string]string{"path": clipPath(r.URL.Path)}})
				}
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func clipPath(p string) string {
	if len(p) > 100 {
		return p[:100]
	}
	return p
}

// Run starts the background work (SkyNet shipping/commands) and the once-a-minute housekeeping until ctx ends.
func (a *App) Run(ctx context.Context) {
	done := make(chan struct{})
	if a.Sky != nil {
		go func() { a.Sky.Run(ctx); close(done) }()
	} else {
		close(done)
	}
	notifyDone := make(chan struct{})
	go func() { a.Notify.Run(ctx); close(notifyDone) }() // nil-safe: returns at once when Beacon is not configured
	a.Tick(ctx, time.Now())
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			<-notifyDone
			a.alerts.Wait()
			<-done // do not return (and let the caller close the database) while SkyNet goroutines are still writing
			return
		case now := <-t.C:
			a.Tick(ctx, now)
		}
	}
}

// Tick is the housekeeping: expired sessions every minute, heavier pruning once an hour.
func (a *App) Tick(ctx context.Context, now time.Time) {
	a.st.PurgeSessions(ctx, 30*time.Minute)
	if a.ticks%60 == 0 {
		a.st.PruneAudit(ctx, time.Duration(a.cfg.AuditRetentionDays)*24*time.Hour)
		a.st.PruneTombstones(ctx, 90*24*time.Hour)
		if n, err := a.st.PruneTrash(ctx, 30*24*time.Hour); err != nil {
			if ctx.Err() == nil {
				log.Printf("prune trash: %v", err)
			}
		} else if n > 0 {
			log.Printf("trash: permanently removed %d item(s) older than 30 days", n)
		}
	}
	a.ticks++
}
