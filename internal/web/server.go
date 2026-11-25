// Package web is Insight's HTTP side: the addon contract the kit mounts (the
// manifest, the setup, the panel's events, health), the admin's own API
// under /api, and the admin web.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nx-panel/addon-kit/addon"
	"github.com/nx-panel/addon-kit/auth"
	"github.com/nx-panel/addon-kit/web"
	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/admins"
	"github.com/nx-panel/insight/internal/ai"
	"github.com/nx-panel/insight/internal/cloud"
	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/ingest"
	"github.com/nx-panel/insight/internal/metrics"
	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/netinfo"
	"github.com/nx-panel/insight/internal/tunnels"
)

const sessionCookie = "nx_insight_session"

// Server is Insight's HTTP side.
type Server struct {
	db      *gorm.DB
	addon   *addon.Addon
	cfg     config.Config
	version string
	spa     fs.FS
	logins  *auth.Limiter

	ingest    *ingest.Ingest
	detect    *detect.Detector
	net       *netinfo.DB
	ai        *ai.Runner
	tunnels   *tunnels.Watcher
	cloud     *cloud.Cloud
	countries []string

	mu      sync.Mutex
	pending map[string]pendingLogin
	enrol   map[uint]string

	tls     *web.TLS
	proxies web.Proxies
}

type pendingLogin struct {
	adminID uint
	expires time.Time
}

// Parts are the pieces of Insight the admin web reads.
type Parts struct {
	Ingest *ingest.Ingest
	Detect *detect.Detector
	Net    *netinfo.DB
	// AI is Mode A's runner, Countries the client countries it reads.
	AI        *ai.Runner
	Countries []string
	// Tunnels is the tunnel watcher, nil for none.
	Tunnels *tunnels.Watcher
	// Cloud is Mode B (internal/cloud), nil for none.
	Cloud *cloud.Cloud
}

// New wires the server; spa is the built admin web, nil for none.
func New(gdb *gorm.DB, a *addon.Addon, cfg config.Config, version string, spa fs.FS, p Parts) *Server {
	s := &Server{
		db: gdb, addon: a, cfg: cfg, version: version, spa: spa,
		logins:  auth.NewLimiter(5, 10*time.Minute),
		pending: map[string]pendingLogin{}, enrol: map[uint]string{},
		ingest: p.Ingest, detect: p.Detect, net: p.Net, ai: p.AI, tunnels: p.Tunnels, cloud: p.Cloud, countries: p.Countries,
	}
	proxies, err := web.ParseProxies(cfg.TrustedProxies)
	if err != nil {
		log.Printf("%v; left out", err)
	}
	s.proxies = proxies
	if cfg.HTTPS != web.HTTPSOff {
		s.tls = &web.TLS{
			Mode: cfg.HTTPS,
			Host: func() string { return web.HostOf(cfg.PublicURL) },
			Dir:  cfg.DataDir, ACMEDirectory: cfg.ACMEDirectory, ACMEInsecure: cfg.ACMEInsecure,
			Panel: a, HTTPListen: cfg.HTTPListen,
		}
	}
	return s
}

// Handler is every route.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.addon.Mount(mux)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/login/mfa", s.handleLoginMFA)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", s.signedIn(s.handleMe))
	mux.HandleFunc("PUT /api/me/password", s.signedIn(s.handlePassword))
	mux.HandleFunc("POST /api/me/2fa/totp", s.signedIn(s.handleTOTPEnrol))
	mux.HandleFunc("POST /api/me/2fa/totp/confirm", s.signedIn(s.handleTOTPConfirm))
	mux.HandleFunc("DELETE /api/me/2fa", s.signedIn(s.handleTOTPDisable))
	s.mountData(mux)
	// Prometheus: its own bearer token, no session.
	src := metrics.Sources{DB: s.db, Detect: s.detect, Ingest: s.ingest, Tunnels: s.tunnels}
	if s.net != nil {
		src.Org = s.net.Org
	}
	mux.HandleFunc("GET /metrics", metrics.Handler(s.cfg.MetricsToken, src))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, _ *http.Request) {
		writeCode(w, http.StatusNotFound, "not_found", "no such API route")
	})
	if s.spa != nil {
		mux.Handle("/", spaHandler(s.spa))
	}
	return s.proxies.Handler(web.RefuseCrossOrigin(securityHeaders(web.Mount(s.cfg.BasePath, mux))))
}

// ServeHTTPS serves every route over HTTPS on Insight's port until ctx ends;
// with https off it does nothing and returns nil at once.
func (s *Server) ServeHTTPS(ctx context.Context) error {
	if s.tls == nil {
		return nil
	}
	if s.tls.Mode == web.HTTPSSelfSigned {
		if fp := s.tls.Fingerprint(); fp != "" {
			log.Printf("https: the self-signed certificate's SHA-256 fingerprint is %s", fp)
		}
	}
	return s.tls.Serve(ctx, s.cfg.Addr(), s.Handler())
}

// HTTPS reports whether Insight serves its port over HTTPS itself.
func (s *Server) HTTPS() bool { return s.tls != nil }

// Healthy is the health path's answer: the database answers.
func Healthy(gdb *gorm.DB) func() error {
	return func() error {
		sqlDB, err := gdb.DB()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return sqlDB.PingContext(ctx)
	}
}

// signedIn admits a request with a live session.
func (s *Server) signedIn(next func(http.ResponseWriter, *http.Request, model.Admin)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := ""
		if c, _ := r.Cookie(sessionCookie); c != nil {
			tok = c.Value
		}
		a, err := admins.Of(s.db, tok)
		if err != nil {
			writeCode(w, http.StatusUnauthorized, "signed_out", err.Error())
			return
		}
		next(w, r, a)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// serverError answers 500 without the error's text, which is the database
// driver's or the kernel's and no business of whoever is asking — some of
// these routes answer before anyone has signed in. The log has it.
func serverError(w http.ResponseWriter, err error) {
	log.Printf("web: %v", err)
	writeCode(w, http.StatusInternalServerError, "internal", "internal error")
}

// writeCode is an error with a code the admin web translates
// (frontend/src/i18n.ts, errors.<code>); msg is the English.
func writeCode(w http.ResponseWriter, status int, code, msg string, params ...string) {
	body := map[string]any{"error": msg, "code": code}
	if len(params) > 1 {
		p := map[string]string{}
		for i := 0; i+1 < len(params); i += 2 {
			p[params[i]] = params[i+1]
		}
		body["params"] = p
	}
	writeJSON(w, status, body)
}

func badBody(w http.ResponseWriter) {
	writeCode(w, http.StatusBadRequest, "bad_request", "invalid body")
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<16))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid body")
	}
	return nil
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		h.ServeHTTP(w, r)
	})
}

// spaHandler serves the built admin web, and index.html for any path that
// is not a file, so the web's own routes survive a reload.
func spaHandler(dist fs.FS) http.Handler {
	files := http.FileServerFS(dist)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" {
			if f, err := dist.Open(p); err == nil {
				st, err := f.Stat()
				f.Close()
				if err == nil && !st.IsDir() {
					if strings.HasPrefix(p, "assets/") {
						w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
					}
					files.ServeHTTP(w, r)
					return
				}
			}
		}
		index, err := fs.ReadFile(dist, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	})
}
