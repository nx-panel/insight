// Command insight is NX Insight, the official open addon that shows which
// paths from the operator's users to their nodes still work (nx-panel
// docs/path-telemetry.md): it polls the panel's path telemetry, turns each
// client prefix into its network and forgets the prefix, keeps hourly and
// daily cells in its own database, and knows each node's host network.
//
//	insight                                     serve (the default)
//	insight admin reset-password -user U -pass P
//	insight version
//
// Configuration comes from the environment, the way the install passes it
// (internal/config): NX_OPT_PORT, NX_OPT_DATABASE (sqlite|postgres),
// NX_OPT_DATABASE_DSN, NX_OPT_REGION_COUNTRIES, NX_OPT_ASN_URL,
// NX_OPT_CITY_URL, NX_OPT_TELEGRAM_TOKEN, NX_OPT_TELEGRAM_CHAT,
// NX_OPT_TELEGRAM_PROXY, NX_OPT_TELEGRAM_API, NX_CLAIM_CODE, NX_DATA_DIR,
// NX_MANIFEST_FILE.
package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/nx-panel/addon-kit/addon"
	"github.com/nx-panel/addon-kit/manifest"
	"github.com/nx-panel/addon-kit/panel"
	"gorm.io/gorm"

	"github.com/nx-panel/insight/frontend"
	"github.com/nx-panel/insight/internal/admins"
	"github.com/nx-panel/insight/internal/ai"
	"github.com/nx-panel/insight/internal/alert"
	"github.com/nx-panel/insight/internal/cloud"
	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/db"
	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/hints"
	"github.com/nx-panel/insight/internal/ingest"
	"github.com/nx-panel/insight/internal/model"
	"github.com/nx-panel/insight/internal/netinfo"
	"github.com/nx-panel/insight/internal/tunnels"
	"github.com/nx-panel/insight/internal/web"
)

//go:embed nx-addon.json
var builtinManifest []byte

func main() {
	log.SetFlags(log.LstdFlags)
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "run":
		err = run()
	case "admin":
		err = adminCmd(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("insight", version())
	default:
		err = fmt.Errorf("unknown command %q: run, admin reset-password, version", cmd)
	}
	if err != nil {
		log.Fatal(err)
	}
}

// version is the manifest's, read without addon.New, which would draw a
// claim code into the data directory as a side effect.
func version() string {
	m, err := manifest.Parse(builtinManifest)
	if err != nil {
		return "unknown"
	}
	return m.Version
}

const (
	nodesEvery   = time.Hour
	compactEvery = time.Hour
)

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	gdb, err := db.Open(cfg)
	if err != nil {
		return err
	}
	raw := builtinManifest
	if cfg.ManifestFile != "" {
		if raw, err = os.ReadFile(cfg.ManifestFile); err != nil {
			return fmt.Errorf("NX_MANIFEST_FILE: %w", err)
		}
	}
	a, err := addon.New(addon.Config{Manifest: raw, DataDir: cfg.DataDir, Healthy: web.Healthy(gdb)}.FromEnv())
	if err != nil {
		return err
	}
	if made, err := admins.EnsureFirst(gdb, cfg.AdminUsername, cfg.AdminPassword); err != nil {
		return fmt.Errorf("the first admin: %w", err)
	} else if made {
		log.Printf("made the first admin, %q, from the install's answers", cfg.AdminUsername)
	}
	a.OnEvent(func(e addon.Event) {
		// The panel says goodbye before it deletes the token: forget the
		// credentials so Insight can be registered again.
		if e.Event == "panel.addon_removed" {
			if err := a.Forget(); err != nil {
				log.Printf("forget: %v", err)
			}
		}
	})
	client := func() ingest.Getter {
		c := a.Credentials()
		if c == nil || c.Token == "" {
			return nil
		}
		return &panel.Client{Base: c.Panel.URL, Token: c.Token}
	}

	net := &netinfo.DB{}
	nodes := &ingest.Nodes{DB: gdb, Net: net, Panel: client}
	mgr := &netinfo.Manager{
		DB: net, Dir: filepath.Join(cfg.DataDir, "netinfo"),
		Sources: netinfo.Sources{ASNURL: cfg.ASNURL, CityURL: cfg.CityURL, RegionCountries: cfg.RegionCountries},
	}
	nodes.CityFile = func() string {
		if _, err := os.Stat(mgr.CityPath()); err != nil {
			return ""
		}
		return mgr.CityPath()
	}
	tg, err := alert.NewTelegram(cfg.TelegramToken, cfg.TelegramChat, cfg.TelegramProxy, cfg.TelegramAPI, cfg.Language, alert.Names{
		Node: func(id uint) string {
			var n model.NodeNetinfo
			if gdb.Select("name").Limit(1).Find(&n, id).Error == nil {
				return n.Name
			}
			return ""
		},
		ASN: net.Org,
	})
	if err != nil {
		return fmt.Errorf("telegram_proxy: %w", err)
	}
	bg, stopBg := context.WithCancel(context.Background())
	defer stopBg()
	// Alerts are sent off the poll's goroutine: Telegram unreachable (the
	// usual state of a server in Iran or Russia without a proxy) at twenty
	// seconds an alert would hold the next polls back past what the panel
	// keeps, and the hole would read as more drops. A burst past the queue
	// loses its oldest sends; every alert is in the database either way.
	var send func(context.Context, detect.Alert)
	if tg != nil {
		queue := make(chan detect.Alert, 256)
		send = func(_ context.Context, a detect.Alert) {
			for {
				select {
				case queue <- a:
					return
				default:
				}
				select {
				case <-queue:
				default:
				}
			}
		}
		go func() {
			for {
				select {
				case <-bg.Done():
					return
				case a := <-queue:
					tg.Send(bg, a)
				}
			}
		}()
	}
	in, det, _ := pipeline(gdb, net, client, send)
	// The tunnels behind the relays (P26): a tunnel with no link speaks for
	// its relay's paths.
	tw := &tunnels.Watcher{DB: gdb, Send: send, Panel: func() tunnels.Getter {
		if c := client(); c != nil {
			return c
		}
		return nil
	}}
	det.TunnelDown = tw.Down

	// Mode A: the admin's own model reads the paths after a flush when a
	// pass is due (internal/ai); off until the admin sets it up.
	brain := &ai.Runner{DB: gdb, State: det, Org: net.Org, Countries: cfg.RegionCountries, Tunnels: tw.Views}
	// Mode B: the closed hours to NX's cloud and its report back, off until
	// the admin turns it on (internal/cloud).
	nx := &cloud.Cloud{
		DB: gdb, URL: cfg.CloudURL,
		Sources: cloud.Sources{DB: gdb, State: det, Shapes: in.Shapes, Tunnels: tw.Views, Org: net.Org, Version: a.Manifest().Version},
		Panel: func() cloud.Panel {
			c := a.Credentials()
			if c == nil || c.Token == "" {
				return nil
			}
			return &panel.Client{Base: c.Panel.URL, Token: c.Token}
		},
	}
	flushed := in.AfterFlush
	in.AfterFlush = func(ctx context.Context) {
		flushed(ctx)
		brain.Tick(bg)
	}
	var work sync.WaitGroup
	refreshNodes := func() {
		if err := nodes.Refresh(bg); err != nil {
			log.Printf("nodes: %v", err)
		}
	}
	mgr.OnCity = refreshNodes
	a.OnSetup(func(addon.Credentials) { go refreshNodes() })
	work.Go(func() { mgr.Run(bg) })
	work.Go(func() { in.Run(bg) })
	work.Go(func() { tw.Run(bg) })
	work.Go(func() { nx.Run(bg) })
	work.Go(func() { every(bg, nodesEvery, refreshNodes) })
	work.Go(func() {
		every(bg, compactEvery, func() {
			if err := ingest.Compact(bg, gdb, time.Now()); err != nil {
				log.Printf("retention: %v", err)
			}
			if err := det.Prune(bg); err != nil {
				log.Printf("retention: %v", err)
			}
			if err := admins.SweepSessions(gdb.WithContext(bg), time.Now()); err != nil {
				log.Printf("retention: %v", err)
			}
		})
	})

	var spa fs.FS
	if sub, err := fs.Sub(frontend.Dist, "dist"); err == nil {
		if _, err := fs.Stat(sub, "index.html"); err == nil {
			spa = sub
		}
	}
	app := web.New(gdb, a, cfg, a.Manifest().Version, spa, web.Parts{Ingest: in, Detect: det, Net: net, AI: brain, Countries: cfg.RegionCountries, Tunnels: tw, Cloud: nx})
	srv := &http.Server{
		Addr: cfg.Addr(), Handler: app.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute,
	}
	log.Printf("nx insight %s on %s (%s)", a.Manifest().Version, cfg.Addr(), cfg.Driver)
	httpsCtx, stopHTTPS := context.WithCancel(context.Background())
	defer stopHTTPS()
	errs := make(chan error, 1)
	if app.HTTPS() {
		go func() { errs <- app.ServeHTTPS(httpsCtx) }()
	} else {
		go func() { errs <- srv.ListenAndServe() }()
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errs:
		stopBg()
		work.Wait()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-stop:
		var err error
		if app.HTTPS() {
			stopHTTPS()
			select {
			case err = <-errs:
				if errors.Is(err, http.ErrServerClosed) {
					err = nil
				}
			case <-time.After(11 * time.Second):
			}
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err = srv.Shutdown(ctx)
		}
		// The last flush runs as the ingest loop ends.
		stopBg()
		work.Wait()
		return err
	}
	return nil
}

// adminCmd is the recovery path: set an admin's password (making the
// account if it is not there), turning its second factor off and ending its
// sessions.
func adminCmd(args []string) error {
	if len(args) == 0 || args[0] != "reset-password" {
		return errors.New("usage: insight admin reset-password -user U -pass P")
	}
	fl := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	user := fl.String("user", "admin", "the admin's username")
	pass := fl.String("pass", "", "the new password (at least 10 characters)")
	if err := fl.Parse(args[1:]); err != nil {
		return err
	}
	if *pass == "" {
		return errors.New("-pass is required")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	gdb, err := db.Open(cfg)
	if err != nil {
		return err
	}
	if err := admins.ResetPassword(gdb, *user, *pass); err != nil {
		return err
	}
	fmt.Printf("the password of %q is set; its two-factor sign-in is off and its sessions ended\n", *user)
	return nil
}

// every runs f now and then at each interval for the life of ctx.
func every(ctx context.Context, d time.Duration, f func()) {
	f()
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f()
		}
	}
}

// pipeline wires the poll to the detector and the hints: every polled
// sample feeds the detector's window, and after every flush the detector
// judges the paths and the endpoints' probe evidence and the hints are
// pushed.
func pipeline(gdb *gorm.DB, net *netinfo.DB, client func() ingest.Getter, send func(context.Context, detect.Alert)) (*ingest.Ingest, *detect.Detector, *hints.Hints) {
	det := &detect.Detector{DB: gdb, Send: send}
	hint := &hints.Hints{DB: gdb, Prefixes: net.Prefixes, State: det, Panel: func() hints.Putter {
		if p, ok := client().(hints.Putter); ok {
			return p
		}
		return nil
	}}
	in := &ingest.Ingest{
		DB: gdb, Net: net, Panel: client,
		Observe: func(node uint, inbound string, asn uint32, network string, c model.PathCounters) {
			det.Observe(detect.Key{Node: node, Inbound: inbound, ASN: asn, Network: network}, c)
		},
		Gapped: det.Gapped,
		Fed: func(ok bool, nodes []ingest.NodeState) {
			if !ok {
				det.Lost()
				return
			}
			det.Covered(ingest.Counting(nodes))
		},
		AfterFlush: func(ctx context.Context) {
			if err := det.Evaluate(ctx); err != nil {
				log.Printf("detect: %v", err)
			}
			if err := det.EvaluateProbes(ctx); err != nil {
				log.Printf("detect probes: %v", err)
			}
			if err := hint.Push(ctx); err != nil {
				log.Printf("hints: %v", err)
			}
		},
	}
	return in, det, hint
}
