// Command demo fills an Insight data directory with made-up but plausible
// data, to look at the admin web without a panel, nodes or users: client
// networks in Iran, Russia and abroad over the last day, four nodes, alerts,
// a probed endpoint, AI reports, and Mode B's batches and report.
//
//	go run ./tools/demo -dir /tmp/insight-demo [-feed seed-file]
//	go run ./tools/demo -cloud 127.0.0.1:8790
//
// Then run Insight on that directory (NX_DATA_DIR) with NX_CLOUD_URL at the
// second command's address, which answers like NX's cloud with nothing new.
// -feed is the base64 seed of NX's feed key: without it the NX report is
// left out, since Insight shows only a report NX signed. Nothing here is
// real; every address is a documentation or private one.
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/ai"
	"github.com/nx-panel/insight/internal/cloud"
	"github.com/nx-panel/insight/internal/config"
	"github.com/nx-panel/insight/internal/db"
	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/model"
)

type network struct {
	asn     uint32
	cc, org string
	regions []string
	weight  float64 // share of the traffic
}

// The client networks, with names as long as the registries write them.
var networks = []network{
	{197207, "IR", "MCCI-AS Mobile Communication Company of Iran PLC", []string{"Tehran", "Isfahan", "Razavi Khorasan", "Fars", "Khuzestan"}, 1},
	{44244, "IR", "IRANCELL-AS Iran Cell Service and Communication Company", []string{"Tehran", "Isfahan", "East Azerbaijan", "Fars"}, 0.8},
	{58224, "IR", "TCI Iran Telecommunication Company PJS", []string{"Tehran", "Razavi Khorasan", "Khuzestan", "Gilan"}, 0.6},
	{57218, "IR", "RIGHTEL-AS Rightel Communication Service Company PJS", []string{"Tehran", "Isfahan"}, 0.2},
	{31549, "IR", "SHATEL-AS Aria Shatel PJSC", []string{"Tehran", "Isfahan"}, 0.25},
	{43754, "IR", "ASIATECH-AS Asiatech Data Transmission company", []string{"Tehran"}, 0.15},
	{16322, "IR", "PARSONLINE Pars Online PJS", []string{"Tehran", "Fars"}, 0.12},
	{8359, "RU", "MTS PJSC MTS", []string{"Moscow", "Saint Petersburg", "Novosibirsk Oblast"}, 0.3},
	{12389, "RU", "ROSTELECOM-AS PJSC Rostelecom", []string{"Moscow", "Tatarstan Republic"}, 0.2},
	{3320, "DE", "DTAG Deutsche Telekom AG", nil, 0.08},
	{9121, "TR", "TTNET Turk Telekom", nil, 0.06},
	{5384, "AE", "EMIRATES-INTERNET Emirates Internet", nil, 0.05},
	{2856, "GB", "BT-UK-AS British Telecommunications PLC", nil, 0.03},
}

type node struct {
	id               uint
	name, addr       string
	asn              uint32
	org, cc, city    string
	inbounds         []inbound
	blockedFor       map[uint32]bool // the networks this node's address is listed for
	blockedInboundOf map[string]map[uint32]bool
}

type inbound struct{ tag, network string }

var nodes = []node{
	{
		1, "de-fra-1", "203.0.113.10", 24940, "HETZNER-AS Hetzner Online GmbH", "DE", "Frankfurt am Main",
		[]inbound{{"vless-reality", "tcp"}, {"vless-xhttp-cdn", "tcp"}, {"hysteria2", "udp"}},
		nil,
		map[string]map[uint32]bool{"hysteria2": {197207: true, 58224: true}},
	},
	{
		2, "nl-ams-1", "203.0.113.20", 14061, "DIGITALOCEAN-ASN DigitalOcean, LLC", "NL", "Amsterdam",
		[]inbound{{"vless-reality", "tcp"}, {"trojan-ws", "tcp"}},
		map[uint32]bool{44244: true},
		nil,
	},
	{
		3, "fi-hel-1", "198.51.100.30", 24940, "HETZNER-AS Hetzner Online GmbH", "FI", "Helsinki",
		[]inbound{{"vless-reality", "tcp"}, {"hysteria2", "udp"}},
		nil,
		map[string]map[uint32]bool{"vless-reality": {197207: true}},
	},
	{
		4, "ir-thr-relay", "192.0.2.40", 43754, "ASIATECH-AS Asiatech Data Transmission company", "IR", "Tehran",
		[]inbound{{"vless-reality", "tcp"}},
		nil, nil,
	},
}

func main() {
	dir := flag.String("dir", "", "the Insight data directory to fill")
	feed := flag.String("feed", "", "file holding the base64 seed of NX's feed key (optional)")
	stub := flag.String("cloud", "", "serve a stand-in for NX's cloud on this address instead")
	flag.Parse()
	if *stub != "" {
		serveCloud(*stub)
		return
	}
	if *dir == "" {
		log.Fatal("-dir is needed")
	}
	if err := seed(*dir, *feed); err != nil {
		log.Fatal(err)
	}
	fmt.Println("filled", *dir)
}

// serveCloud answers Mode B's two calls the way NX's cloud does when it
// has nothing newer: batches are taken, a report request is told so.
func serveCloud(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/batch", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	mux.HandleFunc("POST /v1/report", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"new":false}`))
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("stand-in cloud on http://%s", addr)
	log.Fatal(srv.ListenAndServe())
}

func seed(dir, feedFile string) error {
	ctx := context.Background()
	if err := os.MkdirAll(filepath.Join(dir, "netinfo"), 0o700); err != nil {
		return err
	}
	if err := fixtures(filepath.Join(dir, "netinfo")); err != nil {
		return err
	}
	gdb, err := db.Open(config.Config{Driver: config.DriverSQLite, DSN: filepath.Join(dir, "insight.db")})
	if err != nil {
		return err
	}
	now := time.Now()
	hour := now.Truncate(time.Hour)
	r := rand.New(rand.NewPCG(7, 11))

	for _, n := range nodes {
		row := model.NodeNetinfo{NodeID: n.id, Name: n.name, Address: n.addr, ASN: n.asn, Org: n.org, Country: n.cc, City: n.city, UpdatedAt: now.Unix()}
		if err := gdb.Save(&row).Error; err != nil {
			return err
		}
	}

	// Thirty hours of cells: each network on each node and inbound, by
	// region, with the day's rhythm, the blocks above and some noise.
	var cells []model.PathHour
	for h := 0; h < 30; h++ {
		at := hour.Add(-time.Duration(h) * time.Hour)
		rhythm := 0.55 + 0.45*math.Sin(float64(at.UTC().Hour()-14)/24*2*math.Pi+math.Pi/2)
		for _, nw := range networks {
			regions := nw.regions
			if len(regions) == 0 {
				regions = []string{""}
			}
			for ri, region := range regions {
				share := nw.weight / float64(ri+1)
				for _, n := range nodes {
					if n.id == 4 && nw.cc != "IR" {
						continue // the relay in Tehran serves Iran only
					}
					for _, ib := range n.inbounds {
						base := 400 * share * rhythm * (0.7 + 0.6*r.Float64())
						if ib.network == "udp" {
							base *= 0.5
						}
						accepted := uint64(base)
						if accepted < 3 {
							continue
						}
						ok := 0.93 + 0.06*r.Float64()
						switch {
						case n.blockedFor[nw.asn]:
							ok = 0.02 + 0.05*r.Float64()
						case n.blockedInboundOf[ib.tag][nw.asn]:
							ok = 0.05 + 0.2*r.Float64()
						case nw.asn == 58224 && ib.tag == "vless-xhttp-cdn":
							ok = 0.62 + 0.1*r.Float64() // middling: a throttled CDN path
						}
						authed := uint64(float64(accepted) * ok)
						fail := accepted - authed
						rtt := uint64(120 + r.IntN(140))
						if nw.cc != "IR" {
							rtt = uint64(40 + r.IntN(60))
						}
						cells = append(cells, model.PathHour{
							Hour: at.Unix(),
							PathCell: model.PathCell{
								NodeID: n.id, Inbound: ib.tag, ClientASN: nw.asn, Country: nw.cc,
								Region: region, Network: ib.network, SourceKind: "inbound",
							},
							PathCounters: model.PathCounters{
								Accepted: accepted, Authed: authed, EarlyClose: authed / 25,
								FailedTLS: fail * 6 / 10, FailedTimeout: fail * 3 / 10, FailedReset: fail - fail*6/10 - fail*3/10,
								RTTSum: rtt * authed, RTTN: authed, DurSum: 340 * authed, DurN: authed,
								Up: int64(authed) * 180_000, Down: int64(authed) * 2_400_000,
							},
						})
					}
				}
			}
		}
	}
	if err := gdb.CreateInBatches(cells, 500).Error; err != nil {
		return err
	}

	// Alerts, newest first when read.
	alerts := []detect.Alert{
		{Kind: detect.KindDegraded, NodeID: 1, Inbound: "hysteria2", ASN: 197207, Network: "udp", Reason: "failures", At: now.Add(-26 * time.Hour).Unix(), Detail: `{"failRatio":0.91,"normalFailRatio":0.06}`},
		{Kind: detect.KindDegraded, NodeID: 2, Inbound: "vless-reality", ASN: 44244, Network: "tcp", Reason: "failures", At: now.Add(-20 * time.Hour).Unix(), Detail: `{"failRatio":0.95,"normalFailRatio":0.04}`},
		{Kind: detect.KindProbed, NodeID: 3, Inbound: "vless-reality", At: now.Add(-9 * time.Hour).Unix(), Detail: `{"score":60,"replayed":7}`},
		{Kind: detect.KindDegraded, NodeID: 3, Inbound: "vless-reality", ASN: 197207, Network: "tcp", Reason: "drop", At: now.Add(-5 * time.Hour).Unix(), Detail: `{"authedPerHour":14,"normalAuthedPerHour":210}`},
		{Kind: detect.KindDegraded, NodeID: 1, Inbound: "vless-xhttp-cdn", ASN: 58224, Network: "tcp", Reason: "early_close", At: now.Add(-3 * time.Hour).Unix(), Detail: `{"earlyRatio":0.38,"normalEarlyRatio":0.05}`},
		{Kind: detect.KindOutage, ASN: 57218, At: now.Add(-2 * time.Hour).Unix(), Detail: `{"paths":6,"nodes":3}`},
		{Kind: detect.KindOutageEnd, ASN: 57218, At: now.Add(-90 * time.Minute).Unix()},
	}
	if err := gdb.Create(&alerts).Error; err != nil {
		return err
	}
	if err := gdb.Save(&detect.Suspicion{
		NodeID: 3, Inbound: "vless-reality", Score: 60, Replayed: 7, FollowUpFail: 31, FollowNormal: 6,
		NoRoute: 4, QUICStray: 0, Failed: 220, Accepted: 2400, Probed: true,
		ProbedAtUnix: now.Add(-9 * time.Hour).Unix(), LastEvidence: hour.Add(-time.Hour).Unix(), UpdatedAt: now.Unix(),
	}).Error; err != nil {
		return err
	}

	// Mode A: a model set up, and a report per country.
	if err := ai.Save(ctx, gdb, ai.Settings{Enabled: true, URL: "https://api.openai.com/v1", Model: "gpt-4.1-mini", Key: "demo-not-a-key", DailyTokens: 100_000}); err != nil {
		return err
	}
	reports := []ai.Report{
		{Country: "IR", Trigger: "daily", At: now.Add(-7 * time.Hour).Unix(), Model: "gpt-4.1-mini", Tokens: 11840, Status: "ok", Rows: 212, Findings: mustJSON([]map[string]any{
			{"code": "node_blocked", "severity": "critical", "asn": 44244, "node": 2, "confidence": 0.9},
			{"code": "inbound_blocked", "severity": "critical", "asn": 197207, "node": 1, "inbound": "hysteria2", "confidence": 0.85},
			{"code": "move_users", "severity": "warn", "asn": 44244, "node": 2, "inbound": "vless-reality", "to_node": 1, "to_inbound": "vless-reality", "confidence": 0.8},
			{"code": "throttled", "severity": "warn", "asn": 58224, "node": 1, "inbound": "vless-xhttp-cdn", "confidence": 0.6},
			{"code": "probing", "severity": "warn", "node": 3, "inbound": "vless-reality", "confidence": 0.7},
			{"code": "rotate_endpoint", "severity": "info", "node": 3, "inbound": "vless-reality", "confidence": 0.65},
		})},
		{Country: "RU", Trigger: "daily", At: now.Add(-7 * time.Hour).Unix(), Model: "gpt-4.1-mini", Tokens: 4120, Status: "ok", Rows: 38, Findings: mustJSON([]map[string]any{
			{"code": "all_clear", "severity": "info", "confidence": 0.8},
		})},
		{Country: "CN", Trigger: "daily", At: now.Add(-7 * time.Hour).Unix(), Model: "gpt-4.1-mini", Status: "empty"},
	}
	if err := gdb.Create(&reports).Error; err != nil {
		return err
	}

	// Mode B: on since a day ago, its batches, and NX's report.
	if err := cloud.SeedOn(ctx, gdb, hour.Unix()); err != nil {
		return err
	}
	for h := 1; h <= 6; h++ {
		at := hour.Add(-time.Duration(h) * time.Hour).Unix()
		body, n, err := batch(at)
		if err != nil {
			return err
		}
		o := model.CloudOutbox{Hour: at, Body: body, Cells: n, CreatedAt: at + 3700, Attempts: 1, SentAt: at + 3720}
		if h == 1 {
			o.SentAt, o.NextAt = 0, now.Add(4*time.Minute).Unix()
		}
		if err := gdb.Save(&o).Error; err != nil {
			return err
		}
	}
	if feedFile != "" {
		if err := report(ctx, gdb, feedFile, now); err != nil {
			return err
		}
	}
	return nil
}

// fixtures are the network databases Insight would download, cut down to
// the demo's networks; fresh, so it loads them and asks for nothing.
func fixtures(dir string) error {
	var asn, city bytes.Buffer
	all := append([]network{}, networks...)
	for _, n := range nodes {
		all = append(all, network{asn: n.asn, cc: n.cc, org: n.org})
	}
	for i, n := range all {
		fmt.Fprintf(&asn, "10.%d.0.0\t10.%d.255.255\t%d\t%s\t%s\n", i+1, i+1, n.asn, n.cc, n.org)
		region := "Unknown"
		if len(n.regions) > 0 {
			region = n.regions[0]
		}
		fmt.Fprintf(&city, "10.%d.0.0,10.%d.255.255,AS,%s,%s,%s,0,0\n", i+1, i+1, n.cc, region, region)
	}
	for name, b := range map[string][]byte{"ip2asn.tsv.gz": asn.Bytes(), "dbip-city-lite.csv.gz": city.Bytes()} {
		var z bytes.Buffer
		w := gzip.NewWriter(&z)
		if _, err := w.Write(b); err != nil {
			return err
		}
		if err := w.Close(); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), z.Bytes(), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// batch is one hour as Mode B would have sent it.
func batch(hour int64) ([]byte, int, error) {
	b := cloud.Batch{V: 1, Hour: hour, Insight: "demo"}
	for _, nw := range networks[:5] {
		for _, n := range nodes[:3] {
			for _, ib := range n.inbounds {
				proto, transport, security, front := "vless", "tcp", "reality", "direct"
				switch ib.tag {
				case "vless-xhttp-cdn":
					transport, security, front = "xhttp", "tls", "cdn"
				case "hysteria2":
					proto, transport, security = "hysteria2", "-", "tls"
				case "trojan-ws":
					proto, transport, security = "trojan", "ws", "tls"
				}
				verdict := "ok"
				accepted, authed := uint64(300), uint64(285)
				if n.blockedFor[nw.asn] {
					verdict, authed = "node_blocked", 9
				} else if n.blockedInboundOf[ib.tag][nw.asn] {
					verdict, authed = "degraded", 40
				}
				b.Cells = append(b.Cells, cloud.Cell{
					ASN: nw.asn, CC: nw.cc, Region: nw.regions[0], Org: nw.org,
					NodeASN: n.asn, NodeCC: n.cc, NodeOrg: n.org,
					Proto: proto, Transport: transport, Security: security, Front: front, Network: ib.network,
					Verdict: verdict, Accepted: accepted, Authed: authed,
				})
			}
		}
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return nil, 0, err
	}
	var z bytes.Buffer
	w := gzip.NewWriter(&z)
	if _, err := w.Write(raw); err != nil {
		return nil, 0, err
	}
	if err := w.Close(); err != nil {
		return nil, 0, err
	}
	return z.Bytes(), len(b.Cells), nil
}

// report writes a report signed with the feed key, as Insight keeps one.
func report(ctx context.Context, gdb *gorm.DB, feedFile string, now time.Time) error {
	raw, err := os.ReadFile(feedFile)
	if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("%s is not a base64 Ed25519 seed", feedFile)
	}
	from, to := now.Add(-24*time.Hour).Truncate(time.Hour).Unix(), now.Truncate(time.Hour).Unix()
	r := cloud.Report{V: 1, ExtractedAt: now.Add(-2 * time.Hour).Unix(), Tier: "full", Countries: []cloud.ReportCountry{
		{CC: "IR", From: from, To: to, Contributors: "10+", Findings: []cloud.Finding{
			{Code: "strategy_blocked", Severity: "critical", ASN: 197207, Org: networks[0].org, Strategy: "hysteria2/-/tls/direct", Confidence: 0.92},
			{Code: "hosting_blocked", Severity: "critical", ASN: 44244, Org: networks[1].org, NodeASN: 14061, Confidence: 0.81},
			{Code: "strategy_works", Severity: "info", ASN: 197207, Org: networks[0].org, Strategy: "vless/xhttp/tls/cdn", Confidence: 0.88},
			{Code: "throttled", Severity: "warn", ASN: 58224, Org: networks[2].org, Strategy: "vless/xhttp/tls/cdn", Confidence: 0.64},
			{Code: "probing", Severity: "warn", Strategy: "vless/tcp/reality/direct", Confidence: 0.6},
		}},
		{CC: "RU", From: from, To: to, Contributors: "5-9", Findings: []cloud.Finding{
			{Code: "strategy_degraded", Severity: "warn", ASN: 8359, Org: networks[7].org, Strategy: "vless/tcp/reality/direct", Confidence: 0.58},
			{Code: "strategy_works", Severity: "info", ASN: 12389, Org: networks[8].org, Strategy: "trojan/ws/tls/direct", Confidence: 0.75},
		}},
	}}
	payload, err := json.Marshal(r)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), append([]byte(cloud.ReportContext), payload...))
	return cloud.SeedReport(ctx, gdb, string(payload), base64.StdEncoding.EncodeToString(sig), now.Add(-10*time.Minute).Unix(), r.ExtractedAt)
}

func mustJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
