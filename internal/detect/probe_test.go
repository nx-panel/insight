package detect_test

import (
	"context"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/nx-panel/insight/internal/detect"
	"github.com/nx-panel/insight/internal/model"
)

func hourRow(t *testing.T, gdb *gorm.DB, hour int64, node uint, inbound string, asn uint32, c model.PathCounters) {
	t.Helper()
	row := model.PathHour{Hour: hour, PathCell: model.PathCell{NodeID: node, Inbound: inbound, ClientASN: asn, Country: "IR", Network: "tcp", SourceKind: "peer"}, PathCounters: c}
	if err := gdb.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
}

func suspicion(t *testing.T, gdb *gorm.DB, node uint, inbound string) detect.Suspicion {
	t.Helper()
	var s detect.Suspicion
	gdb.Where("node_id = ? AND inbound = ?", node, inbound).Limit(1).Find(&s)
	return s
}

// TestAReplayRaisesTheScoreAndProbedOnce:
// replayed handshakes raise the endpoint's score; at ProbedAt one
// endpoint.probed alert goes out, not one per evaluation; the episode ends
// once the evidence ages out, and a path alert that follows is read back as
// the calibration.
func TestAReplayRaisesTheScoreAndProbedOnce(t *testing.T) {
	gdb := openDB(t)
	c := &clock{t: time.Date(2026, 11, 23, 12, 30, 0, 0, time.UTC)}
	var sent []detect.Alert
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t, Send: func(_ context.Context, a detect.Alert) { sent = append(sent, a) }}
	hour := c.t.Truncate(time.Hour).Unix()

	hourRow(t, gdb, hour, 1, "vless-reality", 44244, model.PathCounters{Accepted: 100, Authed: 98, Replayed: 1})
	if err := d.EvaluateProbes(t.Context()); err != nil {
		t.Fatal(err)
	}
	if s := suspicion(t, gdb, 1, "vless-reality"); s.Score != 20 || s.Probed || len(sent) != 0 {
		t.Fatalf("one replay: %+v, sent %d", s, len(sent))
	}
	hourRow(t, gdb, hour, 1, "vless-reality", 58224, model.PathCounters{Accepted: 3, Replayed: 2, FailedTLS: 3})
	for range 2 {
		if err := d.EvaluateProbes(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	s := suspicion(t, gdb, 1, "vless-reality")
	if s.Score != 60 || !s.Probed || s.Replayed != 3 || s.LastEvidence != hour {
		t.Fatalf("three replays: %+v", s)
	}
	if len(sent) != 1 || sent[0].Kind != detect.KindProbed || sent[0].NodeID != 1 || sent[0].Inbound != "vless-reality" {
		t.Fatalf("sent %+v", sent)
	}
	if other := suspicion(t, gdb, 1, "trojan"); other.Score != 0 {
		t.Fatalf("an endpoint with no evidence: %+v", other)
	}

	// A path alert on the endpoint a day later: the probe predicted it.
	gdb.Create(&detect.Alert{Kind: detect.KindDegraded, NodeID: 1, Inbound: "vless-reality", ASN: 44244, At: c.t.Add(24 * time.Hour).Unix()})
	var probed []detect.Alert
	gdb.Where("kind = ?", detect.KindProbed).Find(&probed)
	followed, err := detect.Followed(gdb, probed)
	if err != nil || !followed[probed[0].ID] {
		t.Fatalf("followed = %v, %v", followed, err)
	}

	// Seven hours on, the replays are out of the window: the episode ends,
	// and a new one may alert again.
	c.step(7 * time.Hour)
	if err := d.EvaluateProbes(t.Context()); err != nil {
		t.Fatal(err)
	}
	if s := suspicion(t, gdb, 1, "vless-reality"); s.Score != 0 || s.Probed || s.ProbedAtUnix == 0 {
		t.Fatalf("after the window: %+v", s)
	}
	hourRow(t, gdb, c.t.Truncate(time.Hour).Unix(), 1, "vless-reality", 44244, model.PathCounters{Replayed: 2})
	if err := d.EvaluateProbes(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 {
		t.Fatalf("a second episode sent %d alerts in all", len(sent))
	}
}

// TestFollowUpFailuresCountOnlyAsASurge: follow-up failures add to the
// score only at followMin and three times the endpoint's own week.
func TestFollowUpFailuresCountOnlyAsASurge(t *testing.T) {
	if got := detect.Score(0, 9, 0); got != 0 {
		t.Fatalf("under the floor: %d", got)
	}
	if got := detect.Score(0, 30, 2); got != 20 {
		t.Fatalf("a surge: %d", got)
	}
	if got := detect.Score(0, 30, 12); got != 0 {
		t.Fatalf("a busy inbound's usual: %d", got)
	}
	if got := detect.Score(100, 30, 0); got != 100 {
		t.Fatalf("capped: %d", got)
	}

	gdb := openDB(t)
	c := &clock{t: time.Date(2026, 11, 23, 12, 30, 0, 0, time.UTC)}
	d := &detect.Detector{DB: gdb, Now: c.now, Started: c.t}
	hour := c.t.Truncate(time.Hour).Unix()
	for h := int64(1); h <= 7*24; h += 6 { // the week before: about 4 a window
		hourRow(t, gdb, hour-8*3600-h*3600, 2, "ss", 44244, model.PathCounters{Accepted: 50, FollowUpFail: 4})
	}
	hourRow(t, gdb, hour, 2, "ss", 44244, model.PathCounters{Accepted: 50, FollowUpFail: 11})
	if err := d.EvaluateProbes(t.Context()); err != nil {
		t.Fatal(err)
	}
	if s := suspicion(t, gdb, 2, "ss"); s.Score != 0 || s.FollowNormal < 3 {
		t.Fatalf("11 against a normal near 4: %+v", s)
	}
	hourRow(t, gdb, hour-3600, 2, "ss", 44244, model.PathCounters{Accepted: 50, FollowUpFail: 20})
	if err := d.EvaluateProbes(t.Context()); err != nil {
		t.Fatal(err)
	}
	if s := suspicion(t, gdb, 2, "ss"); s.Score != 20 {
		t.Fatalf("31 against a normal near 4: %+v", s)
	}
}
