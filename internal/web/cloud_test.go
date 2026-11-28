package web

import (
	"strings"
	"testing"

	"github.com/nx-panel/insight/internal/cloud"
	"github.com/nx-panel/insight/internal/netinfo"
)

// TestReportOrgsNameTheReportsNetworks: NX may send a finding with no org;
// the page then names the network, client or host, from this install's own
// ASN table, and the report itself is left as NX signed it.
func TestReportOrgsNameTheReportsNetworks(t *testing.T) {
	asns, err := netinfo.ReadASN(strings.NewReader("5.160.0.0\t5.160.255.255\t197207\tIR\tMCCI-AS Mobile Communication Company of Iran PLC\n" +
		"5.161.0.0\t5.161.255.255\t24940\tDE\tHETZNER-AS\n"))
	if err != nil {
		t.Fatal(err)
	}
	net := &netinfo.DB{}
	net.SetASN(asns)
	s := &Server{net: net}
	rep := &cloud.Report{Countries: []cloud.ReportCountry{{CC: "IR", Findings: []cloud.Finding{
		{Code: "strategy_works", ASN: 197207},
		{Code: "hosting_blocked", ASN: 197207, NodeASN: 24940},
		{Code: "asn_outage", ASN: 64512},
	}}}}
	got := s.reportOrgs(rep)
	if got["197207"] != "MCCI-AS Mobile Communication Company of Iran PLC" || got["24940"] != "HETZNER-AS" || len(got) != 2 {
		t.Fatalf("orgs = %v", got)
	}
	if rep.Countries[0].Findings[0].Org != "" {
		t.Fatal("the held report was changed")
	}
	if n := len(s.reportOrgs(nil)); n != 0 || (&Server{}).reportOrgs(rep) == nil {
		t.Fatal("no report or no table must answer an empty map")
	}
}
