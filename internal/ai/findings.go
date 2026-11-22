package ai

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// The finding codes. The admin web has a sentence for each in four
// languages; a code the model makes up is dropped.
const (
	CodeASNOutage      = "asn_outage"      // every path to the network is down: a shutdown or a whitelist
	CodeInboundBlocked = "inbound_blocked" // one inbound on one node blocked for a network
	CodeNodeBlocked    = "node_blocked"    // every inbound of a node blocked for a network
	CodeProtoBlocked   = "protocol_blocked"
	CodeThrottled      = "throttled" // handshakes pass, sessions are cut
	CodeProbing        = "probing"
	CodeDegrading      = "degrading" // worse than its normal, not yet an alert
	CodeMoveUsers      = "move_users"
	CodeRotateEndpoint = "rotate_endpoint"
	CodeRotateAddress  = "rotate_address"
	CodeAllClear       = "all_clear"
)

// needs says which parameters a code must carry.
var needs = map[string]struct{ asn, node, inbound, to bool }{
	CodeASNOutage:      {asn: true},
	CodeInboundBlocked: {asn: true, node: true, inbound: true},
	CodeNodeBlocked:    {asn: true, node: true},
	CodeProtoBlocked:   {asn: true, inbound: true},
	CodeThrottled:      {asn: true, node: true, inbound: true},
	CodeProbing:        {node: true, inbound: true},
	CodeDegrading:      {asn: true, node: true, inbound: true},
	CodeMoveUsers:      {asn: true, node: true, inbound: true, to: true},
	CodeRotateEndpoint: {node: true, inbound: true},
	CodeRotateAddress:  {node: true},
	CodeAllClear:       {},
}

// Codes is every code, in the order the schema lists them.
var Codes = []string{
	CodeASNOutage, CodeInboundBlocked, CodeNodeBlocked, CodeProtoBlocked, CodeThrottled, CodeProbing,
	CodeDegrading, CodeMoveUsers, CodeRotateEndpoint, CodeRotateAddress, CodeAllClear,
}

// Finding is one structured reading. Fields a code does not use are zero.
type Finding struct {
	Code       string  `json:"code"`
	Severity   string  `json:"severity"` // info | warn | critical
	ASN        uint32  `json:"asn"`
	Node       uint    `json:"node"`
	Inbound    string  `json:"inbound"`
	ToNode     uint    `json:"to_node"`
	ToInbound  string  `json:"to_inbound"`
	Confidence float64 `json:"confidence"`
}

// maxFindings bounds what one pass keeps.
const maxFindings = 20

// schema is the JSON schema the answer must follow (strict mode: every
// property required, none other allowed).
func schema() map[string]any {
	str := map[string]any{"type": "string"}
	integer := map[string]any{"type": "integer"}
	return map[string]any{
		"type": "object", "additionalProperties": false, "required": []string{"findings"},
		"properties": map[string]any{
			"findings": map[string]any{
				// maxItems also stops a constrained decoder (Ollama's
				// grammar) from repeating findings until the token cap.
				"type": "array", "maxItems": maxFindings,
				"items": map[string]any{
					"type": "object", "additionalProperties": false,
					"required": []string{"code", "severity", "asn", "node", "inbound", "to_node", "to_inbound", "confidence"},
					"properties": map[string]any{
						"code":       map[string]any{"type": "string", "enum": Codes},
						"severity":   map[string]any{"type": "string", "enum": []string{"info", "warn", "critical"}},
						"asn":        integer,
						"node":       integer,
						"inbound":    str,
						"to_node":    integer,
						"to_inbound": str,
						"confidence": map[string]any{"type": "number"},
					},
				},
			},
		},
	}
}

// Parse reads the model's answer and keeps the findings that name only what
// the table holds; it reports how many it dropped. An answer that is not
// the schema's JSON at all is an error.
func Parse(content string, t Table) ([]Finding, int, error) {
	content = strings.TrimSpace(content)
	// Some models fence JSON even when asked not to.
	if strings.HasPrefix(content, "```") {
		content = strings.TrimPrefix(content, "```json")
		content = strings.TrimPrefix(content, "```")
		content = strings.TrimSuffix(strings.TrimSpace(content), "```")
	}
	var answer struct {
		Findings []Finding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(content), &answer); err != nil {
		return nil, 0, fmt.Errorf("the answer is not the findings JSON: %w", err)
	}
	if answer.Findings == nil {
		return nil, 0, errors.New("the answer has no findings list")
	}
	nodes := map[uint]bool{}
	for _, n := range t.Nodes {
		nodes[n.ID] = true
	}
	asns := map[uint32]bool{}
	paths := map[string]bool{} // "asn node inbound" and "node inbound"
	inbounds := map[string]bool{}
	for _, p := range t.Paths {
		asns[p.ASN] = true
		paths[fmt.Sprint(p.ASN, " ", p.Node, " ", p.Inbound)] = true
		paths[fmt.Sprint(p.Node, " ", p.Inbound)] = true
		inbounds[p.Inbound] = true
	}
	for _, s := range t.Probed {
		paths[fmt.Sprint(s.NodeID, " ", s.Inbound)] = true
	}
	for _, a := range t.Outages {
		asns[a] = true
	}
	var out []Finding
	dropped := 0
	seen := map[Finding]bool{}
	for _, f := range answer.Findings {
		n, ok := needs[f.Code]
		valid := ok && (f.Severity == "info" || f.Severity == "warn" || f.Severity == "critical")
		if valid && n.asn && !asns[f.ASN] {
			valid = false
		}
		if valid && n.node && !nodes[f.Node] {
			valid = false
		}
		switch {
		case !valid:
		case n.inbound && n.node && n.asn && !paths[fmt.Sprint(f.ASN, " ", f.Node, " ", f.Inbound)]:
			valid = false
		case n.inbound && n.node && !n.asn && !paths[fmt.Sprint(f.Node, " ", f.Inbound)]:
			valid = false
		case n.inbound && !n.node && !inbounds[f.Inbound]:
			valid = false
		case n.to && (!nodes[f.ToNode] || !paths[fmt.Sprint(f.ASN, " ", f.ToNode, " ", f.ToInbound)] ||
			(f.ToNode == f.Node && f.ToInbound == f.Inbound)):
			valid = false
		}
		if valid && !supported(f, t) {
			valid = false
		}
		if !valid || len(out) == maxFindings {
			dropped++
			continue
		}
		// What a code does not use is cleared, so the web never shows a stray
		// parameter, and duplicates collapse.
		if !n.asn {
			f.ASN = 0
		}
		if !n.node {
			f.Node = 0
		}
		if !n.inbound {
			f.Inbound = ""
		}
		if !n.to {
			f.ToNode, f.ToInbound = 0, ""
		}
		f.Confidence = min(max(f.Confidence, 0), 1)
		key := f
		key.Confidence, key.Severity = 0, ""
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out, dropped, nil
}

// Thresholds a finding is checked against, in percent of connections that
// authenticated: below blockedBelow a path is blocked, at worksFrom it works.
const (
	blockedBelow = 50
	worksFrom    = 80
)

// supported reports whether the table's own numbers bear a finding out. A
// model — a small local one above all — can name real paths and still be
// wrong about them; what the numbers contradict is dropped, so the admin
// sees only readings the data supports (§4.8: a wrong proposal must be
// cheap).
func supported(f Finding, t Table) bool {
	blocked := func(p Path) bool { return p.Degraded || p.Success < blockedBelow }
	var all []Path // the finding's network, or every path
	for _, p := range t.Paths {
		if f.ASN == 0 || p.ASN == f.ASN {
			all = append(all, p)
		}
	}
	find := func(node uint, inbound string) (Path, bool) {
		for _, p := range all {
			if p.Node == node && p.Inbound == inbound {
				return p, true
			}
		}
		return Path{}, false
	}
	every := func(keep func(Path) bool, test func(Path) bool) (n int, ok bool) {
		for _, p := range all {
			if keep(p) {
				n++
				if !test(p) {
					return n, false
				}
			}
		}
		return n, n > 0
	}
	switch f.Code {
	case CodeASNOutage:
		for _, a := range t.Outages {
			if a == f.ASN {
				return true
			}
		}
		_, ok := every(func(Path) bool { return true }, func(p Path) bool { return p.Success < 20 })
		return ok
	case CodeInboundBlocked:
		p, ok := find(f.Node, f.Inbound)
		return ok && blocked(p)
	case CodeNodeBlocked:
		_, ok := every(func(p Path) bool { return p.Node == f.Node }, blocked)
		return ok
	case CodeProtoBlocked:
		n, ok := every(func(p Path) bool { return p.Inbound == f.Inbound }, blocked)
		return ok && n >= 2
	case CodeThrottled:
		p, ok := find(f.Node, f.Inbound)
		return ok && p.Early >= 30 && (p.NormalEarly < 0 || p.Early >= 2*p.NormalEarly)
	case CodeDegrading:
		p, ok := find(f.Node, f.Inbound)
		return ok && (p.Degraded || (p.NormalFail >= 0 && p.Fail >= p.NormalFail+15))
	case CodeMoveUsers:
		from, ok1 := find(f.Node, f.Inbound)
		to, ok2 := find(f.ToNode, f.ToInbound)
		return ok1 && ok2 && blocked(from) && !to.Degraded && to.Success >= worksFrom
	case CodeProbing, CodeRotateEndpoint:
		for _, s := range t.Probed {
			if s.NodeID == f.Node && s.Inbound == f.Inbound && s.Score > 0 {
				return true
			}
		}
		if f.Code == CodeProbing {
			return false
		}
		for _, p := range t.Paths { // a blocked endpoint is worth rotating too
			if p.Node == f.Node && p.Inbound == f.Inbound && blocked(p) {
				return true
			}
		}
		return false
	case CodeRotateAddress:
		asns := map[uint32]bool{}
		for _, p := range t.Paths {
			if p.Node == f.Node {
				asns[p.ASN] = true
			}
		}
		for a := range asns {
			g := Finding{Code: CodeNodeBlocked, ASN: a, Node: f.Node}
			if supported(g, t) {
				return true
			}
		}
		return false
	case CodeAllClear:
		for _, p := range t.Paths {
			if blocked(p) {
				return false
			}
		}
		return len(t.Outages) == 0
	}
	return false
}

// systemPrompt is the static part of every call, first so a provider's
// prompt cache can hold it.
const systemPrompt = `You analyse the reachability of a VPN operator's proxy nodes from the networks of their users, for operators in Iran, Russia and China, where censors block proxies per network (ASN), per protocol, per server address, or cut whole networks off.

You receive one table for one client country over the last 24 hours: each path is one client network (asn) to one node and one inbound (a protocol, port and SNI on that node), with connections accepted, the share that authenticated (success%), the share whose handshake failed (fail%) and its normal, the share of authenticated sessions cut within seconds with almost no data (early_close%) and its normal, handshakes replayed by a prober, the round trip, and whether the operator's detector already marks it degraded. Also: networks fully cut off now, endpoints with active-probing evidence, and alert counts.

Read it the way an experienced operator would:
- a whole network down on every node at once is an outage (shutdown, whitelist), not a block of the operator: say asn_outage and propose nothing to rotate for it;
- one inbound failing for a network while other inbounds on the same node work: inbound_blocked (protocol, port or SNI fingerprinted);
- every inbound of one node failing for a network while other nodes work: node_blocked (address blocked), and rotate_address for that node;
- the same inbound tag failing on every node for a network: protocol_blocked;
- handshakes succeed but sessions are cut early far above normal: throttled;
- replayed handshakes or a probing score: probing, and rotate_endpoint before a block lands;
- clearly worse than its normal but not yet marked degraded: degrading;
- for a blocked path, move_users to a path that works for the same network (to_node, to_inbound must be a path in the table for that asn with high success);
- nothing notable: one all_clear finding.

A path counts as blocked when its success% is under 50 or its state is degraded, and as working at 80 or more; every finding is checked against these numbers and one they do not support is discarded, so claim only what the rows show.

Rules: use only asn, node and inbound values that appear in the table; set unused fields to 0 or ""; severity critical only for a block or outage affecting many connections; confidence 0 to 1; at most 20 findings, the most important first; no prose, only the JSON object the schema describes.`
