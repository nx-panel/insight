#!/usr/bin/env bash
# The two-ASN walk (compose.yml). Steps, each idempotent enough to rerun:
#
#   run.sh build     cross-build panel (addondev), node and Insight into $WALK
#   run.sh up        fixtures, stack, panel wiring (nodes, inbound, template,
#                    user), client configs, Insight registered and approved
#   run.sh status    what Insight sees: feed, matrix by network
#   run.sh seed      stop Insight, give every path a normal from what the
#                    last hour counted (instead of six hours of history),
#                    start it again
#   run.sh block     node 1 drops ISP A's data packets after the TCP
#                    handshake, as a DPI box does: accepted, never authed
#   run.sh check     alerts, hints, and each ISP's subscription order
#   run.sh tunnel    a tunnel: node 1 relays, node 2 is the origin (reverse,
#                    port 21000), so node 1's users go out through node 2
#   run.sh cut       node 1 drops the tunnel's port and the links are reset:
#                    the tunnel has no link, node 1's sessions authenticate
#                    and then carry nothing (P26: tunnel.down, no
#                    path.degraded on every network); mend undoes it
#   run.sh metrics   Prometheus scraping Insight's /metrics and Grafana with
#                    the panel repository's nx-insight dashboard on
#                    http://127.0.0.1:13000
#   run.sh down      stop and remove the stack (WALK keeps the data)
#
# Needs docker, jq, sqlite3 and the sibling checkouts ../nx-panel and
# ../nx-node on their path-telemetry branches, and ../panel for the
# dashboard. WALK defaults to a scratch
# directory under /tmp.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)" # the directory holding insight, nx-panel, nx-node
export WALK="${WALK:-/tmp/insight-walk}"
export DASHBOARDS="$ROOT/panel/monitoring/grafana/dashboards"
PANEL=http://127.0.0.1:12095
INSIGHT=http://127.0.0.1:18099
dc() { docker compose -f "$HERE/compose.yml" "$@"; }
say() { printf '\033[1;35m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

arch() { case "$(uname -m)" in arm64 | aarch64) echo arm64 ;; *) echo amd64 ;; esac; }

build() {
	mkdir -p "$WALK/bin"
	local a; a="$(arch)"
	# addondev: it trusts the development-signed manifest; 0.2.0: the release
	# that carries path telemetry, which the manifest asks for.
	say "panel"
	(cd "$ROOT/nx-panel/frontend" && npm run -s build >/dev/null)
	(cd "$ROOT/nx-panel" && CGO_ENABLED=0 GOOS=linux GOARCH="$a" go build -tags addondev -ldflags "-X main.Version=0.2.0" -o "$WALK/bin/nx-panel" ./cmd/nx-panel)
	say "node"
	(cd "$ROOT/nx-node" && CGO_ENABLED=0 GOOS=linux GOARCH="$a" go build -o "$WALK/bin/nx-node" ./cmd/nx-node)
	say "insight"
	(cd "$ROOT/insight/frontend" && npm run -s build >/dev/null)
	(cd "$ROOT/insight" && CGO_ENABLED=0 GOOS=linux GOARCH="$a" go build -o "$WALK/bin/insight" . && scripts/sign.sh -dev >/dev/null && cp signed.json "$WALK/insight-signed.json")
}

# The fixture network database: ISP A and ISP B as two Iranian networks,
# the core network (the nodes) as a German host.
fixtures() {
	mkdir -p "$WALK/www"
	# Eight kilobytes: a session that fetches it moves more than the 2 KiB
	# under which a short session counts as cut early, so a session that
	# carries nothing — the tunnel cut behind its node — stands out.
	head -c 8192 /dev/zero | tr '\0' 'w' >"$WALK/www/index.html"
	printf '10.80.0.0\t10.80.0.255\t64500\tDE\tWALK-HOSTER\n10.81.0.0\t10.81.0.255\t64501\tIR\tWALK-ISP-A\n10.82.0.0\t10.82.0.255\t64502\tIR\tWALK-ISP-B\n' |
		gzip >"$WALK/www/ip2asn.tsv.gz"
	printf '10.80.0.0,10.80.0.255,EU,DE,Hesse,Frankfurt,0,0\n10.81.0.0,10.81.0.255,AS,IR,Tehran,Tehran,0,0\n10.82.0.0,10.82.0.255,AS,IR,Isfahan,Isfahan,0,0\n' |
		gzip >"$WALK/www/city.csv.gz"
	# Insight downloads over HTTPS only: the fixtures are put where it
	# keeps its copies, fresh, so it loads them and asks for nothing.
	mkdir -p "$WALK/insight/netinfo"
	cp "$WALK/www/ip2asn.tsv.gz" "$WALK/insight/netinfo/ip2asn.tsv.gz"
	cp "$WALK/www/city.csv.gz" "$WALK/insight/netinfo/dbip-city-lite.csv.gz"
}

tok() {
	curl -sf -X POST "$PANEL/api/login" -H 'Content-Type: application/json' \
		-d '{"username":"admin","password":"walk-admin-1"}' | jq -r .token
}
api() { # api METHOD PATH [BODY]
	curl -sf -X "$1" "$PANEL$2" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' ${3:+-d "$3"}
}

up() {
	[ -x "$WALK/bin/insight" ] || build
	fixtures
	mkdir -p "$WALK"/{panel,node1,node2,insight}
	dc up -d origin panel
	for _ in $(seq 60); do curl -sf -o /dev/null "$PANEL/" && break; sleep 1; done
	TOK="$(tok)"; [ -n "$TOK" ] || die "panel login"

	for n in 1 2; do
		if [ ! -f "$WALK/node$n/certs/panel_ca.pem" ]; then
			say "node$n: the panel's CA, a server certificate"
			it="$(api POST /api/tokens/node-install | jq -r .token)"
			mkdir -p "$WALK/node$n/certs"
			curl -sf "$PANEL/install/ca?token=$it" -o "$WALK/node$n/certs/panel_ca.pem"
			docker run --rm -e NX_STATE_DIR=/walk/node$n -v "$WALK:/walk" alpine:3.24 /walk/bin/nx-node gencerts >/dev/null
		fi
	done
	dc up -d node1 node2

	if [ "$(api GET /api/nodes | jq length)" = 0 ]; then
		say "inbound, template, nodes, user"
		ib="$(api POST /api/inbounds '{"tag":"vless-walk","type":"vless","config":{"listen":"::","listen_port":20001}}' | jq -r .id)"
		tp="$(api POST /api/templates "{\"name\":\"walk\",\"inboundIds\":[$ib]}" | jq -r .id)"
		for n in 1 2; do
			api POST /api/nodes "{\"name\":\"node$n\",\"address\":\"10.80.0.2$n\",\"port\":62050,\"enable\":true,\"templateId\":$tp}" >/dev/null
		done
		api POST /api/users '{"name":"walker","enable":true,"allTemplates":true}' >/dev/null
	fi
	say "waiting for both nodes to connect and serve"
	for _ in $(seq 60); do
		[ "$(api GET /api/nodes | jq '[.[] | select(.status=="connected")] | length')" = 2 ] && break
		sleep 3
	done
	api GET /api/nodes | jq -r '.[] | "\(.name) \(.status) \(.message // "")"'

	uuid="$(api GET /api/users | jq -r '.[] | select(.name=="walker") | .config.uuid')"
	[ -n "$uuid" ] && [ "$uuid" != null ] || die "the walker's uuid"
	for isp in a b; do
		net=81; [ $isp = b ] && net=82
		cat >"$WALK/client-$isp.json" <<JSON
{"log":{"level":"warn"},
 "inbounds":[{"type":"socks","tag":"via1","listen":"127.0.0.1","listen_port":1081},
             {"type":"socks","tag":"via2","listen":"127.0.0.1","listen_port":1082}],
 "outbounds":[{"type":"vless","tag":"node1","server":"10.$net.0.21","server_port":20001,"uuid":"$uuid"},
              {"type":"vless","tag":"node2","server":"10.$net.0.22","server_port":20001,"uuid":"$uuid"}],
 "route":{"rules":[{"inbound":["via1"],"outbound":"node1"},{"inbound":["via2"],"outbound":"node2"}]}}
JSON
	done
	dc up -d clienta clientb traffica trafficb insight

	if [ "$(api GET /api/addons | jq '[.[] | select(.slug=="insight")] | length')" = 0 ]; then
		say "registering Insight"
		for _ in $(seq 30); do curl -sf -o /dev/null "$INSIGHT/health" && break; sleep 1; done
		# From the core network: the panel hands the addon the address it was
		# called at, which must be one Insight can reach.
		incore() {
			docker run --rm --network insight-walk_core curlimages/curl:latest -sf -X POST "http://10.80.0.10:2095$1" \
				-H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d "$2"
		}
		dg="$(incore /api/addons/preview '{"url":"http://10.80.0.30:8099"}' | jq -r .digest)" || die "preview"
		incore /api/addons/register "{\"url\":\"http://10.80.0.30:8099\",\"claimCode\":\"WALK-INSIGHT-0001\",\"digest\":\"$dg\"}" | jq -c '{slug, name}'
	fi
	say "up: panel $PANEL (admin / walk-admin-1), Insight $INSIGHT (admin / walk-admin-1)"
}

insight_login() {
	rm -f "$WALK/jar"
	curl -sf -c "$WALK/jar" -H 'Content-Type: application/json' -H "Origin: $INSIGHT" \
		-d '{"username":"admin","password":"walk-admin-1"}' "$INSIGHT/api/login" >/dev/null
}
iget() { curl -sf -b "$WALK/jar" "$INSIGHT$1"; }

status() {
	insight_login
	iget /api/status | jq -c '{feed: .feed.state, lastPoll: .feed.lastPoll, outages, degraded, probed, tunnels: .tunnels.state, tunnelsDown}'
	iget '/api/matrix?hours=1' | jq -r '.cells[] | "AS\(.asn) \(.org) node\(.nodeId) \(.inbound) accepted=\(.accepted) authed=\(.authed) failed=\(.failed) degraded=\(.degraded)"'
}

# The traffic loop makes about 500 requests an hour per path (one every
# seven seconds or so); PER_HOUR overrides it.
seed() {
	say "giving every path a normal of ${PER_HOUR:-500} sessions an hour, 1% failed"
	dc stop insight
	sqlite3 "$WALK/insight/insight.db" <<SQL
DELETE FROM path_baselines;
INSERT INTO path_baselines (node_id, inbound, asn, network, slot, n, mean_authed, var_authed, mean_fail, var_fail, mean_early, var_early)
SELECT DISTINCT node_id, inbound, client_asn, network, -1, 24, ${PER_HOUR:-500}, 2500, 0.01, 0.0004, 0.02, 0.0004
FROM path_hours WHERE client_asn <> 0;
SQL
	sqlite3 "$WALK/insight/insight.db" 'SELECT node_id, inbound, asn, network, mean_authed FROM path_baselines'
	dc start insight
}

block() {
	# Every segment that carries data: the TCP handshake (SYN 60 bytes, ACK
	# 52 with timestamps) and the client's FIN pass, the protocol's first
	# bytes never arrive. Cut at the request instead and a client that
	# sends its header in a segment of its own would still authenticate.
	say "node1 drops ISP A's data on the inbound (the handshake passes, nothing after it)"
	dc exec node1 iptables -F INPUT
	dc exec node1 iptables -A INPUT -p tcp --dport 20001 -s 10.81.0.0/24 ! --syn -m length --length 53:65535 -j DROP
	dc exec node1 iptables -S INPUT
}

unblock() { dc exec node1 iptables -F INPUT; }

metrics() {
	mkdir -p "$WALK/grafana/provisioning/datasources" "$WALK/grafana/provisioning/dashboards"
	cat >"$WALK/prometheus.yml" <<YML
global: { scrape_interval: 15s }
scrape_configs:
  - job_name: nx-insight
    metrics_path: /metrics
    authorization: { type: Bearer, credentials: walk-metrics-token-0001 }
    static_configs: [{ targets: ['10.80.0.30:8099'] }]
YML
	cat >"$WALK/grafana/provisioning/datasources/prometheus.yml" <<YML
apiVersion: 1
datasources:
  - { name: Prometheus, uid: nx-prometheus, type: prometheus, access: proxy, url: http://10.80.0.40:9090, isDefault: true }
YML
	cp "$ROOT/panel/monitoring/grafana/provisioning/dashboards/nx.yml" "$WALK/grafana/provisioning/dashboards/nx.yml"
	dc --profile metrics up -d prometheus grafana
	say "Grafana: http://127.0.0.1:13000/d/nx-insight (anonymous viewer; admin / walk-admin-1)"
}

tunnel_id() { api GET /api/tunnels | jq -r '.[] | select(.name=="walk-tunnel") | .id'; }

tunnel() {
	TOK="$(tok)"
	if [ -z "$(tunnel_id)" ]; then
		say "a tunnel: node1 relays, node2 is its origin"
		n1="$(api GET /api/nodes | jq -r '.[] | select(.name=="node1") | .id')"
		n2="$(api GET /api/nodes | jq -r '.[] | select(.name=="node2") | .id')"
		api POST /api/tunnels "{\"name\":\"walk-tunnel\",\"mode\":\"reverse\",\"relayNodeId\":$n1,\"originIds\":[$n2],\"listenPort\":21000}" | jq -c '{id, tag}'
	fi
	api GET "/api/tunnels/$(tunnel_id)/status" | jq -c '{healthy, sessions}'
}

cut() {
	TOK="$(tok)"
	say "node1 drops the tunnel's port; the links are reset so none survives"
	dc exec node1 iptables -A INPUT -p tcp --dport 21000 -j DROP
	api POST "/api/tunnels/$(tunnel_id)/reset" >/dev/null
	api GET "/api/tunnels/$(tunnel_id)/status" | jq -c '{healthy, sessions}'
}

mend() {
	TOK="$(tok)"
	dc exec node1 iptables -D INPUT -p tcp --dport 21000 -j DROP
	api GET "/api/tunnels/$(tunnel_id)/status" | jq -c '{healthy, sessions}'
}

check() {
	insight_login
	TOK="$(tok)"
	say "alerts"
	iget /api/alerts | jq -r '.[] | "\(.kind) AS\(.asn) node\(.nodeId) \(.inbound) \(.tunnel // "") \(.reason)"'
	say "tunnels on the Nodes page"
	iget /api/nodes | jq -r '.[] | .name as $n | .tunnels[] | "\($n) \(.name) \(.role) \(.state) attempts=\(.hours.attempts) failed=\(.hours.failed)"'
	# The hints themselves have no read route on the panel; what they do is
	# in the subscriptions below, and Insight logs each push.
	say "Insight's hint pushes"
	dc logs --no-log-prefix insight 2>/dev/null | grep 'hints: pushed' | tail -3
	sub="$(api GET /api/users | jq -r '.[] | select(.name=="walker") | .subId')"
	for isp in a b; do
		say "the subscription as ISP $isp fetches it (first link first)"
		dc exec -T "traffic$isp" curl -s "http://10.8$([ $isp = a ] && echo 1 || echo 2).0.10:2095/sub/$sub" | base64 -d |
			grep -o '@10\.80\.0\.2[12]' | tr -d @ | tr '\n' ' '
		echo
	done
}

case "${1:-}" in
build) build ;;
up) up ;;
status) status ;;
seed) seed ;;
block) block ;;
unblock) unblock ;;
check) check ;;
tunnel) tunnel ;;
cut) cut ;;
mend) mend ;;
metrics) metrics ;;
down) dc down ;;
*) sed -n '2,28p' "$0"; exit 2 ;;
esac
