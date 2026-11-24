#!/bin/sh
# Mode B walk (nx-panel docs/path-telemetry.md §5.3): the real cloud Worker
# and the real licence Worker under `wrangler dev`, five Insight installs
# (internal/cloud) sending their closed hour, a report published through the
# admin API, and each install fetching it.
#
#   WALK=<scratch dir> walk/cloud/run.sh
#
# Needs the sibling checkouts nx-insight-cloud and nx-license with their
# node_modules, and nx-panel/.secrets/insight_feed_ed25519.key: the cloud
# signs with the real feed key so Insight checks it against the key it
# ships. The model call is not walked (the AI binding is always remote);
# a finished run is written in its place.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
cloud="$root/nx-insight-cloud"
license="$root/nx-license"
: "${WALK:?set WALK to a scratch directory}"
mkdir -p "$WALK"
WALK=$(cd "$WALK" && pwd)
state="$WALK/state"
rm -rf "$state" "$WALK/sent" "$WALK/published"
port=${PORT:-8788}
url="http://localhost:$port"

seed=$(cat "$root/nx-panel/.secrets/insight_feed_ed25519.key")
devvars="$cloud/.dev.vars"
[ -e "$devvars" ] && cp "$devvars" "$WALK/dev.vars.saved"
printf 'FEED_SIGNING_KEY=%s\nACCESS_DEV_BYPASS=1\n' "$seed" >"$devvars"

d1() { (cd "$1" && npx wrangler d1 execute DB --local --persist-to "$state" -c "$2" "$@" >/dev/null); }
(cd "$cloud" && npx wrangler d1 execute DB --local --persist-to "$state" -c wrangler.walk.toml --file schema.sql >/dev/null)
(cd "$license" && npx wrangler d1 execute DB --local --persist-to "$state" -c wrangler.toml --file schema.sql >/dev/null)

# Four licensed installs and one free one, as the heartbeat and the
# check-in would have bound them (PT14).
keys=$(cd "$root/insight" && go test -tags cloudwalk -run TestPrintKeys -count=1 -v ./walk/cloud/ | grep '=$')
now=$(date +%s)
old=$((now - 400 * 86400))
sql=""
i=0
for k in $keys; do
	if [ $i -lt 4 ]; then
		sql="$sql INSERT INTO licenses (license_id, plan_id, revoked, suspended, clone_flag, expires_at, first_seen, issued_at) VALUES ('walk-$i', 1, 0, 0, 0, 0, $old, $old);"
		sql="$sql INSERT INTO contributors (public_key, license_id, install_uuid, first_seen, bound_at, last_seen, moves) VALUES ('$k', 'walk-$i', 'walk-install-$i', $old, $old, $now, 0);"
	else
		sql="$sql INSERT INTO contributors (public_key, license_id, install_uuid, first_seen, bound_at, last_seen, moves) VALUES ('$k', NULL, 'walk-install-$i', $((now - 40 * 86400)), $((now - 40 * 86400)), $now, 0);"
	fi
	i=$((i + 1))
done
(cd "$license" && npx wrangler d1 execute DB --local --persist-to "$state" -c wrangler.toml --command "$sql" >/dev/null)

(cd "$cloud" && nohup npx wrangler dev -c wrangler.walk.toml -c "$license/wrangler.toml" --persist-to "$state" --port "$port" --local-upstream "localhost:$port" </dev/null >"$WALK/wrangler.log" 2>&1 &)
cleanup() {
	pkill -f "wrangler dev -c wrangler.walk.toml" 2>/dev/null || true
	if [ -e "$WALK/dev.vars.saved" ]; then mv "$WALK/dev.vars.saved" "$devvars"; else rm -f "$devvars"; fi
}
trap cleanup EXIT
for _ in $(seq 60); do curl -fsS "$url/" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "$url/" >/dev/null

(cd "$root/insight" && NX_CLOUD_WALK_URL="$url" NX_CLOUD_WALK_DIR="$WALK" go test -tags cloudwalk -run TestCloudWalk -count=1 -v ./walk/cloud/ >"$WALK/test.log" 2>&1; echo $? >"$WALK/test.exit") &
for _ in $(seq 120); do [ -e "$WALK/sent" ] && break; sleep 1; done
[ -e "$WALK/sent" ] || { cat "$WALK/test.log"; exit 1; }
hour=$(cat "$WALK/sent")

q() { (cd "$cloud" && npx wrangler d1 execute DB --local --persist-to "$state" -c wrangler.walk.toml --json --command "$1") | sed -n 's/.*"n": *\([0-9]*\).*/\1/p' | head -1; }
for _ in $(seq 60); do [ "$(q 'SELECT COUNT(*) AS n FROM cells')" = 10 ] && break; sleep 1; done
echo "cells stored: $(q 'SELECT COUNT(*) AS n FROM cells'), contributors: $(q 'SELECT COUNT(*) AS n FROM contributors'), licensed: $(q 'SELECT SUM(licensed) AS n FROM contributors')"

post() { curl -sS -X POST -H 'x-nx-admin: 1' -H 'content-type: application/json' --data "$2" "$url$1"; echo; }
echo "a run through the admin API, which has no AI binding here:"
post /v1/admin/runs '{"cc":"IR","hours":24,"model":"anthropic/claude-sonnet-5.5"}'
sleep 3
curl -sS "$url/v1/admin/runs" | head -c 400; echo

findings='[{"code":"strategy_blocked","severity":"critical","asn":197207,"strategy":"vless/xhttp/tls/cdn","node_asn":0,"confidence":0.9},{"code":"throttled","severity":"warn","asn":197207,"strategy":"vless/none/reality/direct","node_asn":0,"confidence":0.7}]'
input='{"text":"walk","rows":[{"asn":197207,"org":"MCCI"}],"belowK":0,"contributors":5}'
(cd "$cloud" && npx wrangler d1 execute DB --local --persist-to "$state" -c wrangler.walk.toml --command \
	"INSERT INTO runs (id, created_at, cc, window_from, window_to, model, below_k, status, rows, contributors, input, output, findings, kept, dropped, finished_at)
	 VALUES (900, $now, 'IR', $((hour - 82800)), $((hour + 3600)), 'anthropic/claude-sonnet-5.5', 0, 'done', 1, 5, '$input', 'walk', '$findings', 2, 0, $now)" >/dev/null)
post /v1/admin/runs/900/choose '{}'
post /v1/admin/publish '{}'
touch "$WALK/published"
for _ in $(seq 90); do [ -e "$WALK/test.exit" ] && break; sleep 1; done
cat "$WALK/test.log"
exit "$(cat "$WALK/test.exit")"
