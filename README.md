# NX Insight

An addon for [NX Panel](https://github.com/nx-panel/panel) that shows which
paths from your users to your nodes still work: per client network (ASN and,
in Iran, Russia and China, region), per node and per inbound — accepted,
failed and authenticated connections, early closes, round-trip times and
retransmits. It warns when a path is blocked, an endpoint is being probed
or a tunnel between your nodes has no link (and then does not blame the
relay's inbounds for it), and can put the links that work first in each
user's subscription.

Optionally, your own AI model — any OpenAI-compatible API with your key, or
Ollama on your server — reads the paths once a day, and after each alert,
for each country whose regions are kept (`region_countries`: Iran, Russia
and China unless you change it), and answers with findings checked against
the numbers. What is sent, to your model and nowhere else: per network (its
AS number and registered name), node number and inbound tag, the last 24
hours' counts and ratios; each node's hosting country and provider (yours,
where you corrected it on the Nodes page); the probing scores and how many
alerts there were; each tunnel touching those nodes, by its name, with its
relay and origin node numbers and whether it has a link. Never a client's or a node's address and never a node's
name. Names are cut down to forty letters, digits, spaces, dashes and
underscores before they go — no dots, so no address or URL as written — but a tag or a provider
name still says what it spells, so mind what you put in them. Nothing of
this goes to NX.

Mode B, off until you turn it on in the NX network page, shares this
panel's counts with NX and brings back NX's regional report: which
protocol shapes work, are degraded or are blocked for each network of your
users' countries, pooled from many independent operators. Once an hour, for
the hour just closed, it sends — signed with this install's key, which it
registers with your panel and, through the panel, with NX's licence service
— per client network (AS number, registered name, country, estimated
region) and per hosting network of your nodes (AS number, name, country),
per protocol shape (protocol, transport, TLS or REALITY, direct or through
a CDN): connections accepted, authenticated and cut early, failures by
class and by signature (bytes read, seconds to failure), replayed
handshakes, round-trip and session-time sums, and Insight's own reading of
the cell (fine, degraded, network outage, the node's address blocked, its
tunnel down). Never a client's or a node's address, a node's name or
number, an inbound's tag, a domain, an SNI, a path or your panel's address.
The page shows every batch as it went out. Turning Mode B off removes the
key from your panel and drops whatever had not been sent. NX publishes a
report only from networks that at least five independent operators share;
a panel without a licence receives outages and throttling only. Insight
asks for a newer report when it starts and when you open the page,
sending the time of the report it holds.

With a metrics token set at install, `/metrics` under the admin path feeds
your own Prometheus, per node, inbound and client network (AS number and
name), and the panel repository's `monitoring/` has the Grafana dashboard
for it (`nx-insight.json`).

Client addresses never leave your server: the nodes report a /24 or /48
prefix (/40 for a 6to4 address), Insight turns it into its network the moment it reads it and keeps
nothing else.

Status: in development (nx-panel `docs/path-telemetry.md`, phases 1 and 2). Needs a
panel and nodes with path telemetry (panel 0.2.0 or later).

## Data

IP address to ASN data from [iptoasn.com](https://iptoasn.com). IP
geolocation by [DB-IP](https://db-ip.com), licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Each install
downloads both itself.

## Licence

AGPL-3.0.
