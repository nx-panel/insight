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
name still says what it spells, so mind what you put in them. Nothing goes to NX.

Client addresses never leave your server: the nodes report a /24 or /48
prefix (/40 for a 6to4 address), Insight turns it into its network the moment it reads it and keeps
nothing else.

Status: in development (nx-panel `docs/path-telemetry.md`, phase 1). Needs a
panel and nodes with path telemetry (panel 0.1.3 or later).

## Data

IP address to ASN data from [iptoasn.com](https://iptoasn.com). IP
geolocation by [DB-IP](https://db-ip.com), licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Each install
downloads both itself.

## Licence

AGPL-3.0.
