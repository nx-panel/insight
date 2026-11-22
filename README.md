# NX Insight

An addon for [NX Panel](https://github.com/nx-panel/panel) that shows which
paths from your users to your nodes still work: per client network (ASN and,
in Iran, Russia and China, region), per node and per inbound — accepted,
failed and authenticated connections, early closes, round-trip times and
retransmits. It warns when a path is blocked and can put the links that work
first in each user's subscription.

Client addresses never leave your server: the nodes report a /24 or /48
prefix, Insight turns it into its network the moment it reads it and keeps
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
