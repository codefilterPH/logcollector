# API integration

Mounting `log_collector.urls` at `/log-collector/` exposes read-only entity
resources under `/log-collector/api/entities/<slug>/`. Resources include
`metrics/`, `access-logs/`, `geolocation/`, `user-sessions/`, `endpoints/`, and
`audit-events/`, subject to the entity's feature flags and caller permissions.
Table resources support pagination; supported resources accept `export=csv`.

Generate an entity-scoped collector token as a superuser on the entity Manage
page. The raw token is shown once. Server-to-server callers send it in the
`X-Api-Key` header. The server stores a hash, not the raw token. Tokens may
have expiry, caller IP/CIDR, and origin restrictions. Do not embed a collector
token in browser or mobile application code.

To view another installation, create an integration entity with its HTTPS base
URL, remote entity slug, and remote collector token. Remote calls are read-only
and fetched on demand; they do not copy remote raw logs into the local database.
The remote service must expose the LOG Collector API. Arbitrary logging APIs
need a separate adapter.

The available entity routes also include `security-summary/`,
`security-incidents/`, `security-blocks/`, and CrowdSec status and decisions.
State-changing security endpoints require an authorized same-origin session,
CSRF protection, and the required operator role; a read-only API token cannot
perform those actions. An expired, revoked, mismatched, or caller-restricted
token is denied. Inspect recent token usage on the entity Manage page to
diagnose denials without logging the raw key.
