# Log Collector performance checks

Use a local PostgreSQL database with the same retained-log volume, active
integrations, cache backend, and Beat schedule for both measurements. Do not
use production credentials or personal data in captured output. Record the
commit, database engine/version, row counts, retention period, integrations,
cache configuration, worker count, and request parameters with every run.

## Routes

Measure these authenticated GET routes:

```text
/log-collector/entities/
/log-collector/entities/hosting-app/?view=access-logs&security=all
/log-collector/api/entities/hosting-app/metrics/
/log-collector/api/entities/hosting-app/access-logs/?q=&page=1&page_size=25
```

Warm the application once, then collect at least 20 timings per route. Use
browser DevTools or a command-line HTTP client and record each request's
time-to-first-byte and total duration. Report median and p95, separately for
cold and warm cache runs. Keep authentication and page state identical.

## Request work and query plans

In a local `DEBUG=True` environment, capture each route's SQL query count and
total SQL duration using Django's `connection.queries` or request profiling.
Count outbound remote health requests, log synchronization calls, and security
analysis calls per request. Entity-list and read-API requests should make zero
remote health probes and zero log-file synchronization calls.

For total-count, page retrieval, unique-IP, and date-range aggregate queries,
capture PostgreSQL plans with `EXPLAIN (ANALYZE, BUFFERS)` against the same
representative data. Do not add indexes until the plan shows a bottleneck;
record expected write and storage costs with any index proposal.

## Freshness checks

Confirm remote health is refreshed by `refresh_entity_health_statuses` and
appears as checking when no cached result exists, stale after 180 seconds, and
never healthy merely because the cache is unavailable. The worker and web
process must share Django's cache backend.

Confirm Beat runs `collect_analyze_and_respond` at the configured interval.
Expected ingestion delay is the poll interval plus queue delay, configured
sync cooldown, and time to consume the configured batch. Record the measured
queue delay and batch size; read requests do not trigger a catch-up sync.

## Acceptance report

Record before/after median and p95 for both HTML routes, all API routes, SQL
count and duration, outbound health requests, synchronization and analysis
calls, and health-result age. The design target is at least 50% lower local p95
for both HTML routes on the same dataset. State whether that target was met;
code changes alone are not performance evidence.
