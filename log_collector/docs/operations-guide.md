# Operations

## Automatic IP blocking

Automatic IP blocking is enabled by default, so the host does not need an
enablement entry in `settings.py`. Set `LOG_COLLECTOR_AUTO_BLOCK_ENABLED` to
`False` there to opt out. Review the trusted-IP configuration, automatic-block
duration, evidence-age limit, and existing detection thresholds before
production rollout. Only fresh evidence from qualifying security incidents
can create a block. The broad path-probing rule does not trigger on repeated
404s to one route; other security rules may still qualify. See
[Configuration](configuration.md#automatic-ip-blocking) for the settings and
defaults.

After installation, run `python manage.py check` and `python manage.py migrate`
with the host's settings. Confirm the web and Celery worker accounts can read
each configured Nginx log. Mount log files read-only where possible; grant the
smallest filesystem permission needed. Check the collector's Manage page for
local connection health and recent token usage.

Run an ASGI server and a channel layer for live security updates. Run Celery
beat and workers consuming `default`; add a worker consuming `sms` when SMS
alerts are enabled. A disconnected WebSocket does not stop HTTP refresh or
scheduled collection. Retain monitoring for worker failures, log rotation,
unreadable paths, and stale last-sync timestamps.

Application-level IP blocking is supplied by the optional collector middleware.
Edge blocking needs a separately installed and reviewed fixed-path helper in
`LOG_COLLECTOR_NGINX_BLOCK_HELPER`. Never configure a shell command or grant
the web account broad Nginx privileges. The helper must validate its inputs
and verify the resulting Nginx rule before reporting success.

Before upgrading, back up the database and apply the package migrations on a
staging copy. Keep the same Django app labels and migration names. Roll out
the new package version to web and worker processes together, then verify
collection, API reads, WebSocket connection, and queued tasks. Rotate API
tokens and SMS provider credentials through the host's normal secret process;
do not put secrets in package configuration files.

## Publishing a release

Publish from the standalone `codefilterPH/logcollector` repository. Review its
source and archives for host-specific names, paths, credentials, and unrelated
apps. Confirm the public license and increment the version in `pyproject.toml`.
Check that the normalized `codefilterph-logcollector` name is still available on both
package indexes immediately before the first release.

In TestPyPI, register a Trusted Publisher for GitHub owner `codefilterPH`,
repository `logcollector`, workflow `publish.yml`, and environment `testpypi`.
Protect that GitHub environment. Tag the reviewed version as `vX.Y.Z`, then
run **Publish package** against that tag with target `testpypi`. Check the
uploaded files and README. In a fresh environment, install dependencies from
PyPI, then install the exact candidate from TestPyPI with
`python -m pip install --no-deps --index-url https://test.pypi.org/simple/ codefilterph-logcollector==X.Y.Z`.
Run the installation and configuration checks on that candidate.

For production, register a separate PyPI Trusted Publisher with the same
owner, repository, and workflow but environment `pypi`. Require review for
that GitHub environment. Run the same workflow against the reviewed tag with
target `pypi`. The workflow uses short-lived OIDC credentials; no PyPI API
token belongs in the repository. Verify `python -m pip install
codefilterph-logcollector==X.Y.Z` in a fresh environment, inspect the installed guides,
and record release notes. A package version cannot be overwritten on PyPI;
fixes require a new version and tag.
