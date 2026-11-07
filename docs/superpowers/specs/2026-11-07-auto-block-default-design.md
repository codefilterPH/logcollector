# Automatic IP blocking default design

## Intent

Enable automatic IP blocking by default when a host project does not define
`LOG_COLLECTOR_AUTO_BLOCK_ENABLED`. Hosts can explicitly set it to `False` to
disable the feature. Document the host configuration and publish the change as
package version `0.1.4` using the repository's protected GitHub Actions release
workflow.

## Goals

- Remove the requirement for production hosts to add an enabling setting.
- Apply the default consistently to normal incident handling and block
  reconciliation.
- Document the default, opt-out, and existing block duration in the existing
  configuration and operations guides.
- Publish the reviewed source and package through the configured TestPyPI then
  PyPI workflow.

## Non-goals and limits

- Do not change which security incidents qualify for automatic blocking.
- Do not change detection thresholds, trusted-IP exemptions, or the default
  block duration.
- In particular, repeated 404s on one route will still not meet the existing
  broad path-probing rule's distinct-path threshold.
- Do not add migrations or host-specific settings files.
- Do not publish a package except through `.github/workflows/publish.yml`.

## Approaches

1. Keep automatic blocking opt-in. This preserves current behavior but does
   not satisfy the request to make the feature active when unset.
2. Default the existing automatic-block setting to `True` at each code path
   that reads it, with explicit `False` as an opt-out. This activates the
   existing policy without changing detection or block durations. **Selected.**
3. Enable blocking only for repeated 404 detections. This introduces a new,
   narrower policy and leaves other existing security incidents dependent on
   host configuration.

## Implementation notes

Use `True` as the fallback wherever automatic-block enablement is checked,
including response reconciliation. Update the existing configuration and
operations documentation to explain that hosts need no setting to enable it,
can opt out with `LOG_COLLECTOR_AUTO_BLOCK_ENABLED = False`, and can override
the block duration with `LOG_COLLECTOR_AUTO_BLOCK_DURATION_SECONDS` (default
86,400 seconds). Add regression coverage for the unset setting and explicit
opt-out behavior.

## Production behavior

When unset, the collector will attempt to block IPs for all existing
eligible incidents. Normal trusted-IP exemptions and stale-evidence checks
remain in effect. The deployment must continue running the collector's
analysis and response tasks for automatic handling to occur.

If the host omits `LOG_COLLECTOR_AUTO_BLOCK_MAX_EVIDENCE_AGE_SECONDS`, use
the existing 900-second fallback in both direct blocking and reconciliation.
This prevents default-on response reconciliation from requiring an unrelated
host setting.

## Release

The current published package is `0.1.3`; release `0.1.4` after checks pass.
Push the merged source and matching `v0.1.4` tag to the configured GitHub
repository, run the workflow for TestPyPI, verify the distribution, then run it
for PyPI. Keep the configured PyPI environment reviewer gate in force.

The optional Nginx edge helper remains optional; when unset, automatic blocking must still apply through the Django middleware path.
