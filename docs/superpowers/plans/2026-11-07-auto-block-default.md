# Automatic IP Blocking Default Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Enable existing eligible automatic IP blocking when the host setting is absent, document host configuration, and publish the change as package version `0.1.4`.

**Architecture:** Define one setting-resolution helper in `log_collector.services.blocking` with a `True` fallback. Use it in both direct blocking and response reconciliation so their behavior cannot diverge. Document host configuration and existing operational limits, then use the repository's protected GitHub Actions workflow to publish through TestPyPI and PyPI.

**Tech Stack:** Python 3.12+, Django, built-in `unittest`.

**Spec:** `docs/superpowers/specs/2026-11-07-auto-block-default-design.md`

## Global Constraints

- Leave detection rules, thresholds, trusted-IP exemptions, and block duration unchanged.
- Explicit `LOG_COLLECTOR_AUTO_BLOCK_ENABLED = False` must disable automatic blocking.
- Automatic blocks default to 86,400 seconds unless `LOG_COLLECTOR_AUTO_BLOCK_DURATION_SECONDS` overrides it.
- Eligible evidence defaults to a maximum age of 900 seconds unless `LOG_COLLECTOR_AUTO_BLOCK_MAX_EVIDENCE_AGE_SECONDS` overrides it.
- Do not add migrations or host-specific settings files.
- Publish only through `.github/workflows/publish.yml` and keep the PyPI environment reviewer gate in force.

## Review Focus

- Missing evidence-age setting: reconciliation uses the existing 900-second fallback.

- Missing host setting: automatic blocking is enabled by default; the regression test must assert this.
- Explicit false override: automatic blocking remains disabled; the regression test must assert this.
- Reconciliation and direct blocking must use the same resolved setting.
- Documentation must state that same-route 404 bursts still do not satisfy the existing distinct-path threshold.

---

### Task 1: Default automatic blocking on and document it

**Files:**
- Create: `packaging/consumer_smoke/test_auto_block_defaults.py`
- Modify: `.github/workflows/package.yml`
- Modify: `log_collector/services/blocking.py`
- Modify: `log_collector/services/response.py`
- Modify: `log_collector/docs/configuration.md`
- Modify: `log_collector/docs/operations-guide.md`

**Interfaces:**
- `log_collector.services.blocking.is_auto_block_enabled() -> bool` reads `LOG_COLLECTOR_AUTO_BLOCK_ENABLED`, defaulting to `True` when absent.
- `log_collector.services.blocking.auto_block_max_evidence_age_seconds() -> int` reads `LOG_COLLECTOR_AUTO_BLOCK_MAX_EVIDENCE_AGE_SECONDS`, defaulting to `900` when absent.
- `log_collector.services.response` uses that helper for reconciliation; `block_ip` uses it for the direct automatic-block gate.

- [ ] **Step 1: Write regression tests** in `packaging/consumer_smoke/test_auto_block_defaults.py` for an absent enablement setting returning `True`, an absent evidence-age setting returning `900`, and an explicit `False` returning `False`. Patch the settings object with `types.SimpleNamespace` to represent missing attributes.
- [ ] **Step 2: Run the new test and confirm it fails** with `AttributeError` because `is_auto_block_enabled` is not implemented. Use the repository's Django test settings: `$env:PYTHONPATH='packaging/consumer_smoke'; python -m django test test_auto_block_defaults --settings=logcollector_package_settings --noinput`.
- [ ] **Step 3: Implement both helpers and route direct blocking plus reconciliation through them.** Keep all other eligibility, exemption, and expiration logic unchanged.
- [ ] **Step 4: Run the targeted test** with `$env:PYTHONPATH='packaging/consumer_smoke'; python -m django test test_auto_block_defaults --settings=logcollector_package_settings --noinput`; expect both tests to pass.
- [ ] **Step 5: Update `configuration.md`** with the default-on behavior, explicit `False` opt-out, and optional duration and evidence-age overrides.
- [ ] **Step 6: Update `operations-guide.md`** with the production activation behavior, trusted-IP/evidence limits, and note that the repeated-404 detector still requires distinct paths.
- [ ] **Step 7: Add `test_auto_block_defaults` to the Django test command** in `.github/workflows/package.yml`, then run the repository checks: Django tests `test_appearance test_optional_models test_auto_block_defaults` with `logcollector_package_settings`, followed by the `test_portable_imports.py` unittest discovery command. Expect all tests to pass.
- [ ] **Step 8: Review the complete diff and run `git diff --check`.** Confirm no migrations or unrelated files changed.
- [ ] **Step 9: Bump `pyproject.toml` from `0.1.3` to `0.1.4`** and update `RELEASE_SETUP.md` to describe matching tag/workflow release steps without stale `v0.1.1` instructions.
- [ ] **Step 10: Build and check the distribution** with `python -m build` and `python -m twine check dist/*`; expect clean metadata validation and included configuration documentation.
- [ ] **Step 11: Commit** the task files with a message such as `feat: enable automatic IP blocking by default`.
- [ ] **Step 12: Merge the task into local `main`, rerun the consumer-smoke suite and package checks, then push `main` and tag `v0.1.4` to `origin`**; verify the remote branch and tag point to the reviewed commit.
- [ ] **Step 13: Run `.github/workflows/publish.yml` with target `testpypi`** for `v0.1.4`; verify the run succeeds and the uploaded distribution installs with the configuration guide.
- [ ] **Step 14: Run the same workflow with target `pypi`**; preserve its required reviewer gate, wait for success, and confirm PyPI reports version `0.1.4`.
