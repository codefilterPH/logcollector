# Release account setup for `codefilterph-logcollector`

Use this checklist for the first public release of `codefilterph-logcollector`.
The public source repository is `codefilterPH/logcollector`; the installed
Django apps remain `log_collector` and `crowdsec_integration`. PyPI rejected
the earlier `logcollector` name as too similar to `log-collector`. Do not
send passwords, recovery codes, or API tokens.

## 1. Confirm the GitHub repository

The [public source repository](https://github.com/codefilterPH/logcollector)
and its protected `testpypi` and `pypi` environments already exist.
Keep their reviewer and tag protection rules enabled.

## 2. Sign in to both package indexes

- [ ] Sign in to [TestPyPI](https://test.pypi.org/account/login/) and
  [PyPI](https://pypi.org/account/login/) in the browser. These are separate
  sites; create an account on either site if you do not have one.
- [ ] Complete any email verification and two-factor authentication each
  site requires. Keep credentials and recovery codes in your own account.
- [ ] Confirm you can open each site's account **Publishing** page. At the
  last check, both sites redirected to their login pages.

## 3. Create protected GitHub environments

After the GitHub repository exists, open its **Settings → Environments → New
environment** page. You need repository owner or admin access.

- [ ] Create an environment named exactly `testpypi`.
- [ ] Create another named exactly `pypi`.
- [ ] On `pypi`, enable **Required reviewers** and select a trusted maintainer
  who will approve the production release. You may also protect `testpypi`.
  Enable **Prevent self-review** only if someone else can approve the run.
- [ ] On each environment, choose **Selected branches and tags → Add
  deployment branch or tag rule → Ref type: Tag**, then enter `v*`. The
  release workflow also checks that its ref starts with `refs/tags/v` and
  that the tag matches the package version.
- [ ] Do not add a PyPI password or long-lived API token as a GitHub secret.
  The workflow requests a short-lived token through Trusted Publishing.

GitHub's [environment instructions](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
show the current settings and reviewer controls.

## 4. Register the TestPyPI publisher

On TestPyPI, open your account **Publishing** page and add a **pending**
GitHub Actions Trusted Publisher. Enter these values exactly:

| Field | Value |
| --- | --- |
| PyPI project name | `codefilterph-logcollector` |
| GitHub owner | `codefilterPH` |
| Repository name | `logcollector` |
| Workflow filename | `publish.yml` |
| Environment name | `testpypi` |

- [ ] Save the publisher and confirm it appears in the pending publisher list.

## 5. Register production PyPI publisher

Repeat the preceding step on **PyPI**, using project name
`codefilterph-logcollector`, GitHub owner `codefilterPH`, repository
`logcollector`, workflow `publish.yml`, and environment `pypi`.

- [ ] Save it and confirm it appears on the PyPI pending publisher list.

TestPyPI and PyPI each need their own registration for the new
distribution. The earlier `logcollector` registration on TestPyPI does
not authorize `codefilterph-logcollector`. A pending publisher does not
reserve a project name. See the [PyPI pending publisher guide](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

## 6. Run the release

After both new pending publishers appear, run package checks, create
the `v0.1.1` tag from reviewed source, and rehearse on TestPyPI. Inspect
a clean install before running the same tag against PyPI. Production
publishing requires approval at the `pypi` environment gate.

Do not manually upload the wheel: it would bypass the reviewed workflow.
Package versions cannot be overwritten after upload; a correction needs a
new version and tag. The [operations guide](log_collector/docs/operations-guide.md)
covers deployment checks after installation.
