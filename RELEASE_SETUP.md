# Release account setup for `logcollector`

Use this checklist to grant access for the first public release. The package
source is committed locally; the GitHub repository and package-index projects
have not been created. You do **not** need to send me passwords, recovery
codes, or API tokens.

## 1. Connect GitHub to Codex

- [ ] In this Codex chat, open the suggested **GitHub** plugin card. Choose
  **Connect** or **Install**, then complete the GitHub authorization screen.
- [ ] Authorize the GitHub account that can create repositories under
  `codefilterPH`. If `codefilterPH` is an organization and GitHub asks for
  organization approval, have an organization owner approve the connection.
- [ ] Return to Codex and confirm that GitHub shows **Connected**. Selecting
  “Connect GitHub plugin” in a chat question alone does not install it.

**Stop after this step and reply “GitHub connected; please create the
repository.”** I will check the connector's permissions, then create the
**public** `codefilterPH/logcollector` repository and push the reviewed local
source if it permits those actions. If it does not, I will tell you; use
[GitHub's new repository page](https://github.com/new): choose owner
`codefilterPH`, name `logcollector`, visibility **Public**, and do not add a
generated README, license, or `.gitignore` because those files already exist
locally. Tell me when the empty repository exists so I can arrange the push.
Continue with Sections 2–5 once the GitHub repository exists.

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
| PyPI project name | `logcollector` |
| GitHub owner | `codefilterPH` |
| Repository name | `logcollector` |
| Workflow filename | `publish.yml` |
| Environment name | `testpypi` |

- [ ] Save the publisher and confirm it appears in the pending publisher list.

## 5. Register the production PyPI publisher

Repeat the preceding step on **PyPI**, using the same project, owner,
repository, and workflow values. Set **Environment name** to `pypi`.

- [ ] Save it and confirm it appears on PyPI as a pending publisher.

TestPyPI and PyPI each need their **own** publisher registration. A pending
publisher does not reserve `logcollector`; I will recheck the name just before
the first upload. If it has been taken, stop before publishing and choose a
new package name with me. PyPI's [pending publisher guide](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
explains the first-release setup.

## 6. Hand the release back to me

Reply in this chat with: **“GitHub connected; repository and both environments
ready; TestPyPI and PyPI publishers registered.”** Tell me if you created the
GitHub repository yourself. I will verify the exact owner/repository/workflow/
environment values, push the reviewed source, run the package checks, create
the version tag, rehearse on TestPyPI, and inspect a clean install. Production
publishing then runs through the `pypi` environment's approval gate. After the
PyPI release is verified, I can switch the current host to a pinned package
version and check its services.

Do not manually upload the wheel: it would bypass the reviewed workflow.
Package versions cannot be overwritten after upload; a correction needs a
new version and tag. The [operations guide](log_collector/docs/operations-guide.md)
covers deployment checks after installation.
