# Entity Manage AJAX Fix Implementation Plan
> **For agentic workers:** Use `superpowers:executing-plans` to implement this plan task-by-task.

**Goal:** Make entity settings saves and API token actions work on the entity manage page when `window.fetchWithAuth` is unavailable.

**Architecture:** Add a page-local fetch wrapper in `entity_manage.html` that uses `window.fetchWithAuth` when supplied and otherwise calls `window.fetch` with same-origin credentials. Route both AJAX submissions and token-panel refreshes through that wrapper, matching the dashboard's existing fallback behavior.

**Tech Stack:** Django template, browser JavaScript.

**Spec:** The user's report and root-cause findings in this conversation.

## Approaches
- **Page-local fallback (recommended):** Reuse `window.fetchWithAuth` when present and provide a same-origin `window.fetch` fallback on this page. This is a small, contained change and follows the dashboard pattern.
- **Shared helper:** Add or wire a common script that defines `fetchWithAuth`. This avoids page-local duplication but broadens the change beyond the isolated manage page.

## Global Constraints
- Keep the change scoped to the entity manage page.
- Preserve the existing AJAX response handling, CSRF form data, status messages, and one-time raw token display.
- Use same-origin credentials for the fallback request.

## Review Focus
- `save_entity` must send the submitted name and slug and report server validation errors inline.
- `create_token` must submit successfully, display the raw token once, and refresh the token panel.
- Other AJAX management actions must continue to use the existing request headers and response handling.

---

### Task 1: Provide a reliable fetch function for manage-page actions

**Files:**
- Modify: `log_collector/templates/log_collector/entity_manage.html`

- [ ] Define a page-local fetch function that prefers `window.fetchWithAuth` when available and otherwise calls `window.fetch(url, {...options, credentials: "same-origin"})`.
- [ ] Use that function for the management form POST and `refreshTokenPanel()` GET.
- [ ] Keep the existing CSRF form payload, `X-Requested-With` and `Accept` headers, error rendering, token display, and generic failure handling intact.
- [ ] Manually verify in a browser that changing the entity name and slug then saving persists the values, and that generating a token shows its one-time value and refreshes the token list.
- [ ] Manually verify an invalid entity setting still shows field errors and that token generation failure still shows an error status.
