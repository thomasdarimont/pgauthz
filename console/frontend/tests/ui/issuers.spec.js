// Platform → Issuers in a real browser: a platform admin creates a binding
// for an issuer, sees it listed with who created it, edits it (created_by
// kept, the state badge follows enabled), reads the history, and removes it
// with the confirmation step. The local admin (role_console_admin) is a
// platform admin and holds can_manage_issuers. Each run uses its own
// issuer; tests/test-console-ui.sh deletes leftovers under
// https://uitest.example/ on exit.
import { test, expect } from '@playwright/test';

const USER = process.env.CONSOLE_UI_USER ?? 'admin';
const PASSWORD = process.env.CONSOLE_UI_PASSWORD ?? 'admin';
const ISSUER = `https://uitest.example/realms/${Date.now()}`;
const STORE = process.env.CONSOLE_UI_STORE ?? 'console_uitest';

const tid = (page, id) => page.getByTestId(id);

async function signIn(page) {
  await page.goto('');
  await page.getByLabel('Username').fill(USER);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toHaveCount(0);
}

const row = (page) => page.locator(`[data-testid="issuers-row"][data-issuer="${ISSUER}"]`);

test.beforeEach(async ({ page }) => {
  await signIn(page);
  await page.goto('platform/issuers');
});

test('a binding is created, edited, audited and removed', async ({ page }) => {
  await expect(tid(page, 'platform-tab-issuers')).toHaveClass(/active/);

  // create
  await tid(page, 'issuers-new').click();
  await tid(page, 'issuers-issuer').fill(ISSUER);
  await tid(page, 'issuers-stores').fill('uitest_docs\nuitest_.*');
  // a known store is picked by name (datalist-backed input) and becomes a line of the list
  await tid(page, 'issuers-pick-stores').fill(STORE);
  await tid(page, 'issuers-pick-stores').press('Enter');
  await expect(tid(page, 'issuers-stores')).toHaveValue(`uitest_docs\nuitest_.*\n${STORE}`);
  await expect(tid(page, 'issuers-pick-stores')).toHaveValue('');
  await tid(page, 'issuers-stores').fill('uitest_docs\nuitest_.*');
  await tid(page, 'issuers-db-roles').fill('app_uitest');
  await tid(page, 'issuers-pep-clients').fill('{"gateway": ["uitest_docs"]}');
  await tid(page, 'issuers-description').fill('browser test');
  await tid(page, 'issuers-save').click();
  await expect(tid(page, 'issuers-saved')).toContainText('revision');
  await expect(row(page)).toContainText('uitest_docs, uitest_.*');
  await expect(row(page)).toContainText('app_uitest');
  await expect(row(page)).toContainText('browser test');
  await expect(row(page).locator('.badge.ok').first()).toHaveText('enabled');
  await expect(row(page)).toContainText(`user:${USER}`); // created_by and updated_by

  // the engine's validation reaches the page
  await tid(page, 'issuers-new').click();
  await tid(page, 'issuers-issuer').fill(ISSUER + '/bad');
  await tid(page, 'issuers-stores').fill('uitest_(');
  await tid(page, 'issuers-save').click();
  await expect(page.locator('.error')).toContainText(/regular expression|pattern/i);
  await tid(page, 'issuers-cancel').click();

  // edit: pause it, created_by stays
  await row(page).getByTestId('issuers-edit').click();
  await expect(tid(page, 'issuers-issuer')).toHaveValue(ISSUER);
  await expect(tid(page, 'issuers-stores')).toHaveValue('uitest_docs\nuitest_.*');
  await tid(page, 'issuers-enabled').uncheck();
  await tid(page, 'issuers-description').fill('paused for the test');
  await tid(page, 'issuers-save').click();
  await expect(tid(page, 'issuers-saved')).toContainText('revision');
  await expect(row(page).locator('.badge.deny').first()).toHaveText('disabled');
  await expect(row(page)).toContainText('paused for the test');

  // history: newest first, the update then the insert, by the person
  const audit = page.locator('[data-testid="issuers-audit-row"]', { hasText: ISSUER });
  await expect(audit.first()).toContainText('UPDATE');
  await expect(audit.first()).toContainText(`user:${USER}`);
  await expect(audit.nth(1)).toContainText('INSERT');
  // the pager: page 1 of the keyset-paged history, a page size change, and
  // refresh reloading everything (the rows stay)
  const pagerText = tid(page, 'issuers-audit-pager').locator('span').first();
  await expect(pagerText).toHaveText(/Page 1 of \d+ ·\s+1–\d+ of \d+/);
  await expect(tid(page, 'issuers-audit-prev')).toBeDisabled();
  await tid(page, 'issuers-audit-limit').selectOption('25');
  await expect(pagerText).toHaveText(/Page 1 of \d+/);
  await tid(page, 'issuers-refresh').click();
  await expect(audit.first()).toContainText('UPDATE');

  // remove, with the confirmation step
  await row(page).getByTestId('issuers-delete').click();
  await row(page).getByTestId('issuers-confirm-delete').click();
  await expect(tid(page, 'issuers-saved')).toContainText('removed');
  await expect(row(page)).toHaveCount(0);
  await expect(audit.first()).toContainText('DELETE');
});
