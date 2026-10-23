// Store → Data subject in a real browser: a look-up over the fixture store
// (alice owns doc:a and doc:b, so she can share both and reads nothing
// else), the objects table with its relation filter, the two download
// links (Objects CSV for the application teams, Everything JSON), and
// that the erasure stays behind a confirmation step (it is not run here).
import { test, expect } from '@playwright/test';

const STORE = process.env.CONSOLE_UI_STORE ?? 'console_uitest';
const USER = process.env.CONSOLE_UI_USER ?? 'admin';
const PASSWORD = process.env.CONSOLE_UI_PASSWORD ?? 'admin';

const tid = (page, id) => page.getByTestId(id);

async function signIn(page) {
  await page.goto('');
  await page.getByLabel('Username').fill(USER);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toHaveCount(0);
}

test.beforeEach(async ({ page }) => {
  await signIn(page);
  await page.goto(`stores/${STORE}/subject`);
});

test('a subject is looked up, its objects listed per relation and offered as CSV', async ({ page }) => {
  await tid(page, 'subject-id').fill('user:alice');
  await tid(page, 'subject-lookup').click();
  await expect(tid(page, 'subject-summary')).toContainText('2 grants and memberships');
  const rows = tid(page, 'subject-objects').locator('tbody tr');
  await expect(rows.filter({ hasText: 'owner' })).toContainText('a, b');
  await expect(rows.filter({ hasText: 'can_share' })).toContainText('a, b');
  await expect(rows.filter({ hasText: 'owner' })).toContainText('direct: a, b');
  await expect(tid(page, 'subject-download-csv')).toHaveAttribute('href', /format=csv/);
  await expect(tid(page, 'subject-download')).toHaveAttribute('href', /format=json/);

  // narrowed to one relation
  await tid(page, 'subject-relations').fill('owner');
  await tid(page, 'subject-lookup').click();
  await expect(rows).toHaveCount(1);
  await expect(rows.first()).toContainText('owner');
  await expect(tid(page, 'subject-download-csv')).toHaveAttribute('href', /relations=owner/);

  // the erasure asks first, and Keep backs out
  await tid(page, 'subject-erase').click();
  await expect(tid(page, 'subject-confirm')).toContainText('user:alice');
  await page.getByRole('button', { name: 'Keep' }).click();
  await expect(tid(page, 'subject-confirm')).toHaveCount(0);
  await expect(rows.first()).toContainText('owner'); // nothing happened
});
