// The share dialog in a real browser: what the Go tests cannot reach —
// the request/response race, Save's binding to the loaded object, the
// post-save state when the refresh fails, the expiry chip's rendering.
// Needs the fixture store (fixture.sql) and a signed-in local admin, who
// is an owner of every store (CONSOLE_LOCAL_ADMIN_STORE_ROLE) and so may
// share; the actor whose grant rules decide is alice, the docs' owner.
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

// Opens the share dialog on the store's Data tab and fills the form for
// object doc:<id> acting as alice (without loading).
async function openShare(page, id) {
  await page.goto(`stores/${STORE}/data`);
  await tid(page, 'data-share-open').click();
  await tid(page, 'data-share-type').fill('doc');
  await tid(page, 'data-share-id').fill(id);
  await tid(page, 'data-share-actor').fill('user:alice');
}

test.beforeEach(async ({ page }) => {
  await signIn(page);
});

test('a late response for object A does not populate object B', async ({ page }) => {
  // hold A's options back until B is typed, as a slow network would
  const optionsForA = /\/share\?.*object_id=a(&|$)/;
  let releaseA;
  const held = new Promise((r) => (releaseA = r));
  await page.route(optionsForA, async (route) => {
    await held;
    await route.continue();
  });
  await openShare(page, 'a');
  const responseA = page.waitForResponse((r) => optionsForA.test(r.url()) && r.request().method() === 'GET');
  await tid(page, 'data-share-load').click();
  await tid(page, 'data-share-id').fill('b');
  releaseA();
  // A's response has fully arrived in the page before the assertion; the
  // form says b, so the dialog must have dropped it — no table, no Save
  const res = await responseA;
  expect(res.status()).toBe(200);
  await res.finished();
  await expect(tid(page, 'data-share-table')).toHaveCount(0);
  await expect(tid(page, 'data-share-apply')).toHaveCount(0);
  await page.unroute(optionsForA);
  // a proper load for b shows b's own (empty) holders
  await tid(page, 'data-share-load').click();
  await expect(tid(page, 'data-share-rel-viewer')).toContainText('nobody');
});

test('Save is bound to the loaded object: retyping the object retires the queue', async ({ page }) => {
  const posts = [];
  page.on('request', (r) => {
    if (r.method() === 'POST' && r.url().includes('/share')) posts.push(r.url());
  });
  await openShare(page, 'a');
  await tid(page, 'data-share-load').click();
  await expect(tid(page, 'data-share-holder-viewer-user-bob')).toBeVisible();
  await tid(page, 'data-share-add-viewer').fill('user:carol');
  await tid(page, 'data-share-queue-viewer').click();
  await expect(tid(page, 'data-share-apply')).toBeEnabled();
  // the object changes under the queued grant: nothing to save until reloaded
  await tid(page, 'data-share-id').fill('b');
  await expect(tid(page, 'data-share-apply')).toHaveCount(0);
  await expect(tid(page, 'data-share-table')).toHaveCount(0);
  expect(posts).toEqual([]);
});

test('a committed save whose refresh fails leaves nothing queued to replay', async ({ page }) => {
  const posts = [];
  page.on('request', (r) => {
    if (r.method() === 'POST' && r.url().includes('/share')) posts.push(r.url());
  });
  await openShare(page, 'a');
  await tid(page, 'data-share-load').click();
  await expect(tid(page, 'data-share-holder-viewer-user-bob')).toBeVisible();
  await tid(page, 'data-share-add-viewer').fill('user:carol');
  await tid(page, 'data-share-queue-viewer').click();
  // the save commits, the refresh that follows fails
  await page.route(/\/share\?/, (route) =>
    route.fulfill({ status: 500, body: '{"error":"refresh failed"}' }),
  );
  const failedRefresh = page.waitForResponse((r) => r.url().includes('/share?') && r.status() === 500);
  await tid(page, 'data-share-apply').click();
  await (await failedRefresh).finished(); // the refresh has failed before the state is judged
  await expect(tid(page, 'data-share-result')).toContainText('saved: 1 granted');
  await expect(tid(page, 'data-share-apply')).toHaveCount(0); // nothing left to save
  expect(posts).toHaveLength(1);
  // the next load shows the committed grant and an empty queue
  await page.unroute(/\/share\?/);
  await tid(page, 'data-share-load').click();
  await expect(tid(page, 'data-share-holder-viewer-user-carol')).toBeVisible();
  await expect(tid(page, 'data-share-queued-viewer-carol')).toHaveCount(0);
  await expect(tid(page, 'data-share-apply')).toBeDisabled();
  // undo for the next run: revoke carol as alice
  await tid(page, 'data-share-revoke-viewer-carol').click();
  await tid(page, 'data-share-apply').click();
  await expect(tid(page, 'data-share-result')).toContainText('1 revoked');
  expect(posts).toHaveLength(2);
});

test('an expiring grant shows when it runs out, relative with the absolute time as its title', async ({
  page,
}) => {
  await openShare(page, 'a');
  const [res] = await Promise.all([
    page.waitForResponse((r) => r.url().includes('/share?') && r.request().method() === 'GET'),
    tid(page, 'data-share-load').click(),
  ]);
  const body = await res.json();
  const temp = body.holders.find((h) => h.user_id === 'temp');
  expect(temp?.expires_at).toBeTruthy();
  const chip = tid(page, 'data-share-holder-viewer-user-temp');
  await expect(chip).toContainText('expires in 2 days');
  // the absolute time, formatted as the Data tab formats it, in the page's language
  const expected = await page.evaluate(
    (iso) =>
      new Date(iso).toLocaleString(document.documentElement.lang || undefined, {
        dateStyle: 'medium',
        timeStyle: 'short',
      }),
    temp.expires_at,
  );
  await expect(chip.getByText('expires in 2 days')).toHaveAttribute('title', expected);
  // bob's grant has no expiry: no such note
  await expect(tid(page, 'data-share-holder-viewer-user-bob')).not.toContainText('expires');
});
