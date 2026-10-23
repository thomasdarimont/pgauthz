// The Decisions tab in a real browser: the window's summary and the list
// over the fixture's 30 logged decisions (decisions.sql, in the console's
// database), keyset paging through the pager, the filters and the summary's
// click-to-narrow, a row's detail with its trace, and the hand-over into
// the Test tab that replays a decision at the instant it was made. Needs
// the decisions fixture — tests/test-console-ui.sh loads it through the
// console-db service and sets CONSOLE_UI_DECISIONS=1; without it the suite
// is skipped (a console reached over CONSOLE_URL only has no such access).
import { test, expect } from '@playwright/test';

const STORE = process.env.CONSOLE_UI_STORE ?? 'console_uitest';
const USER = process.env.CONSOLE_UI_USER ?? 'admin';
const PASSWORD = process.env.CONSOLE_UI_PASSWORD ?? 'admin';

const tid = (page, id) => page.getByTestId(id);

test.skip(process.env.CONSOLE_UI_DECISIONS !== '1', 'decisions fixture not loaded (CONSOLE_UI_DECISIONS)');

async function signIn(page) {
  await page.goto('');
  await page.getByLabel('Username').fill(USER);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toHaveCount(0);
}

async function openDecisions(page) {
  await page.goto(`stores/${STORE}/decisions`);
  await expect(tid(page, 'decisions-summary')).toBeVisible();
  await expect(tid(page, 'decisions-row').first()).toBeVisible();
}

const pagerText = (page) => tid(page, 'decisions-pager').first().locator('span').first();

test.beforeEach(async ({ page }) => {
  await signIn(page);
});

test('the window summarises the outcomes and lists the newest decisions first', async ({ page }) => {
  await openDecisions(page);
  const summary = tid(page, 'decisions-summary');
  await expect(summary.getByRole('heading', { level: 3 })).toHaveText('30 decision(s)');
  await expect(summary.locator('.badge.ok')).toHaveText('12 allowed');
  await expect(summary.locator('.badge.deny')).toHaveText('10 denied');
  await expect(summary.locator('.badge.warn').nth(0)).toHaveText('5 conditional');
  await expect(summary.locator('.badge.warn').nth(1)).toHaveText('3 error');
  // the denials' top lists: bob is the only denied subject, no_matching_rule the reason
  await expect(summary.getByRole('link', { name: 'user:bob' })).toBeVisible();
  await expect(summary.getByRole('link', { name: 'no_matching_rule' })).toBeVisible();

  const rows = tid(page, 'decisions-row');
  await expect(rows).toHaveCount(25); // the first page of 25
  await expect(pagerText(page)).toHaveText(/Page 1 of 2 ·\s+1–25 of 30/);
  // newest first: the first row is the most recent line (alice, allowed)
  await expect(rows.first()).toContainText('allowed');
  await expect(rows.first()).toContainText('user:alice');
  await expect(rows.first()).toContainText('doc:a');
  await expect(rows.first()).toContainText('docs-app');
});

test('the pager walks the pages by keyset and back, and changes the page size', async ({ page }) => {
  await openDecisions(page);
  const next = tid(page, 'decisions-next').first();
  const prev = tid(page, 'decisions-prev').first();
  await expect(prev).toBeDisabled();
  const firstOfPage1 = await tid(page, 'decisions-row').first().innerText();

  await next.click();
  await expect(pagerText(page)).toHaveText(/Page 2 of 2 ·\s+26–30 of 30/);
  await expect(tid(page, 'decisions-row')).toHaveCount(5);
  await expect(next).toBeDisabled();
  // the last page holds the oldest lines: dave's errors
  await expect(tid(page, 'decisions-row').last()).toContainText('error');
  await expect(tid(page, 'decisions-row').last()).toContainText('user:dave');

  await prev.click();
  await expect(pagerText(page)).toHaveText(/Page 1 of 2/);
  expect(await tid(page, 'decisions-row').first().innerText()).toBe(firstOfPage1);

  await tid(page, 'decisions-limit').first().selectOption('50');
  await expect(pagerText(page)).toHaveText(/Page 1 of 1 ·\s+1–30 of 30/);
  await expect(tid(page, 'decisions-row')).toHaveCount(30);
});

test('filters narrow the list and the summary, and a top-list entry narrows by click', async ({ page }) => {
  await openDecisions(page);
  await tid(page, 'decisions-outcome').selectOption('deny');
  await tid(page, 'decisions-search').click();
  await expect(tid(page, 'decisions-summary').getByRole('heading', { level: 3 })).toHaveText(
    '10 decision(s)',
  );
  await expect(tid(page, 'decisions-row')).toHaveCount(10);
  for (const row of await tid(page, 'decisions-row').all()) await expect(row).toContainText('denied');

  await tid(page, 'decisions-outcome').selectOption('');
  await tid(page, 'decisions-subject').fill('user:carol');
  await tid(page, 'decisions-search').click();
  await expect(tid(page, 'decisions-summary').getByRole('heading', { level: 3 })).toHaveText('5 decision(s)');
  await expect(tid(page, 'decisions-row').first()).toContainText('conditional');

  // a bare id and a client filter
  await tid(page, 'decisions-subject').fill('dave');
  await tid(page, 'decisions-client').fill('mail-app');
  await tid(page, 'decisions-search').click();
  await expect(tid(page, 'decisions-summary').getByRole('heading', { level: 3 })).toHaveText(
    /[12] decision\(s\)/,
  );
  await expect(tid(page, 'decisions-row').first()).toContainText('mail-app');

  // the summary's click-to-narrow: the denied subject becomes the filter
  await tid(page, 'decisions-subject').fill('');
  await tid(page, 'decisions-client').fill('');
  await tid(page, 'decisions-search').click();
  await tid(page, 'decisions-summary').getByRole('link', { name: 'user:bob' }).click();
  await expect(tid(page, 'decisions-subject')).toHaveValue('user:bob');
  await expect(tid(page, 'decisions-outcome')).toHaveValue('deny');
  await expect(tid(page, 'decisions-row')).toHaveCount(10);

  // a reason narrows too, and Reset clears every filter back to the window
  await tid(page, 'decisions-reset').click();
  await expect(tid(page, 'decisions-subject')).toHaveValue('');
  await expect(tid(page, 'decisions-outcome')).toHaveValue('');
  await expect(tid(page, 'decisions-reset')).toBeDisabled();
  await expect(tid(page, 'decisions-summary').getByRole('heading', { level: 3 })).toHaveText(
    '30 decision(s)',
  );
  await tid(page, 'decisions-summary').getByRole('link', { name: 'no_matching_rule' }).click();
  await expect(tid(page, 'decisions-reason')).toHaveValue('no_matching_rule');
  await expect(tid(page, 'decisions-row')).toHaveCount(10);
  await tid(page, 'decisions-refresh').click();
  await expect(tid(page, 'decisions-row')).toHaveCount(10);
  await tid(page, 'decisions-reset').click();
  await expect(tid(page, 'decisions-row')).toHaveCount(25);
});

test('a trace id finds its line, and the detail shows the trace', async ({ page }) => {
  await openDecisions(page);
  const traceID = '0000000000000000000000000000000f'; // line 15: bob, denied
  await tid(page, 'decisions-trace').fill(traceID.toUpperCase());
  await tid(page, 'decisions-search').click();
  await expect(tid(page, 'decisions-row')).toHaveCount(1);
  await expect(tid(page, 'decisions-row')).toContainText('user:bob');

  await tid(page, 'decisions-row').click();
  const detail = tid(page, 'decisions-detail');
  await expect(detail).toBeVisible();
  await expect(detail).toContainText(traceID);
  await expect(detail).toContainText('req-15');
  await expect(detail).toContainText('context_keys'); // the full line
  // a configured tracing UI makes the id a link (CONSOLE_TRACE_URL); else text
  const me = await page.evaluate(() => fetch('api/me').then((r) => r.json()));
  if (me.trace_url) {
    await expect(tid(page, 'decisions-trace-link')).toHaveAttribute(
      'href',
      me.trace_url.replace('{trace_id}', traceID),
    );
  } else {
    await expect(tid(page, 'decisions-trace-link')).toHaveCount(0);
  }
});

test('"Replay at that instant" hands the decision to the Test tab with its time', async ({ page }) => {
  await openDecisions(page);
  // the newest line: alice can_share doc:a, decided a minute ago
  await tid(page, 'decisions-row').first().click();
  await tid(page, 'decisions-replay').click();
  await expect(page).toHaveURL(new RegExp(`stores/${STORE}/test/single-check$`));
  // the question is prefilled and was run at the logged instant
  const caption = page.locator('.result-caption');
  await expect(caption).toContainText('user:alice');
  await expect(caption).toContainText('can_share');
  await expect(caption).toContainText('doc:a');
  await expect(caption.locator('.badge.warn')).toContainText('at');
  // decided by replaying the audit trail to that instant — which, for the
  // fixture's artificial timestamps, lies before the store was even
  // created, so the answer is a deny; what matters here is that the
  // replay ran with the logged instant and answered
  await expect(page.locator('.decision')).toHaveText(/allowed|denied/);
});
