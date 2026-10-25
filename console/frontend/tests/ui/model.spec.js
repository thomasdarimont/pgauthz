// The Model tab's relation constraints in a real browser: the guided add
// form offers only pairs a constraint can apply to and disables Max direct
// with the reason where the engine would refuse it; a saved constraint shows
// in its section, as a badge in the Structure view (click to edit) and as
// "n / max active" in the share dialog. Needs the fixture store (fixture.sql:
// doc with owner/viewer direct rules, viewer restricted to user, can_share
// derived from owner; alice owns a and b, bob and temp view a) and the local
// admin, who may edit the model.
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
});

test('the add form offers only applicable pairs and explains a disabled Max direct', async ({ page }) => {
  await page.goto(`stores/${STORE}/model/relation_constraints`);
  await expect(tid(page, 'model-panel-relation_constraints')).toBeVisible();
  await tid(page, 'model-set-relation-constraint').click();
  const form = tid(page, 'model-form-set-relation-constraint');
  await expect(form).toBeVisible();
  // the relation select waits for a type; only types with rules are offered
  await expect(tid(page, 'model-input-constraint-relation')).toBeDisabled();
  const types = await tid(page, 'model-input-constraint-object-type').locator('option').allTextContents();
  expect(types.map((x) => x.trim())).toContain('doc');
  expect(types.map((x) => x.trim())).not.toContain('user'); // no rules on user
  await tid(page, 'model-input-constraint-object-type').selectOption('doc');
  await expect(tid(page, 'model-input-constraint-relation')).toBeEnabled();
  const rels = await tid(page, 'model-input-constraint-relation').locator('option').allTextContents();
  expect(rels.some((x) => x.includes('can_share') && x.includes('derived'))).toBe(true);
  // a derived relation cannot take a direct cap: the field is disabled and says why
  await tid(page, 'model-input-constraint-relation').selectOption('can_share');
  await expect(tid(page, 'model-input-constraint-max-direct')).toBeDisabled();
  await expect(tid(page, 'model-constraint-direct-why')).toContainText('derived');
  await expect(tid(page, 'model-input-constraint-max-effective')).toBeEnabled();
  // an assignable one can
  await tid(page, 'model-input-constraint-relation').selectOption('viewer');
  await expect(tid(page, 'model-input-constraint-max-direct')).toBeEnabled();
  await expect(tid(page, 'model-constraint-direct-why')).toHaveCount(0);
  await tid(page, 'model-form-cancel').click();
});

test('a saved constraint shows in its section, the Structure view and the share dialog', async ({ page }) => {
  await page.goto(`stores/${STORE}/model/relation_constraints`);
  await tid(page, 'model-set-relation-constraint').click();
  await tid(page, 'model-input-constraint-object-type').selectOption('doc');
  await tid(page, 'model-input-constraint-relation').selectOption('viewer');
  await tid(page, 'model-input-constraint-max-direct').fill('5');
  await tid(page, 'model-input-constraint-max-effective').fill('20');
  await tid(page, 'model-form-submit').click();
  const row = tid(page, 'model-relation-constraint-doc-viewer');
  await expect(row).toBeVisible();
  await expect(row).toContainText('5');
  await expect(row).toContainText('20');

  // the Structure view (Relations section) carries the badge; clicking it opens the edit form
  await page.goto(`stores/${STORE}/model/relations`);
  const badge = tid(page, 'model-relation-constraint-badge-doc-viewer');
  await expect(badge).toBeVisible();
  await expect(badge).toContainText('≤ 5 direct');
  await expect(badge).toContainText('≤ 20 effective');
  await badge.click();
  await expect(tid(page, 'model-panel-relation_constraints')).toBeVisible();
  await expect(tid(page, 'model-form-set-relation-constraint')).toBeVisible();
  await expect(tid(page, 'model-input-constraint-max-direct')).toHaveValue('5');
  await expect(tid(page, 'model-input-constraint-max-effective')).toHaveValue('20');
  await tid(page, 'model-form-cancel').click();

  // the share dialog says how full viewer on doc:a is (bob + temp = 2 active of 5)
  await page.goto(`stores/${STORE}/data`);
  await tid(page, 'data-share-open').click();
  await tid(page, 'data-share-type').fill('doc');
  await tid(page, 'data-share-id').fill('a');
  await tid(page, 'data-share-actor').fill('user:alice');
  await tid(page, 'data-share-load').click();
  await expect(tid(page, 'data-share-usage-viewer')).toContainText('2 / 5 active');
  // the constraint stays in the fixture store, which the harness drops after the run
});
