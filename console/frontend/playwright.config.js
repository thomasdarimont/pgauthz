// Browser tests for the console SPA, against a RUNNING console (the
// console-local stack: ./start.sh --console-local, local admin admin/admin)
// with the fixture store loaded — ../../tests/test-console-ui.sh does both
// and is the way to run them. CONSOLE_URL overrides the base URL,
// CONSOLE_UI_USER / CONSOLE_UI_PASSWORD the sign-in.
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: 'tests/ui',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 30_000,
  reporter: [['list']],
  outputDir: 'test-results',
  use: {
    baseURL: process.env.CONSOLE_URL ?? 'http://localhost:8095/console/',
    browserName: 'chromium',
    headless: true,
    trace: 'retain-on-failure',
  },
});
