import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * Strict WCAG regression gate. Scans the fully-mounted app with every
 * collapsible expanded and every live demo driven so dynamically-injected
 * result regions are covered, in both dark (default) and light themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function mount(page: Page): Promise<void> {
  await page.goto('.');
  // App renders into #app; wait for the first exhibit to exist.
  await expect(page.locator('#ex1-title')).toBeVisible();
}

async function neutralizeMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation-duration:0s!important;animation-delay:0s!important;
      transition-duration:0s!important;transition-delay:0s!important;
    }`,
  });
}

async function driveDemos(page: Page): Promise<void> {
  // Exhibit 1 — sign & verify (renders responses, tamper controls, key image).
  await page.locator('#ex1-run').click();
  await expect(page.locator('.responses')).toBeVisible();
  // Reveal tamper result regions.
  await page.locator('#ex1-tamper-response').click();
  await page.locator('#ex1-tamper-message').click();

  // Exhibit 2 — key image linkability.
  await page.locator('#ex2-run').click();

  // Exhibit 4 — group sign then manager open.
  await page.locator('#group-sign').click();
  await expect(page.locator('#group-open')).toBeEnabled();
  await page.locator('#group-open').click();

  // Let any queued renders settle.
  await page.waitForTimeout(150);
}

async function expandAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await mount(page);
  await neutralizeMotion(page);
  await driveDemos(page);
  await expandAll(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await mount(page);
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await neutralizeMotion(page);
  await driveDemos(page);
  await expandAll(page);
  await scan(page);
});
