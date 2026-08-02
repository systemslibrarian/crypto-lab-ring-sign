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

/**
 * WCAG 1.4.11 — form-control boundaries must reach 3:1 against the adjacent
 * surface. Measures rendered computed styles, compositing translucent
 * backgrounds down the ancestor chain, so a token regression cannot pass by
 * only looking right in the source.
 */
async function minControlBorderRatio(page: Page): Promise<number> {
  return page.evaluate(() => {
    const parse = (c: string): number[] => {
      const m = c.match(/rgba?\(([^)]+)\)/);
      if (!m) return [0, 0, 0, 1];
      const p = m[1].split(',').map((v) => parseFloat(v));
      return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
    };
    const over = (top: number[], bot: number[]): number[] => {
      const a = top[3] + bot[3] * (1 - top[3]);
      return [
        (top[0] * top[3] + bot[0] * bot[3] * (1 - top[3])) / a,
        (top[1] * top[3] + bot[1] * bot[3] * (1 - top[3])) / a,
        (top[2] * top[3] + bot[2] * bot[3] * (1 - top[3])) / a,
        a,
      ];
    };
    const surfaceBehind = (el: Element | null): number[] => {
      const layers: number[][] = [];
      for (let n = el; n; n = n.parentElement) {
        const bg = parse(getComputedStyle(n).backgroundColor);
        if (bg[3] > 0) layers.push(bg);
        if (bg[3] >= 1) break;
      }
      let out = [255, 255, 255, 1];
      const rootBg = parse(getComputedStyle(document.documentElement).backgroundColor);
      if (rootBg[3] > 0) out = rootBg;
      for (let i = layers.length - 1; i >= 0; i--) out = over(layers[i], out);
      return out;
    };
    const lum = (c: number[]): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]);
    };
    const ratio = (a: number[], b: number[]): number => {
      const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x);
      return (hi + 0.05) / (lo + 0.05);
    };
    let min = Infinity;
    const controls = document.querySelectorAll<HTMLElement>(
      "input[type='text'], input[type='range'], select",
    );
    for (const el of controls) {
      if (!el.offsetParent) continue;
      const cs = getComputedStyle(el);
      const border = parse(cs.borderTopColor);
      // The border sits between the control fill and the outer surface;
      // it must clear 3:1 against at least one, per the SC's intent for
      // indicating the component's extent. Measure the outer surface —
      // the stricter, load-bearing side here.
      const outside = surfaceBehind(el.parentElement);
      const composited = border[3] < 1 ? over(border, outside) : border;
      min = Math.min(min, ratio(composited, outside));
    }
    return min;
  });
}

test('control borders reach 3:1 in dark theme (WCAG 1.4.11)', async ({ page }) => {
  await mount(page);
  const min = await minControlBorderRatio(page);
  expect(min).toBeGreaterThanOrEqual(3);
});

test('control borders reach 3:1 in light theme (WCAG 1.4.11)', async ({ page }) => {
  await mount(page);
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  const min = await minControlBorderRatio(page);
  expect(min).toBeGreaterThanOrEqual(3);
});
