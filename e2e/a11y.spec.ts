import { expect, test } from '@playwright/test';
import {
  boot,
  driveAllStates,
  expectBaselineNotStale,
  NARROW,
  reportCollected,
  watchPageErrors,
} from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches: the arrival state, where
 * nothing is signed and two controls ship disabled; the skip link focused; a
 * ring signed and the challenge walk WAITED OUT to its closing badge; the
 * privileged reveal on and off, and the verifier's view where the same control
 * is disabled; both tamper paths, each of which paints the broken closing
 * connector; the ring resized to eleven, which retracts the verdict and is the
 * widest this page ever gets; both ledger branches — the same signer spending
 * twice (rejected double-spend) and two different signers (both accepted), the
 * second of which is unreachable from the shipped defaults; the timing sweep,
 * both while it is streaming in and once the fitted curve is charted; a group
 * signature, the manager opening it, and a second member signing so the
 * pseudonym-linkage readout says something other than "1 of 1"; and all four
 * mechanism explainers, each opened by clicking its own summary. Every one of
 * those states is scanned, in both themes, at desktop and phone width.
 *
 * See `gate.ts` for why nothing is injected into the page, why the challenge
 * walk cannot be shortened by a stylesheet, why no `<details>` is opened from
 * script, why the theme is seeded rather than toggled, why the lab's defaults
 * are asserted rather than assumed, and what the old `minControlBorderRatio`
 * test was actually measuring.
 */

for (const theme of ['dark', 'light'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page }) => {
    test.setTimeout(900_000);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    expectBaselineNotStale();
    reportCollected();
  });
}
