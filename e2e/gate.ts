import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Six rules govern everything here, each one a correction of a specific thing
 * the spec this replaces did.
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. `neutralizeMotion()`
 *     pushed `animation-duration:0s; transition-duration:0s` through
 *     `addStyleTag`, BYPASSING `style.css`'s own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it.
 *     And on this page it could not have done the job anyway: the animation that
 *     matters is `animateChallengeChain()`, a JavaScript loop of
 *     `await setTimeout(300)` per ring member that calls `render()` between each
 *     one. No stylesheet can shorten that. The old drive therefore clicked
 *     `#ex1-run`, waited only for `.responses` to become visible — which happens
 *     on the FIRST render of the walk — and then scanned a page caught
 *     mid-animation at whatever step it had reached. This gate asks for reduced
 *     motion, ASSERTS it took effect, and waits on the chain-closed badge, which
 *     is the completion signal the code itself defines.
 *
 *  2. IT FORCE-OPENED EVERY DISCLOSURE FROM SCRIPT. `expandAll()` set
 *     `details.open = true` on all four mechanism explainers, bypassing the
 *     `<summary>` that is a reader's only route in — and bypassing the
 *     `summary::before { content: '▸' }` rotation that is the entire affordance
 *     saying they open at all. This gate clicks each summary.
 *
 *  3. IT SCANNED ONCE PER THEME, AT ONE VIEWPORT, AFTER THE WHOLE DRIVE.
 *     `driveDemos()` ran Exhibit 1, tampered twice, ran Exhibit 2, group-signed
 *     and opened — then scanned once. Every state it built was overwritten
 *     before anything measured it, and the ARRIVAL state (no signature, no
 *     ledger, no chart, `#group-open` disabled) was never scanned at all.
 *     Exhibit 3 was never run in any theme. This gate scans after every one of
 *     its steps, in {dark, light} x {1280, 380}.
 *
 *  4. IT REACHED THE LIGHT THEME BY CLICKING THE TOGGLE after `goto`, so every
 *     light-theme scan measured a page repainted mid-life rather than one that
 *     loaded that way. The theme is seeded through `localStorage` here, which
 *     also pins down whether the anti-flash script and the toggle agree on the
 *     key.
 *
 *  5. `violations` IS NOT THE WHOLE ORACLE, and the 1.4.11 test that was meant
 *     to cover part of the gap pointed at the wrong place. It measured
 *     `input[type='text'], input[type='range'], select` — three of the four
 *     selectors in the one rule `--line-strong` is applied to. The fourth is
 *     `button`, which it never queried; nor did it query anything drawn with
 *     `--line`, the surface divider used sixteen times. It also compared the
 *     border against the OUTER surface only, so a border invisible against the
 *     control's own fill scored fine, and it measured `input[type='range']`,
 *     whose boundary is drawn by the user agent rather than by this stylesheet.
 *     See `auditControlBoundaries`.
 *
 *  6. IT HAD NO REFLOW ORACLE and never opened a phone-width viewport, in a page
 *     whose `.shell` is a bare `display: grid` — an implicit single `auto` track
 *     whose automatic minimum is its widest item's MIN-CONTENT, so one wide
 *     panel sizes the whole document.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page cannot currently be in that shape, and the assertion is what makes
 * that a measurement rather than a reading: `style.css` declares no
 * `@keyframes`, and its reduced-motion block clamps durations only
 * (`animation-duration: 0.01ms`, `animation-iteration-count: 1`,
 * `transition-duration: 0.01ms`) — it sets no `display`, `opacity` or
 * `transform`. The check runs in every state regardless, because all of those
 * are properties of the current stylesheet rather than of the page.
 *
 * `aria-hidden` subtrees are excluded; see the header of `contrast.ts` for the
 * closed set this lab hides and why each member of it is safe.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken — which matters unusually much here, because `render()` rebuilds
 * `#app` from one `innerHTML` string and a throw inside it leaves the previous
 * DOM entirely intact and plausible. Attach before `boot`, assert after.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * `main.ts` renders `<header class="cl-hero">` INSIDE `<main class="shell">`,
 * which scopes it out of the banner role by nesting alone — a `<header>` implies
 * `banner` only when it is not inside sectioning content. `index.html`'s
 * `dedupeBanner()` would demote it anyway, and skips it for that same reason.
 * Asserting the OUTCOME rather than either mechanism catches a change to the
 * nesting as well as a failure of the script.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page.
 *
 * The theme is seeded through `localStorage` rather than by clicking the toggle,
 * which also pins down a real failure mode: `index.html`'s anti-flash script
 * reads `localStorage.getItem('theme')`, the shared bar's toggle writes
 * `localStorage.setItem('theme', …)`, and `main.ts`'s own `setTheme()` writes
 * the same key a third time. If any of the three drifted the theme would
 * silently stop persisting, and this boot fails on `data-theme` rather than
 * quietly scanning dark twice.
 *
 * The defaults are asserted at length because `init()` is ASYNC and does real
 * Ed25519 key generation plus a sanity sign-and-verify before the first
 * `render()`. Until that resolves `#app` is EMPTY — so a navigation that
 * resolves proves nothing at all, and every locator below is the difference
 * between measuring this lab and measuring a blank div.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // `init()` finishes with `render()`; the ring nodes are the last thing it
  // draws and the thing every Exhibit 1 assertion depends on.
  await expect(page.locator('#ex1-title')).toBeVisible();
  await expect(page.locator('.ring-node')).toHaveCount(5);
  await assertSingleBanner(page);

  // The reduced-motion block's visible consequence, asserted rather than
  // assumed. `.cl-btn` declares `transition: background .15s, border-color
  // .15s, color .15s` in the shared header's inline <style>; the only thing that
  // can shorten it is `style.css`'s `@media (prefers-reduced-motion: reduce)`
  // block, which clamps it to 0.01ms. If the emulation were a no-op this reads
  // `0.15s`. Chromium serialises 0.01ms as `1e-05s`, so the comparison is
  // numeric rather than textual — a string match on `0.00001s` fails against a
  // page that is behaving perfectly.
  expect(
    parseFloat(
      await page.evaluate(
        () => getComputedStyle(document.querySelector('.cl-btn')!).transitionDuration
      )
    ),
    "reduced motion must clamp the shared bar's transitions"
  ).toBeLessThan(0.001);

  // ── Five exhibits plus the preamble ──────────────────────────────────────
  await expect(page.locator('#app section.panel')).toHaveCount(6);
  await expect(page.locator('#app .cl-hero-title')).toHaveText('Ring Signatures');

  // ── Exhibit 1 defaults ───────────────────────────────────────────────────
  await expect(page.locator('#ring-size')).toHaveValue('5');
  await expect(page.locator('#signer-select')).toHaveValue('1');
  await expect(page.locator('#ex1-message')).toHaveValue('Monero input spend proof');
  // Nothing is signed on arrival, so none of Exhibit 1's output exists.
  await expect(page.locator('.responses')).toHaveCount(0);
  await expect(page.locator('.tamper')).toHaveCount(0);
  await expect(page.locator('.chain-badge')).toHaveCount(0);
  await expect(page.locator('.info-grid').first()).toContainText('no signature yet');
  await expect(page.locator('.info-grid').first()).toContainText('run exhibit to animate');
  // The view switch ships on "Your view".
  await expect(page.locator('#ex1-view-you')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#ex1-view-verifier')).toHaveAttribute('aria-pressed', 'false');

  // ── Exhibit 2 defaults: no ledger, so the Clear button ships DISABLED ────
  await expect(page.locator('#ex2-message-a')).toHaveValue('Spend output #a1');
  await expect(page.locator('#ex2-message-b')).toHaveValue('Spend output #a1 again');
  await expect(page.locator('#ex2-signer-b')).toHaveValue('1');
  await expect(page.locator('#ex2-reset')).toBeDisabled();
  await expect(page.locator('.ledger')).toHaveCount(0);

  // ── Exhibit 3: no sweep run, so the chart is a prompt ────────────────────
  await expect(page.locator('.scatter')).toHaveCount(0);
  await expect(page.locator('.curve-empty')).toBeVisible();

  // ── Exhibit 4: signing is possible, opening is not ───────────────────────
  await expect(page.locator('#group-member')).toHaveValue('0');
  await expect(page.locator('#group-message')).toHaveValue('Approve shielded settlement #42');
  await expect(page.locator('#group-sign')).toBeEnabled();
  await expect(page.locator('#group-open')).toBeDisabled();

  // Four mechanism explainers, all shut. `expandAll()` used to open these from
  // script; asserting the count is what makes clicking them mean something.
  await expect(page.locator('details.explainer')).toHaveCount(4);
  await expect(page.locator('details[open]')).toHaveCount(0);

  // The lab's own theme toggle is `hidden` because the shared bar replaces it.
  // `[hidden]` is specificity (0,1,0) — the same as a class — so a later
  // `.theme-toggle { display: … }` would silently defeat it. Read the computed
  // value rather than trusting the attribute.
  expect(
    await page.evaluate(() => getComputedStyle(document.querySelector('#theme-toggle')!).display),
    '[hidden] must actually resolve to display:none on the lab theme toggle'
  ).toBe('none');

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this page is
 * the shape that breaks it: `.shell` is a bare `display: grid` with NO
 * `grid-template-columns`, which is an implicit single `auto` track, and an auto
 * track's automatic minimum is its item's MIN-CONTENT. So the widest panel on
 * the page — the ledger, the response grid, the challenge chain, the 320-unit
 * scatter chart — sizes the entire document, and at 380px there is nothing to
 * absorb it. Elsewhere in this fleet the overflow checker named `.hero` while
 * the real cause was a table three panels down, so this reports the widest
 * UNCLIPPED element rather than the first one it finds.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * This is a real question here rather than a formality, because fixing a reflow
 * failure typically means adding `overflow-x: auto` to whatever was too wide —
 * and elsewhere in this sweep axe flagged a scroller with no `tabindex`
 * immediately after such a fix, having been silent before it only because the
 * panel was too wide to ever scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Anything focusable must show WHERE the focus is (WCAG 2.4.7).
 *
 * THE `page.keyboard.press('Tab')` BELOW IS THE WHOLE CHECK, not tidying.
 * Chromium only matches `:focus-visible` on a programmatic `focus()` once its
 * heuristic has seen a keyboard interaction, so an unprimed run measures plain
 * `:focus` and reports every correctly-styled element as unstyled. Measured
 * elsewhere in this sweep: unprimed, `matches(':focus-visible')` is false and
 * the computed outline style is `none`; after one real Tab it is true and the
 * outline resolves to the declared colour, identical to tabbing there for real.
 * An oracle that cannot tell "no focus ring" from "wrong kind of focus" invents
 * defects.
 */
export async function expectFocusVisible(page: Page, label: string): Promise<void> {
  await page.keyboard.press('Tab');
  const missing = await page.evaluate(() => {
    const snap = (el: Element): string => {
      const cs = getComputedStyle(el);
      return [cs.outlineStyle, cs.outlineWidth, cs.outlineColor, cs.boxShadow, cs.border].join('|');
    };
    const out: string[] = [];
    const active = document.activeElement;
    // Blur first. Without this the element that ALREADY holds focus is snapped
    // with its ring up, focused again (no change), and reported as having no
    // indicator.
    (active as HTMLElement | null)?.blur?.();
    for (const el of Array.from(
      document.querySelectorAll<HTMLElement>('[tabindex]:not([tabindex="-1"])')
    )) {
      if (!el.checkVisibility?.()) continue;
      const before = snap(el);
      el.focus();
      const after = snap(el);
      el.blur();
      if (before === after) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    if (active instanceof HTMLElement) active.focus();
    return Array.from(new Set(out));
  });
  expect(missing, `focusable elements with no visible focus indicator in state: ${label}`).toEqual(
    []
  );
}

/**
 * SC 1.4.11 (non-text contrast) for interactive controls: a control's boundary
 * has to be perceivable against what surrounds it.
 *
 * This is `minControlBorderRatio()`'s check, kept because it was right, with
 * three corrections.
 *
 * ITS AIM. It queried `input[type='text'], input[type='range'], select` — three
 * of the four selectors in the single rule `--line-strong` is applied to. The
 * fourth is `button`, and it was never measured; nor was anything drawn with
 * `--line`, the surface divider this stylesheet uses sixteen times against
 * `--line-strong`'s one. A check aimed only at where a rule is already kept
 * confirms itself; the same shape has now been found in a dozen repos in this
 * sweep.
 *
 * ITS ARITHMETIC. It compared the border against the OUTER surface only, so a
 * border invisible against the control's own FILL still scored fine — and a
 * solid button with no border would have scored 1:1 despite being perfectly
 * distinguishable. Here a control passes if EITHER its fill differs from the
 * surface behind it, OR its border stands out from that surface AND from its own
 * fill: `max(fill-vs-outside, min(border-vs-outside, border-vs-fill))`.
 *
 * ITS SUBJECT. It measured `input[type='range']`, whose boundary Chromium draws
 * itself from `accent-color` and the UA sheet; SC 1.4.11 explicitly exempts a
 * component "whose appearance is determined by the user agent and not modified
 * by the author", and reading `getComputedStyle` on one reports the UA's own
 * values rather than anything this stylesheet chose. Ranges are excluded here
 * and the exclusion is a decision, not an oversight.
 *
 * Two more deliberate exclusions:
 *  - `disabled` controls. WCAG exempts inactive components, and this page ships
 *    `#ex2-reset` and `#group-open` disabled until there is something to act on.
 *  - anything outside `#app`. The shared top bar is not this lab's to change —
 *    every repo in the fleet carries a byte-identical copy — and its `.cl-btn`
 *    boundary is measured and ratcheted by `nontext.ts` instead, then reported
 *    upward.
 */
export async function auditControlBoundaries(
  page: Page
): Promise<Array<{ sel: string; ratio: number }>> {
  return page.evaluate(() => {
    type C = { r: number; g: number; b: number; a: number };
    // Resolve through a canvas rather than a regex. The spec this replaces used
    // `c.match(/rgba?\(([^)]+)\)/)` and returned opaque BLACK for anything it
    // could not parse — so a `color-mix()` or an `oklab()` anywhere in the
    // ancestor chain would have been silently read as black, and this page's
    // panels sit on two `color-mix` radial gradients.
    const cv = document.createElement('canvas');
    cv.width = cv.height = 1;
    const ctx = cv.getContext('2d', { willReadFrequently: true })!;
    const parse = (s: string): C => {
      if (!s) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = '#000';
      ctx.fillStyle = s;
      const a = ctx.fillStyle;
      ctx.fillStyle = '#fff';
      ctx.fillStyle = s;
      if (a !== ctx.fillStyle) return { r: 0, g: 0, b: 0, a: 0 };
      ctx.clearRect(0, 0, 1, 1);
      ctx.fillStyle = s;
      ctx.fillRect(0, 0, 1, 1);
      const d = ctx.getImageData(0, 0, 1, 1).data;
      return { r: d[0], g: d[1], b: d[2], a: d[3] / 255 };
    };
    const over = (fg: C, bg: C): C => {
      const a = fg.a + bg.a * (1 - fg.a);
      if (a === 0) return { r: 0, g: 0, b: 0, a: 0 };
      return {
        r: (fg.r * fg.a + bg.r * bg.a * (1 - fg.a)) / a,
        g: (fg.g * fg.a + bg.g * bg.a * (1 - fg.a)) / a,
        b: (fg.b * fg.a + bg.b * bg.a * (1 - fg.a)) / a,
        a,
      };
    };
    const lum = (c: C): number => {
      const f = (v: number): number => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
      };
      return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
    };
    const ratio = (a: C, b: C): number => {
      const la = lum(a);
      const lb = lum(b);
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    };
    const backdrop = (start: Element | null): C => {
      const stack: C[] = [];
      for (let n = start; n; n = n.parentElement) {
        const c = parse(getComputedStyle(n).backgroundColor);
        if (c.a > 0) {
          stack.push(c);
          if (c.a >= 1) break;
        }
      }
      let out: C = { r: 255, g: 255, b: 255, a: 1 };
      for (let i = stack.length - 1; i >= 0; i--) out = over(stack[i], out);
      return out;
    };
    const describe = (el: Element): string => {
      const cls = el.getAttribute('class');
      return (
        el.tagName.toLowerCase() +
        (el.id ? `#${el.id}` : '') +
        (cls ? `.${cls.trim().split(/\s+/).join('.')}` : '')
      );
    };

    const out: Array<{ sel: string; ratio: number }> = [];
    const app = document.getElementById('app');
    if (!app) return out;
    app
      .querySelectorAll<HTMLElement>("button, select, textarea, input[type='text']")
      .forEach((el) => {
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return;
        if ((el as HTMLButtonElement).disabled) return;
        if (el.closest('[hidden]')) return;
        const cs = getComputedStyle(el);
        const outside = backdrop(el.parentElement);
        const fillRaw = parse(cs.backgroundColor);
        const fill = fillRaw.a > 0 ? over(fillRaw, outside) : outside;
        const byFill = ratio(fill, outside);
        let byBorder = 1;
        if (parseFloat(cs.borderTopWidth) > 0 && cs.borderTopStyle !== 'none') {
          const border = over(parse(cs.borderTopColor), fill);
          byBorder = Math.min(ratio(border, outside), ratio(border, fill));
        }
        out.push({
          sel: describe(el),
          ratio: Math.round(Math.max(byFill, byBorder) * 100) / 100,
        });
      });
    return out;
  });
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(String(e).slice(0, 6000));
  }
}

/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast, and
 * the arithmetic text walk cannot reach a control's boundary or a `::before`
 * glyph, because a pseudo-element is not an element and owns no text node. That
 * second half is live on this page: `.explainer summary::before { content: '▸' }`
 * is the entire affordance saying the four mechanism explainers open, because
 * the same rule hides the user agent's own disclosure marker.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate. So it ratchets: anything NOT in the baseline fails,
 * anything in the baseline that got WORSE fails, and anything in the baseline
 * that has been FIXED fails until its entry is deleted.
 *
 * It is called from `scan()`, at every driven state. That placement is the whole
 * point: in the reference gate this pattern came from it was reachable only from
 * inside an `if (!COLLECTING) return …` guard, so it never executed in a strict
 * run and every "no new non-text failures" claim was vacuous.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(
        `NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`
      );
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(
        `NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`
      );
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(`WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`);
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive. It has
 * either been fixed — in which case delete the entry, which is the point — or
 * the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Nine assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus three landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those ratios
 *    arithmetically — which matters here, because every panel on this page is a
 *    translucent `rgba()` over two `color-mix` radial gradients and axe declines
 *    to resolve the composite. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less element hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node,
 *    including the footer's inline `opacity: 0.8`, which axe reads through.
 *  - non-text contrast for interactive controls — SC 1.4.11; see
 *    `auditControlBoundaries`.
 *  - the 1.4.11 / generated-content ratchet over the whole page, shared bar
 *    included.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - a visible focus indicator on everything given `tabindex` — WCAG 2.4.7.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write the same
  // `options.runOnly` field, so the second call SILENTLY REPLACES the first —
  // the axe-core/playwright source says so in as many words on `withRules`
  // ("Cannot be used with AxeBuilder#withTags"). Chained as
  // `.withTags(TAGS).withRules([...landmark rules])`, axe therefore runs those
  // few best-practice rules and NOT ONE WCAG RULE, while a green result reads
  // exactly like a full A/AA pass. For scale, `withTags(TAGS)` selects 69 of
  // axe-core 4.12's 105 rule definitions; the chained form executes 4.
  //
  // Running the two sets separately and merging is the only way to have both.
  // The landmark rules are still wanted because they are best-practice rather
  // than WCAG-tagged, so `withTags` alone does not reach them — and this page
  // has the exact shape they catch: a shared sticky `<header role="banner">`
  // above a `<main class="shell" role="main">` that contains a second
  // `<header class="cl-hero">`.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page })
    .withRules(['landmark-no-duplicate-banner', 'landmark-unique', 'landmark-one-main'])
    .analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  const boundaries = await auditControlBoundaries(page);
  expect(boundaries.length, `no controls found to measure in state: ${label}`).toBeGreaterThan(0);
  const undelineated = Array.from(
    new Set(boundaries.filter((b) => b.ratio < 3).map((b) => `${b.ratio}:1 ${b.sel}`))
  );
  softExpect(undelineated, `control boundaries under 3:1 (SC 1.4.11) in state: ${label}`, []);

  await soft(() => expectNoNewNonTextFailures(page, label));
  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectFocusVisible(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}

// ── The drive ───────────────────────────────────────────────────────────────

/**
 * Open one `<details class="explainer">` by clicking its `<summary>`.
 *
 * Never `details.open = true`. `expandAll()` did exactly that to all four, which
 * bypasses both the `<summary>` a reader has to press and the
 * `summary::before` glyph rotation that is the only cue they can be pressed.
 */
async function openExplainer(page: Page, index: number): Promise<void> {
  const d = page.locator('details.explainer').nth(index);
  await d.locator('summary').click();
  await expect(d).toHaveAttribute('open', '');
}

/**
 * Sign in Exhibit 1 and wait for the challenge walk to FINISH.
 *
 * `animateChallengeChain()` is a JS loop — `render()`, `await setTimeout(300)`,
 * once per ring member, then a final 200ms — so the page passes through n+1
 * distinct renderings and no stylesheet can shorten it. The old gate waited only
 * for `.responses` to appear, which happens on the first of those renderings, so
 * it scanned a half-walked ring. `.chain-badge` is written only after the walk
 * returns to node 0, which makes it the completion signal the code itself
 * defines.
 */
async function signAndWaitForChain(page: Page): Promise<void> {
  await page.locator('#ex1-run').click();
  await expect(page.locator('.chain-badge')).toHaveCount(1, { timeout: 30_000 });
  await expect(page.locator('.responses')).toBeVisible();
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Six things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST. Nothing is signed, there is no ledger,
 *    no chart and no group signature, and two buttons ship `disabled`. The gate
 *    this replaces called `driveDemos()` immediately after `goto`, so it never
 *    measured the state every reader arrives in.
 *
 *  - THE CHALLENGE WALK IS WAITED OUT, NOT RACED. See `signAndWaitForChain`.
 *
 *  - BOTH SIDES OF THE PRIVILEGE FORK. Exhibit 1's whole claim is that one
 *    highlight is privileged information: "Your view" can reveal which slot was
 *    closed with the secret, the "Verifier's view" cannot and disables the
 *    reveal button. Those are three distinct renderings — reveal off, reveal on
 *    with `.response-chip-closed` and `.closed-tag` painted, and the verifier's
 *    view with the control disabled — and each has ink the others do not.
 *
 *  - BOTH TAMPER OUTCOMES AND THE BROKEN CLOSING EDGE. Flipping a response byte
 *    and verifying against a modified message each produce a `.chain-badge-fail`
 *    and a red dashed closing connector, which is the only state where
 *    `--danger` is painted as a verdict rather than as prose.
 *
 *  - BOTH LEDGER BRANCHES. Signing spend B with the SAME member is the only
 *    route to the rejected double-spend row (`.ledger-reject`); signing it with
 *    a DIFFERENT member is the only route to the all-accepted ledger note. The
 *    old drive ran the default, which is the same-signer case, and never saw the
 *    other.
 *
 *  - EXHIBIT 3 AT ALL. The timing sweep was never run by the old gate in either
 *    theme, so the scatter chart — an SVG with axis ticks, two series, a dashed
 *    reference line and a legend — had never been scanned. It is run here, and
 *    the busy state (`aria-busy`, a disabled button reading "Measuring…") is
 *    scanned on the way.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  // The skip link is reached BEFORE anything else, and that ordering is
  // load-bearing rather than stylistic. `expectFocusVisible` — which every
  // `scan` runs — focuses and blurs each `tabindex` element in turn, and
  // Chromium's sequential focus navigation starting point follows the last blur,
  // so after one scan `Tab` resumes from the middle of the document.
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('skip link focused');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await scanAt('first paint, nothing signed and two controls locked');

  // ── Exhibit 1 ───────────────────────────────────────────────────────────
  await signAndWaitForChain(page);
  await expect(page.locator('.chain-badge-ok')).toHaveCount(1);
  await expect(page.locator('.response-chip')).toHaveCount(5);
  await expect(page.locator('.info-grid').first()).toContainText('valid ring signature');
  await scanAt('signed and verified, the challenge chain closed');

  // The privileged reveal — the one place the signer may be named.
  await expect(page.locator('.response-chip-closed')).toHaveCount(0);
  await page.locator('#ex1-reveal-signer').click();
  await expect(page.locator('.response-chip-closed')).toHaveCount(1);
  await expect(page.locator('.closed-tag')).toBeVisible();
  await scanAt('the closed slot revealed, privileged view');

  await page.locator('#ex1-reveal-signer').click();
  await expect(page.locator('.response-chip-closed')).toHaveCount(0);

  // The verifier's view, where the reveal control is disabled and says so.
  await page.locator('#ex1-view-verifier').click();
  await expect(page.locator('#ex1-view-verifier')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#ex1-reveal-signer')).toBeDisabled();
  await expect(page.locator('.reveal-note')).toContainText('A verifier holds no such control');
  await scanAt("the verifier's view, reveal disabled");

  await page.locator('#ex1-view-you').click();
  await expect(page.locator('#ex1-reveal-signer')).toBeEnabled();

  // Both tamper paths. Each rewrites the ring's closing edge as broken.
  await page.locator('#ex1-tamper-response').click();
  await expect(page.locator('.chain-badge-fail')).toHaveCount(1);
  await expect(page.locator('.tamper-result')).toContainText('rejected');
  await expect(page.locator('.ring-edge-broken')).toHaveCount(1);
  await scanAt('one response byte flipped — the chain no longer closes');

  await page.locator('#ex1-tamper-message').click();
  await expect(page.locator('.tamper-result')).toContainText('changed message');
  await expect(page.locator('.chain-badge-fail')).toHaveCount(1);
  await scanAt('verified against a modified message — rejected');

  await openExplainer(page, 0);
  await scanAt('the ring explainer open');

  // A larger ring: eleven nodes, eleven responses, eleven challenge spans. This
  // is the widest this page ever gets, which is what makes it the reflow case.
  await page.locator('#ring-size').fill('11');
  await expect(page.locator('.ring-node')).toHaveCount(11);
  // Changing the ring retracts the verdict, which is a state of its own.
  await expect(page.locator('.responses')).toHaveCount(0);
  await scanAt('ring resized to 11, the verdict retracted');

  await signAndWaitForChain(page);
  await expect(page.locator('.response-chip')).toHaveCount(11);
  await scanAt('an eleven-member ring signed and closed');

  await page.locator('#ring-size').fill('5');
  await expect(page.locator('.ring-node')).toHaveCount(5);

  // ── Exhibit 2, both ledger branches ─────────────────────────────────────
  // Spend B signed by the SAME member: the key images match and the second
  // submission is rejected as a double-spend.
  await signAndWaitForChain(page);
  await page.selectOption('#ex2-signer-b', '1');
  await page.locator('#ex2-run').click();
  await expect(page.locator('.ledger-row')).toHaveCount(2);
  await expect(page.locator('.ledger-reject')).toHaveCount(1);
  await expect(page.locator('.info-grid').nth(1)).toContainText('yes — the two key images are equal');
  await scanAt('the same signer spends twice — double-spend rejected');

  await page.locator('#ex2-reset').click();
  await expect(page.locator('.ledger')).toHaveCount(0);
  await expect(page.locator('#ex2-reset')).toBeDisabled();
  await scanAt('ledger cleared');

  // Spend B signed by a DIFFERENT member: two distinct key images, both
  // accepted. This branch is unreachable from the shipped defaults.
  await page.selectOption('#ex2-signer-b', '3');
  await page.locator('#ex2-run').click();
  await expect(page.locator('.ledger-row')).toHaveCount(2);
  await expect(page.locator('.ledger-reject')).toHaveCount(0);
  await expect(page.locator('.info-grid').nth(1)).toContainText('no — the two key images differ');
  await scanAt('two different signers — both spends accepted');

  await openExplainer(page, 1);
  await scanAt('the key-image explainer open');

  // ── Exhibit 3: the timing sweep, never run by the old gate ──────────────
  await page.locator('#ex3-run').click();
  // The busy state is real and short-lived: the button goes disabled with
  // `aria-busy` and the chart streams in size by size.
  await expect(page.locator('#ex3-run')).toHaveAttribute('aria-busy', 'true');
  await scanAt('the timing sweep running, chart streaming in');

  await expect(page.locator('#ex3-run')).toBeEnabled({ timeout: 180_000 });
  await expect(page.locator('.scatter')).toHaveCount(1);
  await expect(page.locator('.scatter .dot')).not.toHaveCount(0);
  await expect(page.locator('.info-grid').nth(2)).toContainText('Measured on your machine');
  await scanAt('the timing sweep complete, the fitted curve charted');

  await openExplainer(page, 2);
  await scanAt('the ring-size explainer open');

  // ── Exhibit 4: group sign, then the manager opens ───────────────────────
  await page.locator('#group-sign').click();
  await expect(page.locator('.info-grid').nth(3)).toContainText('valid group credential');
  await expect(page.locator('#group-open')).toBeEnabled();
  await scanAt('group-signed anonymously, the manager open now possible');

  await page.locator('#group-open').click();
  await expect(page.locator('.info-grid').nth(3)).toContainText('Member Alpha');
  await scanAt('the manager opened the signature and named the member');

  // A second signature from a different member, which is what makes the
  // pseudonym-linkage readout say something other than "1 of 1".
  await page.selectOption('#group-member', '1');
  await page.locator('#group-sign').click();
  await expect(page.locator('.info-grid').nth(3)).toContainText('2 across 2 distinct signers');
  await scanAt('a second member signs — the linkage readout updates');

  await openExplainer(page, 3);
  await scanAt('the group-signature explainer open, every disclosure now open');
}
