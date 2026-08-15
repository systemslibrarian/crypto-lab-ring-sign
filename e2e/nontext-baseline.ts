/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  // What the live oracle finds, over {dark, light} x {1280, 380} and every one
  // of the 21 states the drive builds, is exactly these two — both in the SHARED
  // Crypto Lab top bar, and neither one this repo's to fix.
  //
  // `.cl-btn` draws its edge as
  // `1px solid color-mix(in srgb, var(--accent, #35d6bb) 38%, transparent)` over
  // the bar's fixed `#0b1512`. Unlike most labs this one gives `--accent` a
  // DIFFERENT value per theme — #5ce0b6 mint in dark, #07735a dark teal in light
  // — while the bar itself is always dark, so the composited edge measures
  // 2.61:1 in dark and 1.45:1 in light. The bar's markup and CSS are a
  // byte-identical copy carried by every repo in the fleet, and `CLAUDE.md` is
  // explicit that a change every lab should get is a reviewed fleet-wide pass
  // and never an overwrite driven from one repo. So it is measured here,
  // ratcheted here, and reported upward.
  //
  // The recorded number is the LIGHT one, because a single baseline key covers
  // both themes and the ratchet fails on anything below it. The cost is stated
  // rather than hidden: a dark-theme regression from 2.61:1 down to 1.46:1 would
  // not trip this entry. It would trip the moment the fleet-wide fix lands and
  // the entry has to be deleted, which is the direction that matters.
  'control-boundary|a.cl-btn': { ratio: 1.45, required: 3, unverified: false },
};
