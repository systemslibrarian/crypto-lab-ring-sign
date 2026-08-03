import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Functional regression gate for the LSAG ring-signature demo.
 *
 * The a11y spec proves the page is reachable and scannable; this one proves the
 * page is *right*. Nothing here is asserted against a value this file invented:
 * every verdict is checked against the numbers the page itself put on screen —
 * the rendered challenge chain decides whether "chain closed" is allowed to
 * appear, the rendered key images decide whether "reuse detected" is allowed to
 * say yes, and the rendered least-squares fit decides whether the sweep is
 * allowed to call itself linear. The claims pinned:
 *
 *   1. Success: the walk returns to c0. The badge may read "chain closed" only
 *      when the LAST rendered challenge really equals the FIRST one, and the
 *      closing edge is drawn solid only then.
 *   2. Anonymity (the README's headline claim, and the page's own "Verifier
 *      cannot identify signer" badge): with the privileged reveal off, nothing
 *      the verifier sees distinguishes the signer's slot — the test picks the
 *      signer itself, so it knows the answer the page is withholding, and then
 *      forces the reveal to prove the page knew it all along.
 *   3. Every failure path the app exposes: a flipped response byte, a modified
 *      message, and the ledger's double-spend rejection — each asserted to
 *      reach the failure state AND to name its cause on screen.
 *   4. Counters are internally consistent, not merely present: ring size ==
 *      nodes == edges == responses == chain length - 1 at several sizes, the
 *      ledger's accept/reject pattern follows from the key images it displays,
 *      the timing sweep's dot count matches the sample count it claims to have
 *      fitted, and the group readout's "N signatures across D signers" follows
 *      from the signatures actually produced.
 *   5. Stale state: changing the ring or the message retracts the verdict; it
 *      never lingers over inputs it was not computed from.
 *
 * Three of these are regressions for bugs this suite found:
 *   - the verifier's view hid the ring highlight but left the response grid and
 *     the reveal note naming the signer's slot (test "the verifier's view
 *     withholds every disclosure");
 *   - moving the signer dropdown after signing moved the "actual signer"
 *     highlight to a member who had not signed, while the response grid kept
 *     marking the real one — two different signers named at once (test "the
 *     revealed slot follows the signature on screen");
 *   - editing the message left "valid ring signature", the closed-chain badge
 *     and the whole recomputed chain standing over a message they were never
 *     computed from (test "editing the message retracts the verdict").
 */

const CHAIN_VALUE = /^[0-9a-f]{7}\.\.\.[0-9a-f]{5}$/;
const KEY_IMAGE = /^[0-9a-f]{16}\.\.\.[0-9a-f]{14}$/;
const RESPONSE_VALUE = /^[0-9a-f]{6}\.\.\.[0-9a-f]{6}$/;

/** The four `.info-grid` readouts, in page order. */
const grid = (page: Page, exhibit: 1 | 2 | 3 | 4): Locator =>
  page.locator('.info-grid').nth(exhibit - 1);

const line = (page: Page, exhibit: 1 | 2 | 3 | 4, index: number): Locator =>
  grid(page, exhibit).locator('p').nth(index);

async function text(locator: Locator): Promise<string> {
  return ((await locator.textContent()) ?? '').replace(/\s+/g, ' ').trim();
}

/** The challenge values as rendered, with the `c0=` / `cₙ=` labels stripped. */
async function renderedChain(page: Page): Promise<string[]> {
  const cells = await page.locator('.chain-wrap .chain').allTextContents();
  return cells.map((c) => c.split('=').slice(1).join('=').trim());
}

/** Run exhibit 1 and wait out the edge-by-edge walk animation. */
async function signAndWait(page: Page): Promise<void> {
  await page.locator('#ex1-run').click();
  // The badge is only rendered once the walk has returned to node 0, so waiting
  // for it is waiting for the animation to finish. A ring of 11 takes ~3.5s.
  await expect(page.locator('.chain-badge')).toBeVisible({ timeout: 20_000 });
}

async function setRingSize(page: Page, size: number): Promise<void> {
  await page.locator('#ring-size').fill(String(size));
  await expect(page.locator('.ring-node')).toHaveCount(size);
}

/** Index of the single ring node flagged as the signer, or -1 if none is. */
async function markedNodeIndex(page: Page): Promise<number> {
  const labels = await page.locator('.ring-node').evaluateAll((nodes) =>
    nodes.map((n) => n.className),
  );
  return labels.findIndex((c) => c.includes('ring-node-signer'));
}

/** The response grid, decomposed: slot label, truncated scalar, extra marking. */
async function responseChips(
  page: Page,
): Promise<{ label: string; value: string; tagged: boolean }[]> {
  return page.locator('.response-chip').evaluateAll((chips) =>
    chips.map((chip) => ({
      label: chip.querySelector('.response-label')?.textContent?.trim() ?? '',
      value: chip.querySelector('code')?.textContent?.trim() ?? '',
      tagged: chip.querySelector('.closed-tag') !== null,
    })),
  );
}

/** Index of the single response chip flagged as closed with the secret, or -1. */
async function markedChipIndex(page: Page): Promise<number> {
  const classes = await page.locator('.response-chip').evaluateAll((chips) =>
    chips.map((c) => c.className),
  );
  return classes.findIndex((c) => c.includes('response-chip-closed'));
}

// Uncaught page exceptions fail the test that provoked them. Reset per test;
// a worker only ever runs one test at a time, so this stays test-scoped.
let pageErrors: string[] = [];

test.beforeEach(async ({ page }) => {
  pageErrors = [];
  page.on('pageerror', (error) => pageErrors.push(String(error)));
  await page.goto('.');
  // The app boots asynchronously (it generates a ring and runs a self-check
  // before its first render), so wait for the controls rather than the shell.
  await expect(page.locator('#ex1-run')).toBeVisible();
  await expect(page.locator('.panel.error')).toHaveCount(0);
});

test.afterEach(() => {
  expect(pageErrors).toEqual([]);
});

test('a fresh signature closes its own chain, and the badge follows the chain', async ({ page }) => {
  await expect(line(page, 1, 0)).toHaveText('Verification: no signature yet');
  await expect(page.locator('.chain-badge')).toHaveCount(0);

  await signAndWait(page);

  // The verdict is checked against the page's OWN recomputed chain: the last
  // challenge must equal the first, which is exactly what "the loop closes"
  // means. A wrong verdict cannot be papered over with a hardcoded string.
  const chain = await renderedChain(page);
  expect(chain.length).toBeGreaterThan(2);
  for (const value of chain) expect(value).toMatch(CHAIN_VALUE);
  expect(chain[chain.length - 1]).toBe(chain[0]);

  await expect(page.locator('.chain-badge')).toHaveText(/chain closed: c.* == c0/);
  await expect(page.locator('.chain-badge')).toHaveClass(/chain-badge-ok/);
  await expect(line(page, 1, 0)).toHaveText('Verification: valid ring signature');

  // The closing connector is solid, not the dashed/red broken variant.
  const closing = page.locator('.ring-edge-closing');
  await expect(closing).toHaveCount(1);
  await expect(closing).toHaveClass(/ring-edge-closed/);
  await expect(closing).not.toHaveClass(/ring-edge-broken/);

  // The key image is a real 32-byte point, rendered in the page's short form.
  expect(await text(grid(page, 1).locator('.hex-value'))).toMatch(KEY_IMAGE);
});

test('every ring-size counter agrees with every other, at three sizes', async ({ page }) => {
  for (const size of [2, 5, 11]) {
    await setRingSize(page, size);
    await signAndWait(page);

    // One node, one edge, one response and one signer option per member; the
    // chain has one more entry than the ring because it starts AND ends at c0.
    await expect(page.locator('.ring-node')).toHaveCount(size);
    await expect(page.locator('.ring-edge')).toHaveCount(size);
    await expect(page.locator('.response-chip')).toHaveCount(size);
    await expect(page.locator('#signer-select option')).toHaveCount(size);
    await expect(page.locator('#ex2-signer-b option')).toHaveCount(size);
    expect(await renderedChain(page)).toHaveLength(size + 1);

    // The slider's rendered value, its accessible value and the prose count all
    // state the same ring size.
    await expect(page.locator('.controls-row output').first()).toHaveText(String(size));
    await expect(page.locator('#ring-size')).toHaveAttribute('aria-valuenow', String(size));
    expect(await text(page.locator('.responses-head'))).toContain(
      `The ${size} responses the verifier sees`,
    );

    // Responses are labelled s0..s(n-1) in order, with no gaps.
    const chips = await responseChips(page);
    expect(chips.map((c) => c.label)).toEqual(
      Array.from({ length: size }, (_, i) => `s${i}`),
    );
  }
});

test('the verifier sees a valid signature that names no signer', async ({ page }) => {
  // The test chooses the signer, so it knows the answer the page must withhold.
  await page.locator('#signer-select').selectOption('3');
  await signAndWait(page);
  await expect(line(page, 1, 0)).toHaveText('Verification: valid ring signature');

  // Nothing in the verifier-visible output flags a member or a slot.
  expect(await markedNodeIndex(page)).toBe(-1);
  expect(await markedChipIndex(page)).toBe(-1);
  await expect(page.locator('.closed-tag')).toHaveCount(0);
  await expect(line(page, 1, 1)).toHaveText(
    'Signer clue to verifier: none (all members satisfy the challenge chain equation)',
  );

  // Every rendered response has the identical shape — same label form, same
  // truncation, no extra annotation on one of them. Structural indistinguish-
  // ability is the visual form of the anonymity claim.
  const chips = await responseChips(page);
  expect(chips).toHaveLength(5);
  for (const chip of chips) {
    expect(chip.label).toMatch(/^s\d+$/);
    expect(chip.value).toMatch(RESPONSE_VALUE);
    expect(chip.tagged).toBe(false);
  }

  // The signer's own id never appears in the readout the verifier is shown.
  const signerId = await page.locator('#signer-select option').nth(3).textContent();
  expect(await text(grid(page, 1))).not.toContain(signerId!.trim());

  // The wire object the grid is drawn from carries no signer field at all.
  const note = await text(page.locator('.responses-note'));
  const wireFields = /whose fields are exactly ([^—]+)—/.exec(note)![1].trim().split(', ');
  expect(wireFields).toEqual(['ring', 'c0Hex', 'responsesHex', 'keyImageHex', 'message']);
  expect(wireFields).not.toContain('signerIndex');

  // Now force the disclosure: the page did know, and it names the slot the test
  // chose — proving the anonymity above was withholding, not ignorance.
  await page.locator('#ex1-reveal-signer').click();
  expect(await markedChipIndex(page)).toBe(3);
  expect(await markedNodeIndex(page)).toBe(3);
  await expect(page.locator('.response-chip-closed')).toHaveCount(1);
  await expect(page.locator('.ring-node-signer')).toHaveCount(1);
  await expect(page.locator('.reveal-note')).toContainText('The secret closed s3');
});

test("the verifier's view withholds every disclosure, not just the ring highlight", async ({
  page,
}) => {
  await page.locator('#signer-select').selectOption('2');
  await signAndWait(page);
  await page.locator('#ex1-reveal-signer').click();
  expect(await markedChipIndex(page)).toBe(2);

  await page.locator('#ex1-view-verifier').click();
  await expect(page.locator('.view-switch-note')).toHaveText(
    'The signer highlight is hidden — this is exactly what a verifier can see.',
  );

  // Regression: the highlight was hidden but the response grid still carried the
  // "closed with secret" tag and the reveal note still read "The secret closed
  // s2", so the view that claims to be exactly a verifier's view named the
  // signer twice over.
  expect(await markedNodeIndex(page)).toBe(-1);
  expect(await markedChipIndex(page)).toBe(-1);
  await expect(page.locator('.closed-tag')).toHaveCount(0);
  await expect(page.locator('.reveal-note')).not.toContainText('s2');
  expect(await text(page.locator('.responses'))).not.toContain('closed with secret');

  // The control is visibly unavailable rather than silently dead, and it says why.
  await expect(page.locator('#ex1-reveal-signer')).toBeDisabled();
  await expect(page.locator('#ex1-reveal-signer')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('.reveal-note')).toContainText('A verifier holds no such control');

  // Switching back restores the privileged view without needing a re-sign.
  await page.locator('#ex1-view-you').click();
  await expect(page.locator('#ex1-reveal-signer')).toBeEnabled();
  expect(await markedChipIndex(page)).toBe(2);
  expect(await markedNodeIndex(page)).toBe(2);
});

test('the revealed slot follows the signature on screen, not the signer dropdown', async ({
  page,
}) => {
  await page.locator('#signer-select').selectOption('3');
  await signAndWait(page);
  await page.locator('#ex1-reveal-signer').click();
  expect(await markedNodeIndex(page)).toBe(3);

  // Regression: this used to repoint the ring highlight at M1 while the response
  // grid kept marking s3, so the page named two different signers at once.
  await page.locator('#signer-select').selectOption('0');
  const node = await markedNodeIndex(page);
  const chip = await markedChipIndex(page);
  expect(node).toBe(3);
  expect(chip).toBe(node);
  await expect(page.locator('.ring-node-signer')).toHaveCount(1);
  await expect(page.locator('.response-chip-closed')).toHaveCount(1);
  await expect(page.locator('.reveal-note')).toContainText('The secret closed s3');
});

test('flipping one response byte breaks the chain and the page names the cause', async ({
  page,
}) => {
  await signAndWait(page);
  const clean = await renderedChain(page);

  await page.locator('#ex1-tamper-response').click();
  await expect(page.locator('.tamper-result')).toBeVisible();

  const broken = await renderedChain(page);
  expect(broken).toHaveLength(clean.length);
  // The tamper hits s0, which is consumed on the FIRST hop: c0 is untouched and
  // every challenge derived after it moves, so the walk lands somewhere else.
  expect(broken[0]).toBe(clean[0]);
  expect(broken.slice(1).some((v, i) => v === clean[i + 1])).toBe(false);
  expect(broken[broken.length - 1]).not.toBe(broken[0]);

  // The failure state, derived from that same chain rather than assumed.
  await expect(page.locator('.chain-badge')).toHaveText(/chain broken: c.* ≠ c0/);
  await expect(page.locator('.chain-badge')).toHaveClass(/chain-badge-fail/);
  await expect(page.locator('.ring-edge-closing')).toHaveClass(/ring-edge-broken/);
  await expect(page.locator('.ring-edge-closing')).not.toHaveClass(/ring-edge-closed/);

  // ...and the cause is named on screen: which field was corrupted, that it was
  // rejected, and why the closing connector is now dashed.
  const result = await text(page.locator('.tamper-result'));
  expect(result).toContain('Flipped one byte of s0');
  expect(result).toContain('rejected');
  expect(result).not.toContain('unexpectedly valid');
  expect(result).toContain('no longer equals c0');
});

test('verifying against a modified message is rejected, and the page names the cause', async ({
  page,
}) => {
  await signAndWait(page);
  const clean = await renderedChain(page);

  await page.locator('#ex1-tamper-message').click();
  await expect(page.locator('.tamper-result')).toBeVisible();

  // The message is hashed into every challenge, so c0 (which is carried in the
  // signature) survives and everything recomputed from it moves.
  const broken = await renderedChain(page);
  expect(broken[0]).toBe(clean[0]);
  expect(broken.slice(1).some((v, i) => v === clean[i + 1])).toBe(false);
  expect(broken[broken.length - 1]).not.toBe(broken[0]);

  await expect(page.locator('.chain-badge')).toHaveText(/chain broken: c.* ≠ c0/);
  await expect(page.locator('.chain-badge')).toHaveClass(/chain-badge-fail/);
  await expect(page.locator('.ring-edge-closing')).toHaveClass(/ring-edge-broken/);

  const result = await text(page.locator('.tamper-result'));
  expect(result).toContain('Checked the signature against a changed message');
  expect(result).toContain('rejected');
  expect(result).not.toContain('unexpectedly valid');
  expect(result).toContain('the challenge is hashed over the message');
});

test('changing the ring retracts the verdict', async ({ page }) => {
  await signAndWait(page);
  await page.locator('#ex1-tamper-response').click();
  await expect(page.locator('.tamper-result')).toBeVisible();

  // A new ring means new public keys, so nothing computed over the old one may
  // survive on screen — verdict, badge, chain, responses and tamper readout.
  await setRingSize(page, 4);
  await expect(line(page, 1, 0)).toHaveText('Verification: no signature yet');
  await expect(page.locator('.chain-badge')).toHaveCount(0);
  await expect(page.locator('.chain-wrap .chain')).toHaveCount(0);
  await expect(page.locator('.response-chip')).toHaveCount(0);
  await expect(page.locator('.tamper-result')).toHaveCount(0);
  await expect(page.locator('#ex1-tamper-response')).toHaveCount(0);
  expect(await text(grid(page, 1))).toContain('Key image: not generated');
});

test('editing the message retracts the verdict', async ({ page }) => {
  await signAndWait(page);
  await page.locator('#ex1-reveal-signer').click();
  await expect(page.locator('.response-chip-closed')).toHaveCount(1);

  // Regression: a signature binds to its exact message, but editing the box used
  // to leave "valid ring signature", the closed-chain badge and the whole
  // recomputed chain standing over a message they were never computed from.
  await page.locator('#ex1-message').fill('a completely different spend proof');
  await expect(line(page, 1, 0)).toHaveText('Verification: no signature yet');
  await expect(page.locator('.chain-badge')).toHaveCount(0);
  await expect(page.locator('.chain-wrap .chain')).toHaveCount(0);
  await expect(page.locator('.response-chip')).toHaveCount(0);
  await expect(page.locator('.ring-node-signer')).toHaveCount(0);
  expect(await text(grid(page, 1))).toContain('Key image: not generated');

  // The control is not left dead: signing the new message works and closes.
  await signAndWait(page);
  const chain = await renderedChain(page);
  expect(chain[chain.length - 1]).toBe(chain[0]);
  await expect(line(page, 1, 0)).toHaveText('Verification: valid ring signature');
});

test('the ledger rejects the repeat key image and accepts distinct ones', async ({ page }) => {
  // Default: spend B is signed by the same member as spend A.
  await page.locator('#ex2-run').click();
  await expect(page.locator('.ledger-row')).toHaveCount(2);

  const images = await grid(page, 2).locator('.hex-value').allTextContents();
  expect(images).toHaveLength(2);
  for (const image of images) expect(image.trim()).toMatch(KEY_IMAGE);

  // The verdict is read off the two images the page displayed: same secret ⇒
  // same image ⇒ "reuse detected: yes" ⇒ the second submission is rejected.
  const sameImage = images[0].trim() === images[1].trim();
  expect(sameImage).toBe(true);
  expect(await text(line(page, 2, 2))).toContain('yes — the two key images are equal');

  const rows = page.locator('.ledger-row');
  await expect(rows.nth(0)).toHaveClass(/ledger-ok/);
  await expect(rows.nth(0)).toContainText('accepted (new key image)');
  await expect(rows.nth(1)).toHaveClass(/ledger-reject/);
  await expect(rows.nth(1)).toContainText('REJECTED double-spend (image already spent)');
  await expect(page.locator('.ledger-note')).toContainText('The rejected line proves');

  // Linkability without identification: the ledger names messages and images,
  // never a ring member. (README: "without ever revealing which ring member
  // signed".) The prover-side narration lives outside this block.
  const ledger = await text(page.locator('.ledger'));
  const memberIds = await page.locator('#signer-select option').allTextContents();
  for (const id of memberIds) expect(ledger).not.toContain(id.trim());

  // Clearing really clears: no rows, no images, and the control disables itself.
  await page.locator('#ex2-reset').click();
  await expect(page.locator('.ledger-row')).toHaveCount(0);
  await expect(page.locator('#ex2-reset')).toBeDisabled();
  expect(await text(grid(page, 2))).toContain('Key image A: pending');
  expect(await text(line(page, 2, 2))).toContain('run exhibit');

  // Two different signers ⇒ two different images ⇒ no reuse ⇒ both accepted.
  // This is the branch that proves the rejection above was a fact about the key
  // images rather than a foregone conclusion of the control flow.
  await page.locator('#ex2-signer-b').selectOption('4');
  await page.locator('#ex2-run').click();
  await expect(page.locator('.ledger-row')).toHaveCount(2);

  const distinct = await grid(page, 2).locator('.hex-value').allTextContents();
  expect(distinct[0].trim()).not.toBe(distinct[1].trim());
  expect(await text(line(page, 2, 2))).toContain('no — the two key images differ');
  await expect(page.locator('.ledger-reject')).toHaveCount(0);
  await expect(page.locator('.ledger-ok')).toHaveCount(2);
  await expect(page.locator('.ledger-note')).toContainText('Every submission was accepted');
});

test('the timing sweep charts exactly the samples it claims to have fitted', async ({ page }) => {
  await expect(page.locator('svg.scatter')).toHaveCount(0);
  await page.locator('#ex3-run').click();
  // Results stream in one ring size at a time; ten dots means the sweep is done.
  await expect(page.locator('.dot-sign')).toHaveCount(10, { timeout: 120_000 });
  await expect(page.locator('#ex3-run')).toBeEnabled();
  await expect(page.locator('svg.scatter')).toBeVisible();

  const verdict = await text(line(page, 3, 0));
  const samples = Number(/fit over (\d+) ring sizes/.exec(verdict)![1]);
  expect(samples).toBe(10); // ring sizes 2..11, one sample each

  // Every claimed sample is actually plotted, on both series.
  await expect(page.locator('.dot-sign')).toHaveCount(samples);
  await expect(page.locator('.dot-verify')).toHaveCount(samples);
  for (const series of ['sign', 'verify']) {
    const points = await page.locator(`.series-${series}`).getAttribute('points');
    expect(points!.trim().split(/\s+/)).toHaveLength(samples);
  }

  // X axis is labelled with real ring sizes spanning the sweep.
  const xTicks = await page.locator('text.axis-tick[y="188"]').allTextContents();
  expect(xTicks[0]).toBe('2');
  expect(xTicks[xTicks.length - 1]).toBe('11');

  // The prose verdict is read off the fit, not printed beside it: the page may
  // only say "close to linear" when both R² it just reported clear 0.9.
  const signFit = /sign ≈ ([\d.]+) ms per extra ring member \(R² = ([\d.]+)\)/.exec(verdict)!;
  const verifyFit = /verify ≈ ([\d.]+) ms per extra member \(R² = ([\d.]+)\)/.exec(verdict)!;
  const signR2 = Number(signFit[2]);
  const verifyR2 = Number(verifyFit[2]);
  const claimsLinear = verdict.includes('came out close to linear');
  // Skip the equivalence only if a rounded R² sits on the threshold itself,
  // where the printed value cannot decide which side the raw value fell on.
  if (Math.abs(signR2 - 0.9) > 0.001 && Math.abs(verifyR2 - 0.9) > 0.001) {
    expect(claimsLinear).toBe(signR2 >= 0.9 && verifyR2 >= 0.9);
  }
  if (!claimsLinear) expect(verdict).toContain('the linear fit is weak here');

  // The chart's accessible description reports the same fit as the prose, so a
  // screen-reader user and a sighted user are told the same numbers.
  const label = await page.locator('svg.scatter').getAttribute('aria-label');
  const labelFit = /R squared ([\d.]+), slope ([\d.]+) milliseconds/.exec(label!)!;
  expect(Math.abs(Number(labelFit[1]) - signR2)).toBeLessThanOrEqual(0.01);
  expect(Math.abs(Number(labelFit[2]) - Number(signFit[1]))).toBeLessThanOrEqual(0.01);
  expect(label).toContain(`ring size ${xTicks[0]} to ${xTicks[xTicks.length - 1]}`);
});

test('the group readout counts the signatures it was actually given, and only the manager names the signer', async ({
  page,
}) => {
  await expect(page.locator('#group-open')).toBeDisabled();
  await expect(line(page, 4, 0)).toHaveText('Verifier result: no signature yet');
  await expect(line(page, 4, 2)).toHaveText('Manager open result: not opened yet');

  const members = (await page.locator('#group-member option').allTextContents()).map((m) =>
    m.trim(),
  );
  expect(members.length).toBeGreaterThan(1);

  const linkage = async (): Promise<{ total: number; distinct: number; linked: number }> => {
    const raw = await text(line(page, 4, 1));
    const m = /session: (\d+) across (\d+) distinct signers?; (\d+) of them share/.exec(raw)!;
    return { total: Number(m[1]), distinct: Number(m[2]), linked: Number(m[3]) };
  };

  // One signature from the first member.
  await page.locator('#group-sign').click();
  await expect(line(page, 4, 0)).toHaveText(
    'Verifier result: valid group credential + member signature',
  );
  expect(await linkage()).toEqual({ total: 1, distinct: 1, linked: 1 });

  // A second from the same member: the verifier can group them with no manager.
  await page.locator('#group-sign').click();
  expect(await linkage()).toEqual({ total: 2, distinct: 1, linked: 2 });
  await expect(line(page, 4, 1)).toContainText(
    'credentialId, issuedPayload, managerSignatureHex, memberPublicJwk',
  );

  // A third from a different member: three signatures, two distinct signers,
  // and only one of them shares the pseudonym now on display.
  await page.locator('#group-member').selectOption('2');
  await page.locator('#group-sign').click();
  expect(await linkage()).toEqual({ total: 3, distinct: 2, linked: 1 });

  // Until the manager opens it, no member's name is anywhere in the readout.
  for (const member of members) expect(await text(grid(page, 4))).not.toContain(member);
  await expect(line(page, 4, 2)).toHaveText('Manager open result: not opened yet');

  // The manager's trapdoor names the member that actually signed — the property
  // the ring deliberately lacks.
  await page.locator('#group-open').click();
  await expect(line(page, 4, 2)).toHaveText(`Manager open result: ${members[2]}`);
});
