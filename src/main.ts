import './style.css';
import {
  detectKeyImageReuse,
  generateRingMembers,
  reconstructChallengeChain,
  ringSignAndVerify,
  signLsag,
  tamperLsagSignature,
  toVerifierView,
  verifyLsag,
  type LsagSignature,
  type RingKeyPair
} from './ring';
import {
  createGroupManager,
  groupSign,
  isRingVsGroupSummary,
  issueCredential,
  linkageFromWire,
  openGroupSignature,
  verifyGroupSignature,
  type GroupCredential,
  type GroupManager,
  type GroupSignature,
  type PseudonymLinkage
} from './group';

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing #app element');
}

type ThemeMode = 'dark' | 'light';

type PerfSample = {
  ringSize: number;
  signMs: number;
  verifyMs: number;
};

type TamperKind = 'response' | 'message';

type TamperResult = {
  kind: TamperKind;
  verified: boolean;
  // The chain the verifier actually recomputes from the tampered inputs.
  // Its last entry no longer equals c0, so the loop visibly fails to close.
  chain: string[];
};

type GroupState = {
  manager: GroupManager | null;
  credentials: GroupCredential[];
  selected: number;
  latestSignature: GroupSignature | null;
  verified: boolean;
  openedMember: string | null;
  history: GroupSignature[];
  linkage: PseudonymLinkage | null;
};

const state: {
  ringSize: number;
  members: RingKeyPair[];
  signerIndex: number;
  ex1Message: string;
  ex1Signature: LsagSignature | null;
  ex1Verified: boolean;
  ex1Chain: string[];
  ex1ActiveStep: number;
  ex1ChainWalked: boolean;
  ex1ChainClosed: boolean;
  ex1Tamper: TamperResult | null;
  ex1RevealSigner: boolean;
  ex1VerifierView: boolean;
  ex2MessageA: string;
  ex2MessageB: string;
  ex2SignerIndexB: number;
  ex2Result: {
    keyImageA: string;
    keyImageB: string;
    reused: boolean;
    signerA: number;
    signerB: number;
  } | null;
  ex2Ledger: { image: string; label: string; accepted: boolean }[];
  ex3Curve: PerfSample[];
  ex3Busy: boolean;
  group: GroupState;
  groupMessage: string;
  error: string | null;
} = {
  ringSize: 5,
  members: [],
  signerIndex: 1,
  ex1Message: 'Monero input spend proof',
  ex1Signature: null,
  ex1Verified: false,
  ex1Chain: [],
  ex1ActiveStep: -1,
  ex1ChainWalked: false,
  ex1ChainClosed: false,
  ex1Tamper: null,
  ex1RevealSigner: false,
  ex1VerifierView: false,
  ex2MessageA: 'Spend output #a1',
  ex2MessageB: 'Spend output #a1 again',
  ex2SignerIndexB: 1,
  ex2Result: null,
  ex2Ledger: [],
  ex3Curve: [],
  ex3Busy: false,
  group: {
    manager: null,
    credentials: [],
    selected: 0,
    latestSignature: null,
    verified: false,
    openedMember: null,
    history: [],
    linkage: null
  },
  groupMessage: 'Approve shielded settlement #42',
  error: null
};

const shortHex = (hex: string, left = 10, right = 8): string => {
  if (hex.length <= left + right + 3) {
    return hex;
  }
  return `${hex.slice(0, left)}...${hex.slice(-right)}`;
};

// Collapsible, keyboard-accessible mechanism explainer rendered under each exhibit.
const explainer = (summary: string, bodyHtml: string): string => `
  <details class="explainer">
    <summary>${summary}</summary>
    <div class="explainer-body">${bodyHtml}</div>
  </details>`;

const getTheme = (): ThemeMode =>
  document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';

const setTheme = (theme: ThemeMode): void => {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
};

const themeMeta = (theme: ThemeMode): { icon: string; label: string } =>
  theme === 'dark'
    ? { icon: '🌙', label: 'Switch to light mode' }
    : { icon: '☀️', label: 'Switch to dark mode' };

// Walk the challenge chain one edge at a time. ex1ActiveStep counts edges:
// step i lights the edge leaving node i (deriving c_{i+1} from c_i). After the
// last edge the walk lands back on node 0; ex1ChainClosed then controls whether
// the "chain closed: c_n == c0" connector/badge is drawn.
//
// ex1ChainClosed is DERIVED, never asserted: it is the actual equality
// c_n == c0 over the chain the verifier recomputed, AND-ed with the boolean
// verifyLsag() returned. If the LSAG arithmetic were wrong, the walk would
// finish and the badge would read "chain broken" — the animation cannot print
// a verdict the math did not produce.
const chainActuallyCloses = (chain: string[]): boolean =>
  chain.length > 1 && chain[chain.length - 1] === chain[0];

const animateChallengeChain = async (): Promise<void> => {
  const n = state.members.length;
  state.ex1ChainClosed = false;
  state.ex1ChainWalked = false;
  state.ex1ActiveStep = -1;
  render();
  for (let i = 0; i < n; i += 1) {
    state.ex1ActiveStep = i;
    render();
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  // The walk has returned to node 0. Snap the closing connector shut only if the
  // recomputed final challenge really equals c0 and verification really passed.
  state.ex1ChainWalked = true;
  state.ex1ChainClosed = chainActuallyCloses(state.ex1Chain) && state.ex1Verified;
  render();
  await new Promise((resolve) => setTimeout(resolve, 200));
};

// Everything in Exhibit 1 that is a claim ABOUT one particular signature: the
// verdict, the chain it was recomputed from, the closing badge, the tamper
// readout and the privileged reveal. A verdict is only true of the message and
// ring it was computed over, so whenever that subject changes the verdict has to
// be retracted rather than left standing over inputs it never saw.
const retractExhibit1Verdict = (): void => {
  state.ex1Signature = null;
  state.ex1Verified = false;
  state.ex1Chain = [];
  state.ex1ActiveStep = -1;
  state.ex1ChainWalked = false;
  state.ex1ChainClosed = false;
  state.ex1Tamper = null;
  state.ex1RevealSigner = false;
};

const setupRing = async (ringSize: number): Promise<void> => {
  state.ringSize = ringSize;
  state.members = await generateRingMembers(ringSize);
  state.signerIndex = Math.min(state.signerIndex, ringSize - 1);
  retractExhibit1Verdict();
  state.ex2Result = null;
};

const setupGroup = async (): Promise<void> => {
  const manager = await createGroupManager();
  const credentials: GroupCredential[] = [];
  credentials.push(await issueCredential(manager, 'Member Alpha'));
  credentials.push(await issueCredential(manager, 'Member Beta'));
  credentials.push(await issueCredential(manager, 'Member Gamma'));
  state.group = {
    manager,
    credentials,
    selected: 0,
    latestSignature: null,
    verified: false,
    openedMember: null,
    history: [],
    linkage: null
  };
};

const runExhibit1 = async (): Promise<void> => {
  const signature = await signLsag(state.ex1Message, state.members, state.signerIndex);
  const verified = await verifyLsag(state.ex1Message, signature);
  const chain = await reconstructChallengeChain(state.ex1Message, signature);
  state.ex1Signature = signature;
  state.ex1Verified = verified;
  state.ex1Chain = chain;
  state.ex1Tamper = null;
  state.ex1RevealSigner = false;
  await animateChallengeChain();
};

const safeVerify = async (message: string, signature: LsagSignature): Promise<boolean> => {
  try {
    return await verifyLsag(message, signature);
  } catch {
    // A corrupted point/scalar can throw during decoding — that is still a rejection.
    return false;
  }
};

const safeReconstruct = async (
  message: string,
  signature: LsagSignature
): Promise<string[]> => {
  try {
    return await reconstructChallengeChain(message, signature);
  } catch {
    return [];
  }
};

const runExhibit1Tamper = async (kind: TamperKind): Promise<void> => {
  if (!state.ex1Signature) {
    return;
  }
  let verified: boolean;
  let chain: string[];
  if (kind === 'message') {
    // Same signature, but the verifier checks a different message than was signed.
    const modified = `${state.ex1Message} (modified)`;
    verified = await safeVerify(modified, state.ex1Signature);
    // Reconstruct against the intact ring but the changed message: because the
    // challenge is hashed over the message, every c_i shifts and the loop misses c0.
    const rebound: LsagSignature = { ...state.ex1Signature, message: modified };
    chain = await safeReconstruct(modified, rebound);
  } else {
    // Flip one byte of a response so the challenge chain no longer closes at c0.
    const corrupted = tamperLsagSignature(state.ex1Signature, 'response');
    verified = await safeVerify(state.ex1Message, corrupted);
    chain = await safeReconstruct(state.ex1Message, corrupted);
  }
  state.ex1Tamper = { kind, verified, chain };
  // Show the walk in the ring, then derive closure from the tampered chain the
  // verifier actually recomputed — not from the assumption that tampering fails.
  state.ex1Chain = chain.length > 0 ? chain : state.ex1Chain;
  state.ex1ActiveStep = state.members.length - 1;
  state.ex1ChainWalked = true;
  state.ex1ChainClosed = chainActuallyCloses(chain) && verified;
};

// A ledger records every key image a "network node" has already accepted. A
// second spend with the same image is rejected as a double-spend — the payoff
// of linkability — while the ring still hides WHICH member produced it.
const ledgerSubmit = (image: string, label: string): boolean => {
  const alreadySpent = state.ex2Ledger.some((e) => e.image === image && e.accepted);
  const accepted = !alreadySpent;
  state.ex2Ledger.push({ image, label, accepted });
  return accepted;
};

const runExhibit2 = async (): Promise<void> => {
  // Spend B is signed by whoever the learner picked, which may or may not be
  // the signer of spend A. Both signings used to use state.signerIndex, so
  // detectKeyImageReuse could only ever return true and the "no reuse" branch
  // below was unreachable — the ledger's REJECTED line was a foregone
  // conclusion of control flow rather than a fact about the key images.
  const signerB = Math.min(state.ex2SignerIndexB, state.members.length - 1);
  const a = await signLsag(state.ex2MessageA, state.members, state.signerIndex);
  const b = await signLsag(state.ex2MessageB, state.members, signerB);
  const reuse = detectKeyImageReuse([a.keyImageHex, b.keyImageHex]);
  // Push both signings at the ledger in order; a repeated image is rejected.
  ledgerSubmit(a.keyImageHex, state.ex2MessageA);
  ledgerSubmit(b.keyImageHex, state.ex2MessageB);
  state.ex2Result = {
    keyImageA: a.keyImageHex,
    keyImageB: b.keyImageHex,
    reused: reuse.reused,
    signerA: state.signerIndex,
    signerB
  };
};

const resetLedger = (): void => {
  state.ex2Ledger = [];
  state.ex2Result = null;
};

const RING_SIZES = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
const PERF_ITERATIONS = 6;

// Sweep every ring size and average sign/verify over several runs so the
// privacy-vs-cost relationship shows up as a curve rather than one noisy dot.
const runExhibit3 = async (): Promise<void> => {
  state.ex3Busy = true;
  state.ex3Curve = [];
  render();

  const curve: PerfSample[] = [];
  for (const size of RING_SIZES) {
    const members = await generateRingMembers(size);
    let signTotal = 0;
    let verifyTotal = 0;
    for (let iter = 0; iter < PERF_ITERATIONS; iter += 1) {
      const message = `perf-${size}-${iter}`;
      const signerIndex = iter % size;

      const signStart = performance.now();
      const signature = await signLsag(message, members, signerIndex);
      signTotal += performance.now() - signStart;

      const verifyStart = performance.now();
      await verifyLsag(message, signature);
      verifyTotal += performance.now() - verifyStart;
    }
    curve.push({
      ringSize: size,
      signMs: signTotal / PERF_ITERATIONS,
      verifyMs: verifyTotal / PERF_ITERATIONS
    });
    // Stream partial results so the chart fills in as the sweep runs.
    state.ex3Curve = [...curve];
    render();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  state.ex3Curve = curve;
  state.ex3Busy = false;
};

const runExhibit4Sign = async (): Promise<void> => {
  if (!state.group.manager || state.group.credentials.length === 0) {
    return;
  }
  const credential = state.group.credentials[state.group.selected];
  const signature = await groupSign(state.groupMessage, credential);
  const verified = await verifyGroupSignature(state.group.manager.managerPublicJwk, signature);
  state.group.latestSignature = signature;
  state.group.verified = verified;
  state.group.openedMember = null;
  // Keep every signature a verifier has seen, so the readout can compute what a
  // verifier can correlate rather than assert that it can correlate nothing.
  state.group.history.push(signature);
  state.group.linkage = linkageFromWire(signature, state.group.history);
};

const runExhibit4Open = (): void => {
  if (!state.group.manager || !state.group.latestSignature) {
    return;
  }
  state.group.openedMember = openGroupSignature(state.group.manager, state.group.latestSignature);
};

const RING_RADIUS = 39;

const ringNodePos = (idx: number, count: number): { x: number; y: number } => {
  const angle = (idx / count) * Math.PI * 2 - Math.PI / 2;
  return {
    x: 50 + RING_RADIUS * Math.cos(angle),
    y: 50 + RING_RADIUS * Math.sin(angle)
  };
};

// SVG layer of directed edges c_i → c_{i+1} that light as the walk proceeds and,
// when the loop returns, snaps a distinct "closing" edge from the last node back
// to node 0. On tamper the closing edge is drawn as a broken (dashed) connector.
const ringEdges = (): string => {
  const n = state.members.length;
  if (n < 2) {
    return '';
  }
  const walked = state.ex1ChainWalked;
  const walking = state.ex1ActiveStep >= 0;
  const segments: string[] = [];
  for (let i = 0; i < n; i += 1) {
    const from = ringNodePos(i, n);
    const to = ringNodePos((i + 1) % n, n);
    const isClosing = (i + 1) % n === 0; // edge that returns to node 0
    // An edge is "lit" once the walk has reached or passed its source node.
    const lit = walking && state.ex1ActiveStep >= i;
    // The closing edge is solid only when the recomputed c_n really equalled c0.
    const closed = isClosing && walked && state.ex1ChainClosed;
    const brokenClose = isClosing && walked && !state.ex1ChainClosed;
    const classes = [
      'ring-edge',
      isClosing ? 'ring-edge-closing' : '',
      lit ? 'ring-edge-lit' : '',
      closed ? 'ring-edge-closed' : '',
      brokenClose ? 'ring-edge-broken' : ''
    ]
      .filter(Boolean)
      .join(' ');
    segments.push(
      `<line class="${classes}" x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}" />`
    );
  }
  return `<svg class="ring-edges" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true" focusable="false">${segments.join('')}</svg>`;
};

// `privilegedSignerIndex` is the ONE place the signer may be named, and it is
// -1 unless the learner is in their own view AND has pressed the reveal. It is
// read off the signature currently on screen, never off the signer dropdown:
// changing the dropdown after signing used to move this highlight to a member
// who did not produce the displayed signature, while the response grid — which
// already keyed off the signature — kept marking the real one. The page then
// named two different signers at once.
const ringVisual = (privilegedSignerIndex: number): string =>
  state.members
    .map((member, idx) => {
      const { x, y } = ringNodePos(idx, state.members.length);
      const active = state.ex1ActiveStep === idx || state.ex1ActiveStep === idx + 1;
      const isSigner = idx === privilegedSignerIndex;
      const classes = [
        'ring-node',
        isSigner ? 'ring-node-signer' : '',
        active ? 'ring-node-active' : '',
        idx === 0 ? 'ring-node-start' : ''
      ]
        .filter(Boolean)
        .join(' ');
      const signerLabel = isSigner ? ' (actual signer, revealed to you only)' : '';
      const startLabel = idx === 0 ? ', challenge start c0' : '';
      return `<div class="${classes}" style="left:${x}%;top:${y}%" title="${member.id}" role="img" aria-label="Ring member ${member.id}${signerLabel}${startLabel}${active ? ', challenge active' : ''}">
        <span aria-hidden="true">${member.id}</span>
      </div>`;
    })
    .join('');

// Ordinary least-squares fit of one series against ring size, plus the
// coefficient of determination. This is what lets the page SAY "cost grows
// roughly linearly" only when the numbers it just measured actually say so —
// the claim is read off the samples, not printed next to them.
const fitLinear = (
  samples: PerfSample[],
  series: 'sign' | 'verify'
): { slope: number; intercept: number; r2: number } | null => {
  if (samples.length < 3) {
    return null;
  }
  const xs = samples.map((s) => s.ringSize);
  const ys = samples.map((s) => (series === 'sign' ? s.signMs : s.verifyMs));
  const n = xs.length;
  const meanX = xs.reduce((a, b) => a + b, 0) / n;
  const meanY = ys.reduce((a, b) => a + b, 0) / n;
  let sxy = 0;
  let sxx = 0;
  let syy = 0;
  for (let i = 0; i < n; i += 1) {
    sxy += (xs[i] - meanX) * (ys[i] - meanY);
    sxx += (xs[i] - meanX) ** 2;
    syy += (ys[i] - meanY) ** 2;
  }
  if (sxx === 0 || syy === 0) {
    return null;
  }
  const slope = sxy / sxx;
  return { slope, intercept: meanY - slope * meanX, r2: (sxy * sxy) / (sxx * syy) };
};

// Describe the measured growth honestly. A timing sweep in a browser is noisy;
// if this run did not in fact come out close to linear, say that instead of
// asserting the textbook answer over the top of the user's own data.
const growthVerdict = (samples: PerfSample[]): string => {
  const sign = fitLinear(samples, 'sign');
  const verify = fitLinear(samples, 'verify');
  if (!sign || !verify) {
    return 'Run the full sweep to fit a growth curve to your own measurements.';
  }
  const fmt = (v: number): string => v.toFixed(v < 1 ? 3 : 2);
  const linear = sign.r2 >= 0.9 && verify.r2 >= 0.9;
  const lead = linear
    ? 'Your run came out close to linear, as O(n) predicts'
    : 'Your run is noisy — the linear fit is weak here, which is a timing artefact of the browser, not evidence against O(n)';
  return `<strong>Measured on your machine:</strong> ${lead}. Least-squares fit over ${samples.length} ring sizes: sign ≈ ${fmt(sign.slope)} ms per extra ring member (R² = ${sign.r2.toFixed(3)}), verify ≈ ${fmt(verify.slope)} ms per extra member (R² = ${verify.r2.toFixed(3)}).`;
};

// A real line/scatter plot: ring size on the x-axis, milliseconds on the y-axis,
// two overlaid series (sign, verify), plus a faint reference chord drawn between
// the first and last measured sign samples so O(n) growth is legible by eye.
const scatterPlot = (samples: PerfSample[]): string => {
  if (samples.length === 0) {
    return '';
  }
  // viewBox space; plot area inset for axis labels.
  const W = 320;
  const H = 200;
  const padL = 34;
  const padR = 8;
  const padT = 10;
  const padB = 26;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  const sizes = samples.map((s) => s.ringSize);
  const minX = Math.min(...sizes, 2);
  const maxX = Math.max(...sizes, 3);
  const maxY = Math.max(...samples.map((s) => Math.max(s.signMs, s.verifyMs))) * 1.1 || 1;

  const xOf = (ring: number): number =>
    padL + ((ring - minX) / (maxX - minX || 1)) * plotW;
  const yOf = (ms: number): number => padT + plotH - (ms / maxY) * plotH;

  const line = (series: 'sign' | 'verify'): string =>
    samples
      .map((s) => `${xOf(s.ringSize).toFixed(1)},${yOf(series === 'sign' ? s.signMs : s.verifyMs).toFixed(1)}`)
      .join(' ');

  const dots = (series: 'sign' | 'verify'): string =>
    samples
      .map((s) => {
        const cy = yOf(series === 'sign' ? s.signMs : s.verifyMs);
        return `<circle class="dot dot-${series}" cx="${xOf(s.ringSize).toFixed(1)}" cy="${cy.toFixed(1)}" r="2.6" />`;
      })
      .join('');

  // Linear reference: straight line from (minX, sign@minX) to (maxX, sign@maxX)
  // scaled so a purely O(n) cost would lie on it. Using the first and last sign
  // samples keeps it honest to the measured data rather than an invented slope.
  const first = samples[0];
  const last = samples[samples.length - 1];
  const refX1 = xOf(first.ringSize);
  const refY1 = yOf(first.signMs);
  const refX2 = xOf(last.ringSize);
  const refY2 = yOf(last.signMs);

  // Y gridlines / ticks.
  const yTicks = [0, 0.5, 1].map((f) => {
    const ms = maxY * f;
    const y = yOf(ms);
    return `<line class="grid" x1="${padL}" y1="${y.toFixed(1)}" x2="${W - padR}" y2="${y.toFixed(1)}" /><text class="axis-tick" x="${padL - 4}" y="${(y + 3).toFixed(1)}" text-anchor="end">${ms.toFixed(1)}</text>`;
  });
  const xTicks = samples
    .filter((_, i) => i % 2 === 0 || i === samples.length - 1)
    .map((s) => {
      const x = xOf(s.ringSize);
      return `<text class="axis-tick" x="${x.toFixed(1)}" y="${H - padB + 14}" text-anchor="middle">${s.ringSize}</text>`;
    });

  const fit = fitLinear(samples, 'sign');
  const shape = fit
    ? `The sign series fits a straight line with R squared ${fit.r2.toFixed(2)}, slope ${fit.slope.toFixed(3)} milliseconds per extra ring member.`
    : 'Not enough samples yet to fit a growth curve.';

  return `<svg class="scatter" viewBox="0 0 ${W} ${H}" role="img" aria-label="Line chart of average sign and verify time in milliseconds versus ring size ${minX} to ${maxX}. ${shape}">
    ${yTicks.join('')}
    <line class="axis" x1="${padL}" y1="${padT}" x2="${padL}" y2="${padT + plotH}" />
    <line class="axis" x1="${padL}" y1="${padT + plotH}" x2="${W - padR}" y2="${padT + plotH}" />
    ${xTicks.join('')}
    <text class="axis-title" x="${padL + plotW / 2}" y="${H - 2}" text-anchor="middle">ring size (anonymity set)</text>
    <text class="axis-title" x="10" y="${padT + plotH / 2}" text-anchor="middle" transform="rotate(-90 10 ${padT + plotH / 2})">ms</text>
    <line class="ref-line" x1="${refX1.toFixed(1)}" y1="${refY1.toFixed(1)}" x2="${refX2.toFixed(1)}" y2="${refY2.toFixed(1)}" />
    <polyline class="series series-verify" points="${line('verify')}" />
    <polyline class="series series-sign" points="${line('sign')}" />
    ${dots('verify')}
    ${dots('sign')}
  </svg>`;
};

const render = (): void => {
  const theme = getTheme();
  const toggle = themeMeta(theme);
  const latestSig = state.ex1Signature;
  // Everything the page claims a verifier can see is rendered from this, which
  // structurally lacks signerIndex. The privileged index is available only when
  // the learner presses "Reveal the closed slot".
  const wireView = latestSig ? toVerifierView(latestSig) : null;
  // The reveal is privileged information, so it is available only in YOUR view.
  // The verifier's view claims on screen to be "exactly what a verifier can
  // see"; it previously hid the ring highlight but left the response grid and
  // the reveal note naming the signer's slot, which broke that claim outright.
  // One flag now gates every disclosure, so the two cannot drift apart again.
  const privilegedRevealActive = state.ex1RevealSigner && !state.ex1VerifierView;
  const privilegedSignerIndex = latestSig && privilegedRevealActive ? latestSig.signerIndex : -1;
  const ex2 = state.ex2Result;
  const ex3Curve = state.ex3Curve;
  const group = state.group;
  const compareLine = isRingVsGroupSummary();

  const ex3ChartHtml = scatterPlot(ex3Curve);

  app.innerHTML = `
    <main class="shell" id="main-content" role="main">
      <header class="cl-hero">
        <div class="cl-hero-main">
          <h1 class="cl-hero-title">Ring Signatures</h1>
          <p class="cl-hero-sub">LSAG · key-image linkable · vs. group signatures</p>
          <p class="cl-hero-desc">Sign a message as one of several ring members and watch the verifier confirm the signature closes without learning which member signed — then reuse a key to expose the linkable key image and contrast it with an openable group signature.</p>
        </div>
        <aside class="cl-hero-why" aria-label="Why it matters">
          <span class="cl-hero-why-label">WHY IT MATTERS</span>
          <p class="cl-hero-why-text">Ring signatures give Monero-style spend privacy: membership is provable, the signer stays hidden. Key images stop double-spends without breaking anonymity, and group signatures show the opposite trade — anonymity a manager can revoke.</p>
        </aside>
        <button id="theme-toggle" class="theme-toggle" type="button" hidden aria-hidden="true" aria-label="${toggle.label}" title="${toggle.label}">${toggle.icon}</button>
      </header>

      ${state.error ? `<section class="panel error" role="alert" aria-live="assertive">${state.error}</section>` : ''}

      <section class="panel preamble" aria-labelledby="preamble-title">
        <div class="panel-head">
          <h2 id="preamble-title">Start Here — The Words You'll Meet</h2>
          <span class="badge" aria-hidden="true">Plain language first</span>
        </div>
        <p class="preamble-lede">Picture a signed note passed hand to hand around a circle of suspects. Anyone can check the note is genuine, but no outsider can tell whose hand actually wrote it. That circle is the <em>ring</em>, and this lab builds it for real with Ed25519 curve math. Four words to carry with you:</p>
        <dl class="glossary">
          <div class="glossary-item">
            <dt>Ring</dt>
            <dd>The set of possible signers — the real one plus decoys. The signature proves <em>someone in the ring</em> signed, nothing narrower.</dd>
          </div>
          <div class="glossary-item">
            <dt>Decoy</dt>
            <dd>A ring member whose public key is borrowed for cover. They did nothing, but the math treats them as an equally plausible signer.</dd>
          </div>
          <div class="glossary-item">
            <dt>Challenge chain</dt>
            <dd>A loop of values <code>c0 → c1 → … → c0</code>. The signer rigs it so it comes full circle back to where it started; if it doesn't close, the signature is fake.</dd>
          </div>
          <div class="glossary-item">
            <dt>Key image</dt>
            <dd>A fingerprint <code>I = x·H(P)</code> tied to the secret key. It never names the signer, but the <em>same</em> signer always produces the <em>same</em> image — which is how double-spends get caught.</dd>
          </div>
        </dl>
        <p class="preamble-foot">A "<em>scalar</em>" below just means a number modulo the curve order — the raw material every response is made of. "<em>LSAG</em>" is the specific ring-signature recipe (Linkable Spontaneous Anonymous Group) this lab implements.</p>
      </section>

      <section class="panel" aria-labelledby="ex1-title">
        <div class="panel-head">
          <h2 id="ex1-title">Exhibit 1 — The Ring</h2>
          <span class="badge" aria-hidden="true">Verifier cannot identify signer</span>
        </div>
        <fieldset class="controls-row">
          <legend class="sr-only">Ring signature controls</legend>
          <label for="ring-size">Ring size
            <input id="ring-size" type="range" min="2" max="11" value="${state.ringSize}" aria-valuenow="${state.ringSize}" aria-valuemin="2" aria-valuemax="11" />
            <output>${state.ringSize}</output>
          </label>
          <label for="signer-select">Actual signer (hidden from verifier)
            <select id="signer-select">
              ${state.members.map((m, i) => `<option value="${i}" ${i === state.signerIndex ? 'selected' : ''}>${m.id}</option>`).join('')}
            </select>
          </label>
          <label for="ex1-message">Message
            <input id="ex1-message" type="text" value="${state.ex1Message}" />
          </label>
          <button id="ex1-run" type="button">Sign and Verify</button>
        </fieldset>
        <div class="view-switch" role="group" aria-label="Whose view of the ring to show">
          <span class="view-switch-label" id="view-switch-label">Whose view:</span>
          <button id="ex1-view-you" type="button" class="seg ${state.ex1VerifierView ? '' : 'seg-on'}" aria-pressed="${state.ex1VerifierView ? 'false' : 'true'}">Your view</button>
          <button id="ex1-view-verifier" type="button" class="seg ${state.ex1VerifierView ? 'seg-on' : ''}" aria-pressed="${state.ex1VerifierView ? 'true' : 'false'}">Verifier's view</button>
          <span class="view-switch-note">${state.ex1VerifierView ? 'The signer highlight is hidden — this is exactly what a verifier can see.' : 'The signer highlight is privileged information a verifier never has.'}</span>
        </div>
        <div class="ring-stage" role="group" aria-label="Visual ring showing ${state.members.length} members with the challenge chain walking edge by edge back to c0">
          <div class="ring-track"></div>
          ${ringEdges()}
          ${ringVisual(privilegedSignerIndex)}
          ${
            !state.ex1ChainWalked
              ? ''
              : state.ex1ChainClosed
                ? '<span class="chain-badge chain-badge-ok" role="status">chain closed: c<sub>n</sub> == c0 ✓</span>'
                : '<span class="chain-badge chain-badge-fail" role="status">chain broken: c<sub>n</sub> ≠ c0 ✗</span>'
          }
        </div>
        <div class="info-grid" aria-live="polite" role="status">
          <p><strong>Verification:</strong> ${
            latestSig
              ? state.ex1Verified
                ? '<span class="ok">valid ring signature</span>'
                : '<span class="danger">rejected — verifyLsag() returned false</span>'
              : '<span class="muted">no signature yet</span>'
          }</p>
          <p><strong>Signer clue to verifier:</strong> none (all members satisfy the challenge chain equation)</p>
          <p><strong>Challenge chain (walks the loop, must return to c0):</strong> <span class="chain-wrap">${
            state.ex1Chain.length > 0
              ? state.ex1Chain
                  .map((c, i) => {
                    const isLast = i === state.ex1Chain.length - 1;
                    const lit = state.ex1ActiveStep >= 0 && i <= state.ex1ActiveStep + 1;
                    const closeOk = isLast && state.ex1ChainWalked && state.ex1ChainClosed;
                    const closeFail = isLast && state.ex1ChainWalked && !state.ex1ChainClosed;
                    const cls = ['chain', lit ? 'active' : '', closeOk ? 'chain-close-ok' : '', closeFail ? 'chain-close-fail' : ''].filter(Boolean).join(' ');
                    // No `aria-label` here, and its absence is the fix rather
                    // than an omission. These are role-less <span>s, on which
                    // ARIA PROHIBITS aria-label: the attribute is silently
                    // discarded, so it never announced anything — and axe files
                    // that under `incomplete`, never `violations`, which is
                    // where the gate this replaces was not looking. It was also
                    // doing active harm on paper: an accessible name REPLACES
                    // an element's contents, so `aria-label="challenge 3"` over
                    // `c3=1a2b3c4…9f0e1` would have hidden the challenge value
                    // itself — the one thing this readout exists to show.
                    // The information the labels carried is restated as real
                    // text in one .sr-only SIBLING after the run (below), not
                    // per span: `.chain` is the element whose textContent IS the
                    // challenge value — `claims.spec.ts` parses it and compares
                    // c_n against c0 — so anything appended inside it would be
                    // read as part of the hex.
                    void isLast;
                    return `<span class="${cls}">c${i === state.ex1Chain.length - 1 ? 'ₙ' : i}=${shortHex(c, 7, 5)}</span>`;
                  })
                  .join(' <span class="chain-arrow" aria-hidden="true">→</span> ') +
                '<span class="sr-only"> — the last value shown is c-n, the final challenge, which should equal c0.</span>'
              : 'run exhibit to animate'
          }</span></p>
          <p><strong>Key image:</strong> <code class="hex-value">${latestSig ? shortHex(latestSig.keyImageHex, 16, 14) : 'not generated'}</code></p>
        </div>

        ${
          latestSig
            ? `<div class="responses">
          <p class="responses-head"><strong>The ${wireView!.responsesHex.length} responses the verifier sees</strong> — one per ring member. <span class="challenge-q">Can you pick out which one was computed with the secret key?</span></p>
          <div class="response-grid" role="list" aria-label="Ring responses">
            ${wireView!.responsesHex
              .map((s, i) => {
                // `wireView` has no signerIndex to consult. The highlight is
                // available only through `privilegedSignerIndex`, which is -1
                // unless the learner presses the privileged reveal button.
                const marked = i === privilegedSignerIndex;
                const cls = ['response-chip', marked ? 'response-chip-closed' : ''].filter(Boolean).join(' ');
                const tag = marked ? ' <span class="closed-tag">closed with secret</span>' : '';
                return `<span class="${cls}" role="listitem"><span class="response-label">s${i}</span><code>${shortHex(s, 6, 6)}</code>${tag}</span>`;
              })
              .join('')}
          </div>
          <div class="reveal-row">
            <button id="ex1-reveal-signer" type="button" class="ghost" ${state.ex1VerifierView ? 'disabled' : ''} aria-pressed="${privilegedRevealActive ? 'true' : 'false'}">${privilegedRevealActive ? 'Hide the closed slot' : 'Reveal the closed slot'}</button>
            <span class="reveal-note" role="status" aria-live="polite">${
              state.ex1VerifierView
                ? 'A verifier holds no such control — that is the point. Switch back to "Your view" to use the privileged reveal.'
                : privilegedRevealActive
                  ? `The secret closed <strong>s${latestSig.signerIndex}</strong> — but now that the hint is off again, it is indistinguishable from the rest. Could you have found it without the hint?`
                  : 'Try first: guess before you peek. The response computed with the secret is a uniform scalar just like every decoy, so statistically there is nothing to find.'
            }</span>
          </div>
          <p class="responses-note">Every response is a uniform scalar. This grid is rendered from the verifier's copy of the signature, whose fields are exactly <code>${Object.keys(wireView!).join(', ')}</code> — the prover-only <code>signerIndex</code> is stripped by <code>toVerifierView()</code> before anything here is drawn, and <code>verifyLsag()</code> never reads it either. The real signer's response is statistically identical to the rest, which is precisely why membership is provable but the signer stays hidden.</p>
        </div>

        <div class="tamper">
          <p class="tamper-head"><strong>Try to break it</strong> — a valid signature must close the chain at c0 and bind to its exact message:</p>
          <div class="tamper-row">
            <button id="ex1-tamper-response" type="button" class="ghost">Flip one byte of a response</button>
            <button id="ex1-tamper-message" type="button" class="ghost">Verify against a modified message</button>
          </div>
          ${
            state.ex1Tamper
              ? `<p class="tamper-result" role="status" aria-live="polite">${
                  state.ex1Tamper.kind === 'response'
                    ? 'Flipped one byte of s0 → '
                    : 'Checked the signature against a changed message → '
                }${
                  state.ex1Tamper.verified
                    ? '<span class="danger">unexpectedly valid</span>'
                    : '<span class="ok">rejected</span>'
                }${
                  state.ex1Tamper.kind === 'response'
                    ? ' — watch the ring above: the walk still lights every edge, but the closing connector back to c0 is now dashed and red because the last challenge no longer equals c0.'
                    : ' — the challenge is hashed over the message, so any edit changes every challenge and the loop above lands on a different value that fails to close.'
                }</p>`
              : ''
          }
        </div>`
            : ''
        }

        ${explainer(
          'How the ring hides the signer',
          `<p>The signature is one starting challenge <code>c0</code> plus one response <code>s<sub>i</sub></code> per member. Verification walks the ring: from <code>c0</code> it recomputes the next challenge using each member's public key and response, and accepts only if the walk returns to <code>c0</code>.</p>
           <p>To sign, the real member fills <em>every other</em> slot with a random response and derives each challenge honestly around the loop. Then they use their secret key to compute the single response that makes the loop close back at <code>c0</code>. Because all responses are uniform scalars, the verifier cannot tell which slot was closed with a secret — so any member of the ring is an equally plausible signer.</p>
           <p>The <strong>key image</strong> is derived from the secret key and a hash of the public key. It is unique to the signer but reveals nothing about which ring member it belongs to — that is what makes Exhibit 2 possible.</p>
           <p><strong>What each challenge actually hashes.</strong> LSAG defines <code>c<sub>i+1</sub> = H(L, m, L<sub>i</sub>, R<sub>i</sub>)</code>, where <code>L</code> is the <em>list of ring public keys</em> — every member, in order. Hashing <code>L</code> is what binds a signature to the exact ring it was made for: change one decoy, or merely reorder the ring, and every challenge shifts and the loop no longer closes. Without it the signature would only assert "someone in <em>some</em> ring signed this", and the ring the verifier is looking at would not be the one the signer committed to. The Liu-Wei-Wong security proof relies on it.</p>`
        )}
      </section>

      <section class="panel" aria-labelledby="ex2-title">
        <div class="panel-head">
          <h2 id="ex2-title">Exhibit 2 — Linkability and Key Images</h2>
          <span class="badge" aria-hidden="true">Double-spend detection</span>
        </div>
        <fieldset class="controls-row">
          <legend class="sr-only">Key image linkability controls</legend>
          <label for="ex2-message-a">Message A
            <input id="ex2-message-a" type="text" value="${state.ex2MessageA}" />
          </label>
          <label for="ex2-message-b">Message B
            <input id="ex2-message-b" type="text" value="${state.ex2MessageB}" />
          </label>
          <label for="ex2-signer-b">Signer of spend B (spend A is signed by ${state.members[state.signerIndex]?.id ?? '—'})
            <select id="ex2-signer-b">
              ${state.members.map((m, i) => `<option value="${i}" ${i === Math.min(state.ex2SignerIndexB, state.members.length - 1) ? 'selected' : ''}>${m.id}${i === state.signerIndex ? ' (same signer)' : ''}</option>`).join('')}
            </select>
          </label>
          <button id="ex2-run" type="button">Submit Both Spends To The Ledger</button>
          <button id="ex2-reset" type="button" class="ghost" ${state.ex2Ledger.length > 0 ? '' : 'disabled'}>Clear ledger</button>
        </fieldset>
        <div class="info-grid" aria-live="polite" role="status">
          <p><strong>Key image A:</strong> <code class="hex-value">${ex2 ? shortHex(ex2.keyImageA, 16, 14) : 'pending'}</code></p>
          <p><strong>Key image B:</strong> <code class="hex-value">${ex2 ? shortHex(ex2.keyImageB, 16, 14) : 'pending'}</code></p>
          <p><strong>Reuse detected:</strong> ${
            ex2
              ? ex2.reused
                ? '<span class="danger" role="alert">yes — the two key images are equal, so one secret signed both</span>'
                : `<span class="ok">no — the two key images differ, so the ledger accepted both</span>`
              : 'run exhibit'
          }${
            ex2
              ? ` <span class="muted">(computed by comparing the images above; spend A signed by ${state.members[ex2.signerA]?.id ?? '?'}, spend B by ${state.members[ex2.signerB]?.id ?? '?'})</span>`
              : ''
          }</p>
          <p><strong>Monero context:</strong> key images allow network nodes to reject duplicate spends while preserving signer ambiguity.</p>
        </div>
        ${
          state.ex2Ledger.length > 0
            ? `<div class="ledger">
          <p class="ledger-head"><strong>Network ledger of spent key images</strong> — a node accepts each new image once and rejects any repeat:</p>
          <ol class="ledger-list" aria-label="Ledger of submitted spends in order">
            ${state.ex2Ledger
              .map((e, i) => {
                const statusText = e.accepted ? 'accepted (new key image)' : 'REJECTED double-spend (image already spent)';
                const cls = e.accepted ? 'ledger-ok' : 'ledger-reject';
                const icon = e.accepted ? '✓' : '✗';
                return `<li class="ledger-row ${cls}">
                  <span class="ledger-idx" aria-hidden="true">#${i + 1}</span>
                  <code class="ledger-image">${shortHex(e.image, 12, 10)}</code>
                  <span class="ledger-msg">${e.label}</span>
                  <span class="ledger-status"><span aria-hidden="true">${icon}</span> ${statusText}</span>
                </li>`;
              })
              .join('')}
          </ol>
          <p class="ledger-note">${
            state.ex2Ledger.some((e) => !e.accepted)
              ? `The rejected line proves the double-spend was caught — yet nothing in the ledger reveals <em>which</em> of the ${state.members.length} ring members signed. Linkability and anonymity hold at the same time.`
              : `Every submission was accepted: no two key images in this ledger are equal, so the node saw no double-spend. Point spend B at the same signer as spend A and resubmit to make the rejection happen.`
          }</p>
        </div>`
            : ''
        }
        ${explainer(
          'Why the same signer always produces the same key image',
          `<p>The key image is <code>I = x · H(P)</code>, where <code>x</code> is the signer's secret key and <code>H(P)</code> is a hash of their public key mapped to a curve point. It does not depend on the message, so signing two different messages with the same secret yields the <em>same</em> key image.</p>
           <p>A network can publish every spent key image and reject any repeat — catching a double-spend — without ever learning which ring member produced it. Linkability and anonymity coexist: linkable <em>across a signer's own signatures</em>, anonymous <em>within each ring</em>.</p>`
        )}
      </section>

      <section class="panel" aria-labelledby="ex3-title">
        <div class="panel-head">
          <h2 id="ex3-title">Exhibit 3 — Ring Size vs Privacy</h2>
          <span class="badge" aria-hidden="true">Anonymity set and performance</span>
        </div>
        <fieldset class="controls-row">
          <legend class="sr-only">Ring size performance controls</legend>
          <button id="ex3-run" type="button" ${state.ex3Busy ? 'disabled aria-busy="true"' : ''}>${state.ex3Busy ? 'Measuring…' : `Run timing sweep (ring 2–11, ×${PERF_ITERATIONS})`}</button>
        </fieldset>
        ${
          ex3Curve.length > 0
            ? `<figure class="curve">
                <div class="curve-legend" aria-hidden="true">
                  <span><span class="swatch swatch-sign"></span>sign</span>
                  <span><span class="swatch swatch-verify"></span>verify</span>
                  <span><span class="swatch swatch-ref"></span>linear reference</span>
                </div>
                ${ex3ChartHtml}
                <figcaption class="sr-only">Average sign and verify time in milliseconds plotted against ring size, with a least-squares linear fit reported below the chart.</figcaption>
              </figure>`
            : '<p class="muted curve-empty">Run the sweep to chart how signing and verification cost scale with the anonymity set.</p>'
        }
        <div class="info-grid" aria-live="polite" role="status">
          ${ex3Curve.length > 0 ? `<p>${growthVerdict(ex3Curve)}</p>` : ''}
          <p><strong>What the chart should show:</strong> cost grows linearly with ring size — each extra decoy adds one more set of curve operations to both signing and verifying. The fit above is measured, not assumed.</p>
          <p><strong>The tradeoff:</strong> a larger ring means more plausible signers (better anonymity) but more computation and a larger signature.</p>
          <p><strong>Monero ring size timeline:</strong> the mandatory minimum rose <strong>3</strong> (Mar 2016) → <strong>5</strong> (Sep 2017) → <strong>7</strong> (Apr 2018) → <strong>11</strong>, now fixed rather than a floor (Oct 2018) → <strong>16</strong> (Aug 2022), trading cost for stronger privacy. Older write-ups say "4" for the 2017 step; that was the minimum <em>mixin</em> (decoys), and ring size = mixin + 1, so the ring size was 5. Monero never mandated a ring size of 4.</p>
        </div>
        ${explainer(
          'Why bigger rings cost more',
          `<p>Both signing and verification do <code>O(n)</code> work: each of the <code>n</code> ring members contributes two scalar-multiplications and a hash to the challenge chain. Doubling the ring roughly doubles the time and the signature size (one response per member).</p>
           <p>Anonymity, meanwhile, grows only as the <em>set size</em> — a ring of 16 hides you among 16, not exponentially more. That diminishing return, against linear cost, is exactly why real systems pick a fixed, modest ring size rather than "as large as possible".</p>`
        )}
      </section>

      <section class="panel" aria-labelledby="ex4-title">
        <div class="panel-head">
          <h2 id="ex4-title">Exhibit 4 — Group Signatures</h2>
          <span class="badge" aria-hidden="true">Accountable anonymity</span>
        </div>
        <fieldset class="controls-row">
          <legend class="sr-only">Group signature controls</legend>
          <label for="group-member">Member credential
            <select id="group-member">
              ${group.credentials.map((c, i) => `<option value="${i}" ${i === group.selected ? 'selected' : ''}>${c.memberId}</option>`).join('')}
            </select>
          </label>
          <label for="group-message">Message
            <input id="group-message" type="text" value="${state.groupMessage}" />
          </label>
          <button id="group-sign" type="button">Anonymous Group Sign</button>
          <button id="group-open" type="button" ${group.latestSignature ? '' : 'disabled'} aria-describedby="open-desc">Manager Open Signature</button>
          <span id="open-desc" class="sr-only">Reveals which group member produced the signature</span>
        </fieldset>
        <div class="info-grid" aria-live="polite" role="status">
          <p><strong>Verifier result:</strong> ${group.verified ? '<span class="ok">valid group credential + member signature</span>' : '<span class="muted">no signature yet</span>'}</p>
          <p><strong>Signer identity to verifier:</strong> ${
            group.linkage
              ? `real-world name hidden — the registry that maps credentials to people is the manager's. But the signature is <strong>pseudonymous, not anonymous</strong>: it carries credential <code>${group.linkage.pseudonym}</code> and the member's public key in the clear. Signatures collected in this session: ${group.history.length} across ${group.linkage.distinctSigners} distinct signer${group.linkage.distinctSigners === 1 ? '' : 's'}; <strong>${group.linkage.linkedCount}</strong> of them share this pseudonym${
                  group.linkage.stableFields.length > 0
                    ? `, linked by the fields <code>${group.linkage.stableFields.join(', ')}</code>, which were byte-identical across every one of them`
                    : ''
                }. Any verifier can do that grouping; no manager needed.`
              : 'no signature yet'
          }</p>
          <p><strong>Manager open result:</strong> ${group.openedMember ?? 'not opened yet'}</p>
          <p><strong>Ring vs Group:</strong> ${compareLine}</p>
        </div>
        <p class="note caveat"><strong>Teaching honesty:</strong> this exhibit sends each member's P-256 public key in the clear inside every signature, so two signatures from the same member are trivially linkable and only the credential-to-identity mapping is hidden. A production scheme (e.g. BBS+ / randomizable credentials) hides the member key itself, making even repeat signatures unlinkable to everyone but the manager. Read this as a model of the <em>accountability</em> property, not of full unlinkability.</p>
        ${explainer(
          'How accountable anonymity is built',
          `<p>The manager issues a <strong>credential</strong>: an ECDSA signature over the member's public key. To sign a message, the member signs it with their own key and attaches that credential. A verifier checks two things — the manager's signature proves "a manager admitted this key", and the member's signature proves "the holder of that key approved this message" — without learning the member's real-world identity.</p>
           <p>The manager keeps a private registry mapping each credential to an identity, so <em>only</em> the manager can <strong>open</strong> a signature and name the signer. Compare with Exhibit 1: a ring signature has no manager and no opener — nobody holds a trapdoor that names the signer, whereas a group signature deliberately keeps an accountability backdoor.</p>
           <p class="note caveat"><strong>Careful with the word "unconditional".</strong> LSAG's signer ambiguity is <strong>computational</strong>, not information-theoretic: the proof reduces to the DDH assumption on the curve in the random-oracle model. An adversary with unbounded computing power, or a break in DDH on edwards25519, could identify the signer. Some ring signatures really are unconditional — the original Rivest-Shamir-Tauman construction is <em>unconditionally</em> signer-ambiguous. LSAG trades that away to buy linkability: the key image is a deterministic function of the signer's secret, so signer ambiguity can only be computational. "No opener exists" and "anonymity holds against any adversary" are different claims; only the first is true here.</p>`
        )}
      </section>

      <section class="panel" aria-labelledby="ex5-title">
        <div class="panel-head">
          <h2 id="ex5-title">Exhibit 5 — Real World</h2>
          <span class="badge" aria-hidden="true">Monero, Zcash, Bitcoin</span>
        </div>
        <div class="cards-three">
          <article class="mini-card">
            <h3>Monero</h3>
            <p>Uses ring signatures, stealth addresses, and confidential transaction amounts to hide sender ambiguity and spending links.</p>
          </article>
          <article class="mini-card">
            <h3>Zcash</h3>
            <p>Uses zk-SNARK proofs to show transaction validity without revealing sender, receiver, or amount when shielded mode is used.</p>
          </article>
          <article class="mini-card">
            <h3>Bitcoin</h3>
            <p>No built-in sender anonymity set. Addresses and graph heuristics often expose ownership clusters and flow patterns.</p>
          </article>
        </div>
        <p class="note">Blockchain analysis resistance improves when cryptographic proofs remove or diffuse direct linkage signals between transactions.</p>

        <h3 class="reading-heading">Further reading</h3>
        <ul class="reading-list">
          <li><a href="https://people.csail.mit.edu/rivest/pubs/RST01.pdf" target="_blank" rel="noreferrer">Rivest, Shamir &amp; Tauman, "How to Leak a Secret" (ASIACRYPT 2001)</a> — the paper that introduced ring signatures; its construction is <em>unconditionally</em> signer-ambiguous.</li>
          <li><a href="https://eprint.iacr.org/2004/027" target="_blank" rel="noreferrer">Liu, Wei &amp; Wong, "Linkable Spontaneous Anonymous Group Signature for Ad Hoc Groups" (ACISP 2004, ePrint 2004/027)</a> — <strong>LSAG</strong>, the scheme this lab implements: the key image, the linkability property, and the signer-ambiguity proof under DDH in the random-oracle model.</li>
          <li><a href="https://eprint.iacr.org/2019/654" target="_blank" rel="noreferrer">Goodell, Noether &amp; Blue, "Concise Linkable Ring Signatures and Forgery Against Adversarial Keys" (ePrint 2019/654)</a> — <strong>CLSAG</strong>, the smaller successor Monero runs today.</li>
          <li><a href="https://www.getmonero.org/2017/09/13/september-15-2017-protocol-upgrade-hard-fork.html" target="_blank" rel="noreferrer">Monero, "A Scheduled Protocol Upgrade is Planned for September 15" (2017)</a> — the upgrade that set the minimum ring size to 5 (mixin 4), the step often misquoted as "ring size 4".</li>
        </ul>
      </section>
    </main>
  `;

  const themeToggleBtn = document.querySelector<HTMLButtonElement>('#theme-toggle');
  themeToggleBtn?.addEventListener('click', () => {
    setTheme(getTheme() === 'dark' ? 'light' : 'dark');
    render();
  });

  const ringSize = document.querySelector<HTMLInputElement>('#ring-size');
  ringSize?.addEventListener('input', async (event) => {
    const target = event.target as HTMLInputElement;
    await setupRing(Number.parseInt(target.value, 10));
    render();
  });

  const signerSelect = document.querySelector<HTMLSelectElement>('#signer-select');
  signerSelect?.addEventListener('change', (event) => {
    const target = event.target as HTMLSelectElement;
    state.signerIndex = Number.parseInt(target.value, 10);
    render();
  });

  document.querySelector<HTMLButtonElement>('#ex1-view-you')?.addEventListener('click', () => {
    state.ex1VerifierView = false;
    render();
  });
  document.querySelector<HTMLButtonElement>('#ex1-view-verifier')?.addEventListener('click', () => {
    state.ex1VerifierView = true;
    render();
  });

  document.querySelector<HTMLButtonElement>('#ex1-reveal-signer')?.addEventListener('click', () => {
    state.ex1RevealSigner = !state.ex1RevealSigner;
    render();
  });

  const ex1Message = document.querySelector<HTMLInputElement>('#ex1-message');
  ex1Message?.addEventListener('input', (event) => {
    const target = event.target as HTMLInputElement;
    state.ex1Message = target.value;
    // A signature binds to its exact message, so a verdict about the OLD message
    // says nothing about the one now in the box. Editing used to leave "valid
    // ring signature", the closed-chain badge and the whole recomputed chain
    // standing over a message they were never computed from — and the tamper
    // buttons would then reject on the message-binding check while claiming the
    // chain had failed to close. Retract instead.
    if (state.ex1Signature && state.ex1Signature.message !== target.value) {
      retractExhibit1Verdict();
      // render() replaces #app wholesale, so hand typing back to the user: this
      // fires at most once per signature (the state is null afterwards).
      const caret = target.selectionStart;
      render();
      const reborn = document.querySelector<HTMLInputElement>('#ex1-message');
      if (reborn) {
        reborn.focus();
        if (caret !== null) {
          reborn.setSelectionRange(caret, caret);
        }
      }
    }
  });

  const ex1Run = document.querySelector<HTMLButtonElement>('#ex1-run');
  ex1Run?.addEventListener('click', async () => {
    try {
      state.error = null;
      await runExhibit1();
      render();
    } catch (error) {
      state.error = error instanceof Error ? error.message : String(error);
      render();
    }
  });

  const wireTamper = (selector: string, kind: TamperKind): void => {
    document.querySelector<HTMLButtonElement>(selector)?.addEventListener('click', async () => {
      try {
        state.error = null;
        await runExhibit1Tamper(kind);
        render();
      } catch (error) {
        state.error = error instanceof Error ? error.message : String(error);
        render();
      }
    });
  };
  wireTamper('#ex1-tamper-response', 'response');
  wireTamper('#ex1-tamper-message', 'message');

  const ex2MessageA = document.querySelector<HTMLInputElement>('#ex2-message-a');
  ex2MessageA?.addEventListener('input', (event) => {
    const target = event.target as HTMLInputElement;
    state.ex2MessageA = target.value;
  });

  const ex2MessageB = document.querySelector<HTMLInputElement>('#ex2-message-b');
  ex2MessageB?.addEventListener('input', (event) => {
    const target = event.target as HTMLInputElement;
    state.ex2MessageB = target.value;
  });

  const ex2SignerB = document.querySelector<HTMLSelectElement>('#ex2-signer-b');
  ex2SignerB?.addEventListener('change', (event) => {
    const target = event.target as HTMLSelectElement;
    state.ex2SignerIndexB = Number.parseInt(target.value, 10);
  });

  const ex2Run = document.querySelector<HTMLButtonElement>('#ex2-run');
  ex2Run?.addEventListener('click', async () => {
    try {
      state.error = null;
      await runExhibit2();
      render();
    } catch (error) {
      state.error = error instanceof Error ? error.message : String(error);
      render();
    }
  });

  document.querySelector<HTMLButtonElement>('#ex2-reset')?.addEventListener('click', () => {
    resetLedger();
    render();
  });

  const ex3Run = document.querySelector<HTMLButtonElement>('#ex3-run');
  ex3Run?.addEventListener('click', async () => {
    try {
      state.error = null;
      await runExhibit3();
      render();
    } catch (error) {
      state.ex3Busy = false;
      state.error = error instanceof Error ? error.message : String(error);
      render();
    }
  });

  const groupMember = document.querySelector<HTMLSelectElement>('#group-member');
  groupMember?.addEventListener('change', (event) => {
    const target = event.target as HTMLSelectElement;
    state.group.selected = Number.parseInt(target.value, 10);
  });

  const groupMessage = document.querySelector<HTMLInputElement>('#group-message');
  groupMessage?.addEventListener('input', (event) => {
    const target = event.target as HTMLInputElement;
    state.groupMessage = target.value;
  });

  const groupSignBtn = document.querySelector<HTMLButtonElement>('#group-sign');
  groupSignBtn?.addEventListener('click', async () => {
    try {
      state.error = null;
      await runExhibit4Sign();
      render();
    } catch (error) {
      state.error = error instanceof Error ? error.message : String(error);
      render();
    }
  });

  const groupOpenBtn = document.querySelector<HTMLButtonElement>('#group-open');
  groupOpenBtn?.addEventListener('click', () => {
    runExhibit4Open();
    render();
  });
};

const init = async (): Promise<void> => {
  try {
    await setupRing(state.ringSize);
    await setupGroup();
    const sanity = await ringSignAndVerify('sanity-check', state.members, state.signerIndex);
    if (!sanity.verified) {
      throw new Error('Ring signature engine failed sanity verification');
    }
    render();
  } catch (error) {
    state.error = error instanceof Error ? error.message : String(error);
    render();
  }
};

init();
