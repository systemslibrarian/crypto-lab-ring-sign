import './style.css';
import {
  detectKeyImageReuse,
  generateRingMembers,
  reconstructChallengeChain,
  ringSignAndVerify,
  signLsag,
  tamperLsagSignature,
  verifyLsag,
  type LsagSignature,
  type RingKeyPair
} from './ring';
import {
  createGroupManager,
  groupSign,
  isRingVsGroupSummary,
  issueCredential,
  openGroupSignature,
  verifyGroupSignature,
  type GroupCredential,
  type GroupManager,
  type GroupSignature
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
};

type GroupState = {
  manager: GroupManager | null;
  credentials: GroupCredential[];
  selected: number;
  latestSignature: GroupSignature | null;
  verified: boolean;
  openedMember: string | null;
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
  ex1Tamper: TamperResult | null;
  ex2MessageA: string;
  ex2MessageB: string;
  ex2Result: {
    keyImageA: string;
    keyImageB: string;
    reused: boolean;
  } | null;
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
  ex1Tamper: null,
  ex2MessageA: 'Spend output #a1',
  ex2MessageB: 'Spend output #a1 again',
  ex2Result: null,
  ex3Curve: [],
  ex3Busy: false,
  group: {
    manager: null,
    credentials: [],
    selected: 0,
    latestSignature: null,
    verified: false,
    openedMember: null
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

const animateChallengeChain = async (chain: string[]): Promise<void> => {
  state.ex1ActiveStep = 0;
  render();
  for (let i = 0; i < chain.length; i += 1) {
    state.ex1ActiveStep = i;
    render();
    await new Promise((resolve) => setTimeout(resolve, 280));
  }
};

const setupRing = async (ringSize: number): Promise<void> => {
  state.ringSize = ringSize;
  state.members = await generateRingMembers(ringSize);
  state.signerIndex = Math.min(state.signerIndex, ringSize - 1);
  state.ex1Signature = null;
  state.ex1Verified = false;
  state.ex1Chain = [];
  state.ex1ActiveStep = -1;
  state.ex1Tamper = null;
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
    openedMember: null
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
  await animateChallengeChain(chain);
};

const safeVerify = async (message: string, signature: LsagSignature): Promise<boolean> => {
  try {
    return await verifyLsag(message, signature);
  } catch {
    // A corrupted point/scalar can throw during decoding — that is still a rejection.
    return false;
  }
};

const runExhibit1Tamper = async (kind: TamperKind): Promise<void> => {
  if (!state.ex1Signature) {
    return;
  }
  let verified: boolean;
  if (kind === 'message') {
    // Same signature, but the verifier checks a different message than was signed.
    verified = await safeVerify(`${state.ex1Message} (modified)`, state.ex1Signature);
  } else {
    // Flip one byte of a response so the challenge chain no longer closes at c0.
    const corrupted = tamperLsagSignature(state.ex1Signature, 'response');
    verified = await safeVerify(state.ex1Message, corrupted);
  }
  state.ex1Tamper = { kind, verified };
};

const runExhibit2 = async (): Promise<void> => {
  const a = await signLsag(state.ex2MessageA, state.members, state.signerIndex);
  const b = await signLsag(state.ex2MessageB, state.members, state.signerIndex);
  const reuse = detectKeyImageReuse([a.keyImageHex, b.keyImageHex]);
  state.ex2Result = {
    keyImageA: a.keyImageHex,
    keyImageB: b.keyImageHex,
    reused: reuse.reused
  };
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
};

const runExhibit4Open = (): void => {
  if (!state.group.manager || !state.group.latestSignature) {
    return;
  }
  state.group.openedMember = openGroupSignature(state.group.manager, state.group.latestSignature);
};

const ringVisual = (): string => {
  const radius = 39;
  return state.members
    .map((member, idx) => {
      const angle = (idx / state.members.length) * Math.PI * 2 - Math.PI / 2;
      const x = 50 + radius * Math.cos(angle);
      const y = 50 + radius * Math.sin(angle);
      const active = state.ex1ActiveStep === idx || state.ex1ActiveStep === idx + 1;
      const classes = [
        'ring-node',
        idx === state.signerIndex ? 'ring-node-signer' : '',
        active ? 'ring-node-active' : ''
      ].join(' ');
      return `<div class="${classes}" style="left:${x}%;top:${y}%" title="${member.id}" role="listitem" aria-label="${member.id}${idx === state.signerIndex ? ' (selected signer)' : ''}${active ? ', challenge active' : ''}">
        <span aria-hidden="true">${member.id}</span>
      </div>`;
    })
    .join('');
};

const render = (): void => {
  const theme = getTheme();
  const toggle = themeMeta(theme);
  const latestSig = state.ex1Signature;
  const ex2 = state.ex2Result;
  const ex3Curve = state.ex3Curve;
  const group = state.group;
  const compareLine = isRingVsGroupSummary();

  const maxMs = ex3Curve.reduce((m, s) => Math.max(m, s.signMs, s.verifyMs), 0) || 1;
  const ex3ChartHtml = ex3Curve
    .map((s) => {
      const signW = Math.max(3, (s.signMs / maxMs) * 100);
      const verifyW = Math.max(3, (s.verifyMs / maxMs) * 100);
      return `<div class="curve-row" role="listitem" aria-label="Ring size ${s.ringSize}: sign ${s.signMs.toFixed(2)} milliseconds, verify ${s.verifyMs.toFixed(2)} milliseconds">
        <span class="curve-size">ring ${s.ringSize}</span>
        <span class="curve-bars" aria-hidden="true">
          <span class="bar bar-sign" style="width:${signW}%"></span>
          <span class="bar bar-verify" style="width:${verifyW}%"></span>
        </span>
        <span class="curve-val" aria-hidden="true">${s.signMs.toFixed(1)} / ${s.verifyMs.toFixed(1)} ms</span>
      </div>`;
    })
    .join('');

  app.innerHTML = `
    <main class="shell" id="main-content" role="main">
      <header class="hero">
        <button id="theme-toggle" class="theme-toggle" type="button" aria-label="${toggle.label}" title="${toggle.label}">${toggle.icon}</button>
        <p class="eyebrow">systemslibrarian · crypto-lab</p>
        <h1>Ring Signatures and Group Signatures</h1>
        <p class="hero-text">Interactive cryptography lab showing how a verifier can confirm group membership without learning which specific member signed.</p>
        <div class="hero-chips">
          <span class="chip">Ed25519 LSAG</span>
          <span class="chip">P-256 Group Manager</span>
          <span class="chip">Monero Privacy Context</span>
        </div>
      </header>

      ${state.error ? `<section class="panel error" role="alert" aria-live="assertive">${state.error}</section>` : ''}

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
        <div class="ring-stage" role="list" aria-label="Visual ring showing ${state.members.length} members with challenge propagation">
          <div class="ring-track"></div>
          ${ringVisual()}
        </div>
        <div class="info-grid" aria-live="polite" role="status">
          <p><strong>Verification:</strong> ${state.ex1Verified ? '<span class="ok">valid ring signature</span>' : '<span class="muted">no signature yet</span>'}</p>
          <p><strong>Signer clue to verifier:</strong> none (all members satisfy the challenge chain equation)</p>
          <p><strong>Challenge chain:</strong> <span class="chain-wrap">${state.ex1Chain.length > 0 ? state.ex1Chain.map((c, i) => `<span class="chain ${state.ex1ActiveStep === i ? 'active' : ''}" aria-label="challenge ${i}">c${i}=${shortHex(c, 7, 5)}</span>`).join(' ') : 'run exhibit to animate'}</span></p>
          <p><strong>Key image:</strong> <code class="hex-value">${latestSig ? shortHex(latestSig.keyImageHex, 16, 14) : 'not generated'}</code></p>
        </div>

        ${
          latestSig
            ? `<div class="responses">
          <p class="responses-head"><strong>The ${latestSig.responsesHex.length} responses the verifier sees</strong> — one per ring member:</p>
          <div class="response-grid" role="list" aria-label="Ring responses">
            ${latestSig.responsesHex
              .map(
                (s, i) =>
                  `<span class="response-chip" role="listitem"><span class="response-label">s${i}</span><code>${shortHex(s, 6, 6)}</code></span>`
              )
              .join('')}
          </div>
          <p class="responses-note">Every response is a uniform scalar. You chose <strong>${state.members[state.signerIndex]?.id ?? '—'}</strong>, so the ring above highlights them — but the verifier only sees the data here, and the real signer's response is statistically identical to the rest.</p>
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
                    ? ' (the recomputed chain no longer returns to c0).'
                    : ' (the challenge is hashed over the message, so any edit changes every challenge).'
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
           <p>The <strong>key image</strong> is derived from the secret key and a hash of the public key. It is unique to the signer but reveals nothing about which ring member it belongs to — that is what makes Exhibit 2 possible.</p>`
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
          <button id="ex2-run" type="button">Sign Both With Same Member</button>
        </fieldset>
        <div class="info-grid" aria-live="polite" role="status">
          <p><strong>Key image A:</strong> <code class="hex-value">${ex2 ? shortHex(ex2.keyImageA, 16, 14) : 'pending'}</code></p>
          <p><strong>Key image B:</strong> <code class="hex-value">${ex2 ? shortHex(ex2.keyImageB, 16, 14) : 'pending'}</code></p>
          <p><strong>Reuse detected:</strong> ${ex2 ? (ex2.reused ? '<span class="danger" role="alert">yes — same signer secret reused</span>' : '<span class="ok">no</span>') : 'run exhibit'}</p>
          <p><strong>Monero context:</strong> key images allow network nodes to reject duplicate spends while preserving signer ambiguity.</p>
        </div>
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
            ? `<div class="curve" role="list" aria-label="Average sign and verify time by ring size">
                <div class="curve-legend" aria-hidden="true">
                  <span><span class="swatch swatch-sign"></span>sign</span>
                  <span><span class="swatch swatch-verify"></span>verify</span>
                </div>
                ${ex3ChartHtml}
              </div>`
            : '<p class="muted curve-empty">Run the sweep to chart how signing and verification cost scale with the anonymity set.</p>'
        }
        <div class="info-grid" aria-live="polite" role="status">
          <p><strong>What the chart shows:</strong> cost grows roughly linearly with ring size — each extra decoy adds one more set of curve operations to both signing and verifying.</p>
          <p><strong>The tradeoff:</strong> a larger ring means more plausible signers (better anonymity) but more computation and a larger signature.</p>
          <p><strong>Monero ring size timeline:</strong> the mandatory minimum rose 4 → 7 → 11 → 16 over time, trading cost for stronger privacy.</p>
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
          <p><strong>Signer identity to verifier:</strong> hidden (only sees manager-issued credential proof)</p>
          <p><strong>Manager open result:</strong> ${group.openedMember ?? 'not opened yet'}</p>
          <p><strong>Ring vs Group:</strong> ${compareLine}</p>
        </div>
        <p class="note caveat"><strong>Teaching honesty:</strong> this exhibit sends each member's P-256 public key in the clear inside every signature, so two signatures from the same member are trivially linkable and only the credential-to-identity mapping is hidden. A production scheme (e.g. BBS+ / randomizable credentials) hides the member key itself, making even repeat signatures unlinkable to everyone but the manager. Read this as a model of the <em>accountability</em> property, not of full unlinkability.</p>
        ${explainer(
          'How accountable anonymity is built',
          `<p>The manager issues a <strong>credential</strong>: an ECDSA signature over the member's public key. To sign a message, the member signs it with their own key and attaches that credential. A verifier checks two things — the manager's signature proves "a manager admitted this key", and the member's signature proves "the holder of that key approved this message" — without learning the member's real-world identity.</p>
           <p>The manager keeps a private registry mapping each credential to an identity, so <em>only</em> the manager can <strong>open</strong> a signature and name the signer. Compare with Exhibit 1: a ring signature has no manager and no opener — anonymity there is unconditional, whereas a group signature deliberately keeps an accountability backdoor.</p>`
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

  const ex1Message = document.querySelector<HTMLInputElement>('#ex1-message');
  ex1Message?.addEventListener('input', (event) => {
    const target = event.target as HTMLInputElement;
    state.ex1Message = target.value;
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
