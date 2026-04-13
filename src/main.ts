import './style.css';
import {
  detectKeyImageReuse,
  generateRingMembers,
  reconstructChallengeChain,
  ringSignAndVerify,
  signLsag,
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
  ex2MessageA: string;
  ex2MessageB: string;
  ex2Result: {
    keyImageA: string;
    keyImageB: string;
    reused: boolean;
  } | null;
  ex3Perf: PerfSample | null;
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
  ex2MessageA: 'Spend output #a1',
  ex2MessageB: 'Spend output #a1 again',
  ex2Result: null,
  ex3Perf: null,
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
  await animateChallengeChain(chain);
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

const runExhibit3 = async (): Promise<void> => {
  state.ex3Busy = true;
  render();
  const message = `perf-${Date.now()}`;
  const members = await generateRingMembers(state.ringSize);
  const signerIndex = Math.min(state.signerIndex, members.length - 1);

  const signStart = performance.now();
  const signature = await signLsag(message, members, signerIndex);
  const signMs = performance.now() - signStart;

  const verifyStart = performance.now();
  await verifyLsag(message, signature);
  const verifyMs = performance.now() - verifyStart;

  state.ex3Perf = {
    ringSize: state.ringSize,
    signMs,
    verifyMs
  };
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
  const ex3 = state.ex3Perf;
  const group = state.group;
  const compareLine = isRingVsGroupSummary();

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
      </section>

      <section class="panel" aria-labelledby="ex3-title">
        <div class="panel-head">
          <h2 id="ex3-title">Exhibit 3 — Ring Size vs Privacy</h2>
          <span class="badge" aria-hidden="true">Anonymity set and performance</span>
        </div>
        <fieldset class="controls-row">
          <legend class="sr-only">Ring size performance controls</legend>
          <label for="ex3-size">Anonymity set size
            <input id="ex3-size" type="range" min="2" max="11" value="${state.ringSize}" aria-valuenow="${state.ringSize}" aria-valuemin="2" aria-valuemax="11" />
            <output>${state.ringSize}</output>
          </label>
          <button id="ex3-run" type="button" ${state.ex3Busy ? 'disabled aria-busy="true"' : ''}>${state.ex3Busy ? 'Measuring…' : 'Measure Real Timing'}</button>
        </fieldset>
        <div class="info-grid" aria-live="polite" role="status">
          <p><strong>Privacy intuition:</strong> larger ring means more plausible signers.</p>
          <p><strong>Timing sample:</strong> ${ex3 ? `sign ${ex3.signMs.toFixed(2)} ms · verify ${ex3.verifyMs.toFixed(2)} ms (ring ${ex3.ringSize})` : 'not measured yet'}</p>
          <p><strong>Monero ring size timeline:</strong> 4 → 7 → 11 → 16 mandatory minimum progression.</p>
          <p><strong>Tradeoff:</strong> more decoys improve ambiguity but increase computation and transaction size.</p>
        </div>
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

  const ex3Slider = document.querySelector<HTMLInputElement>('#ex3-size');
  ex3Slider?.addEventListener('input', async (event) => {
    const target = event.target as HTMLInputElement;
    await setupRing(Number.parseInt(target.value, 10));
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
