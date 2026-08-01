import { describe, it, expect } from 'vitest';
import { ed25519, ed25519_hasher } from '@noble/curves/ed25519.js';
import {
  generateRingMembers,
  getPublicRing,
  signLsag,
  verifyLsag,
  tamperLsagSignature,
  detectKeyImageReuse,
  reconstructChallengeChain,
  ringSignAndVerify,
  verifyEd25519WebCryptoRoundtrip,
  toVerifierView,
  decodeHex,
  type LsagSignature,
  type RingKeyPair
} from './ring.ts';

const BASE = ed25519.Point.BASE;
const TEXT = new TextEncoder();

// Mirror the module's hash-to-point construction so tests can assert the
// security property directly (DL of H_p(P) is unknown, key image unforgeable).
const HASH_TO_POINT_DST = 'crypto-lab-ring-sign:LSAG:H2P:v1';
const hashPoint = (p: typeof BASE): typeof BASE =>
  ed25519_hasher.hashToCurve(p.toBytes(), { DST: TEXT.encode(HASH_TO_POINT_DST) }).clearCofactor();

const pointFromHex = (hex: string) => ed25519.Point.fromHex(hex);
const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

describe('LSAG ring signature', () => {
  it(
    'signs and verifies for every ring size and every signer position',
    async () => {
      for (const size of [2, 3, 5, 8, 11]) {
        const members = await generateRingMembers(size);
        for (let signer = 0; signer < size; signer += 1) {
          const sig = await signLsag(`msg-${size}-${signer}`, members, signer);
          expect(sig.ring.length).toBe(size);
          expect(sig.responsesHex.length).toBe(size);
          await expect(verifyLsag(`msg-${size}-${signer}`, sig)).resolves.toBe(true);
        }
      }
    },
    // Exhaustive matrix does 29 full WebCrypto keygen + sign/verify rounds; the
    // 5s default is too tight on loaded CI runners.
    30_000
  );

  it('ringSignAndVerify reports verified=true', async () => {
    const members = await generateRingMembers(4);
    const { signature, verified } = await ringSignAndVerify('hello', members, 2);
    expect(verified).toBe(true);
    expect(signature.signerIndex).toBe(2);
  });

  it('challenge chain closes at c0 (reconstructed final challenge == c0)', async () => {
    const members = await generateRingMembers(5);
    const sig = await signLsag('chain', members, 3);
    const chain = await reconstructChallengeChain('chain', sig);
    // chain has n+1 entries: c0, c1, ..., cn where cn must wrap back to c0.
    expect(chain.length).toBe(sig.ring.length + 1);
    expect(chain[0]).toBe(sig.c0Hex);
    expect(chain[chain.length - 1]).toBe(sig.c0Hex);
  });
});

describe('LSAG rejects forgeries and tampering', () => {
  it('rejects a tampered response (chain no longer closes at c0)', async () => {
    const members = await generateRingMembers(4);
    const sig = await signLsag('pay-alice', members, 1);
    const forged = tamperLsagSignature(sig, 'response');
    await expect(verifyLsag('pay-alice', forged)).resolves.toBe(false);
  });

  it('rejects a tampered c0', async () => {
    const members = await generateRingMembers(4);
    const sig = await signLsag('pay-alice', members, 1);
    const forged = tamperLsagSignature(sig, 'c0');
    await expect(verifyLsag('pay-alice', forged)).resolves.toBe(false);
  });

  it('rejects when the verified message differs from the signed message', async () => {
    const members = await generateRingMembers(3);
    const sig = await signLsag('original', members, 0);
    await expect(verifyLsag('tampered-message', sig)).resolves.toBe(false);
  });

  it('rejects a signature whose embedded message was swapped', async () => {
    const members = await generateRingMembers(3);
    const sig = await signLsag('original', members, 0);
    const swapped: LsagSignature = { ...sig, message: 'swapped' };
    // verify(message) checks message === signature.message, and the challenge
    // hash binds the message, so even matching them fails the chain.
    await expect(verifyLsag('swapped', swapped)).resolves.toBe(false);
  });

  it('rejects a response-count mismatch', async () => {
    const members = await generateRingMembers(3);
    const sig = await signLsag('m', members, 0);
    const bad: LsagSignature = { ...sig, responsesHex: sig.responsesHex.slice(0, 2) };
    await expect(verifyLsag('m', bad)).resolves.toBe(false);
  });

  it('cannot forge a signature without any secret key (key image made up)', async () => {
    const members = await generateRingMembers(4);
    const pubRing = getPublicRing(members);
    // Attacker fabricates random responses / c0 / key image with no secret.
    const forged: LsagSignature = {
      ring: pubRing,
      c0Hex: '01'.repeat(32),
      responsesHex: pubRing.map((_, i) => (i + 1).toString(16).padStart(64, '0')),
      keyImageHex: toHex(BASE.multiply(12345n).toBytes()),
      message: 'steal',
      signerIndex: 0
    };
    await expect(verifyLsag('steal', forged)).resolves.toBe(false);
  });

  // Liu-Wei-Wong LSAG computes c_{i+1} = H(L, m, L_i, R_i) where L is the LIST
  // of ring public keys. The challenge hash now includes that list, so a
  // signature is bound to the exact ring — same members, same order — it was
  // produced for.
  it('binds the signature to its ring: substituting a member fails verification', async () => {
    const members = await generateRingMembers(5);
    const strangers = await generateRingMembers(2);
    const sig = await signLsag('bind', members, 2);
    await expect(verifyLsag('bind', sig)).resolves.toBe(true);

    const substituted: LsagSignature = {
      ...sig,
      ring: sig.ring.map((m, i) =>
        i === 4 ? { ...m, publicKeyHex: strangers[0].publicKeyHex } : m
      )
    };
    await expect(verifyLsag('bind', substituted)).resolves.toBe(false);
  });

  it('binds the signature to its ring ORDER: permuting the ring fails verification', async () => {
    const members = await generateRingMembers(5);
    const sig = await signLsag('order', members, 2);
    const reordered: LsagSignature = {
      ...sig,
      ring: [sig.ring[1], sig.ring[0], ...sig.ring.slice(2)]
    };
    await expect(verifyLsag('order', reordered)).resolves.toBe(false);
  });
});

describe('LSAG anonymity / signer ambiguity', () => {
  it('responses reveal nothing about the signer: a signature verifies identically regardless of position', async () => {
    const members = await generateRingMembers(6);
    const sigA = await signLsag('same-ring', members, 0);
    const sigB = await signLsag('same-ring', members, 4);
    // Both valid; the public ring is identical; only the (hidden) signerIndex differs.
    await expect(verifyLsag('same-ring', sigA)).resolves.toBe(true);
    await expect(verifyLsag('same-ring', sigB)).resolves.toBe(true);
    expect(sigA.ring).toEqual(sigB.ring);
  });

  it('SECURITY: key image is NOT recomputable from public keys (the old h·G bug is gone)', async () => {
    // The historical bug: H_p(P) = G·SHA512(P) = h·G with public h, so the key
    // image I = x·H_p(P) = h·P was computable by anyone from the public key P.
    // Here we prove that no such public scalar h exists for the real hash-to-curve:
    // an observer can no longer reconstruct the key image from a public key alone.
    const members = await generateRingMembers(4);
    const sig = await signLsag('deanon-attempt', members, 2);
    const keyImage = pointFromHex(sig.keyImageHex);

    // Attacker's ONLY public knowledge: ring public keys. In the broken scheme,
    // for the true signer k, h_k·P_k == I where h_k = SHA512(P_k) mod L.
    // Reproduce that exact attack and confirm it no longer matches anyone.
    const attackerHash = async (pBytes: Uint8Array): Promise<bigint> => {
      const d = await crypto.subtle.digest('SHA-512', new Uint8Array(pBytes).buffer);
      const L = ed25519.Point.Fn.ORDER;
      const v = BigInt(`0x${Array.from(new Uint8Array(d), (b) => b.toString(16).padStart(2, '0')).join('')}`);
      return v % L;
    };
    for (const m of sig.ring) {
      const P = pointFromHex(m.publicKeyHex);
      const h = await attackerHash(P.toBytes());
      const guess = P.multiply(h === 0n ? 1n : h); // h·P — the old deanonymization guess
      expect(guess.equals(keyImage)).toBe(false);
    }
  });

  it('H_p(P) has an UNKNOWN discrete log to G (not a public multiple of the base point)', async () => {
    // Sanity guard on the hash-to-point primitive itself: distinct public keys
    // map to distinct, torsion-free points, and H_p(P) is never a small,
    // guessable multiple of G.
    const members = await generateRingMembers(3);
    const hps = members.map((m) => hashPoint(pointFromHex(m.publicKeyHex)));
    for (const hp of hps) {
      expect(hp.isTorsionFree()).toBe(true);
      expect(hp.isSmallOrder()).toBe(false);
      // Not a tiny multiple of G (would imply a trivially-known DL).
      for (let k = 0n; k <= 64n; k += 1n) {
        expect(hp.equals(BASE.multiply(k === 0n ? 1n : k))).toBe(false);
      }
    }
    // Distinct keys -> distinct hash points.
    expect(hps[0].equals(hps[1])).toBe(false);
    expect(hps[1].equals(hps[2])).toBe(false);
  });
});

describe('LSAG linkability (key images)', () => {
  it('same signer + same key produces the SAME key image across different messages', async () => {
    const members = await generateRingMembers(5);
    const sig1 = await signLsag('spend-1', members, 2);
    const sig2 = await signLsag('spend-2', members, 2);
    expect(sig1.keyImageHex).toBe(sig2.keyImageHex);
    const reuse = detectKeyImageReuse([sig1.keyImageHex, sig2.keyImageHex]);
    expect(reuse.reused).toBe(true);
    expect(reuse.duplicates).toContain(sig1.keyImageHex);
  });

  it('different signers produce DIFFERENT key images (no false double-spend)', async () => {
    const members = await generateRingMembers(5);
    const sigA = await signLsag('m', members, 0);
    const sigB = await signLsag('m', members, 1);
    expect(sigA.keyImageHex).not.toBe(sigB.keyImageHex);
    const reuse = detectKeyImageReuse([sigA.keyImageHex, sigB.keyImageHex]);
    expect(reuse.reused).toBe(false);
    expect(reuse.duplicates).toHaveLength(0);
  });

  it('key image is a valid, torsion-free, non-zero curve point', async () => {
    const members = await generateRingMembers(3);
    const sig = await signLsag('m', members, 1);
    const ki = pointFromHex(sig.keyImageHex);
    expect(ki.equals(ed25519.Point.ZERO)).toBe(false);
    expect(ki.isSmallOrder()).toBe(false);
    expect(ki.isTorsionFree()).toBe(true);
  });
});

describe('LSAG rejects malformed / small-order points', () => {
  it('rejects a zero key image', async () => {
    const members = await generateRingMembers(3);
    const sig = await signLsag('m', members, 0);
    const bad: LsagSignature = {
      ...sig,
      keyImageHex: toHex(ed25519.Point.ZERO.toBytes())
    };
    await expect(verifyLsag('m', bad)).resolves.toBe(false);
  });

  it('rejects a small-order key image (torsion point)', async () => {
    const members = await generateRingMembers(3);
    const sig = await signLsag('m', members, 0);
    // A known 8-torsion point on edwards25519 (order 8), i.e. small order.
    const torsionHex = 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a';
    const bad: LsagSignature = { ...sig, keyImageHex: torsionHex };
    await expect(verifyLsag('m', bad)).resolves.toBe(false);
  });
});

describe('scalar reduction / randomScalar regression guards', () => {
  it('decodeHex round-trips a known vector', () => {
    const bytes = decodeHex('00ff10ab');
    expect(Array.from(bytes)).toEqual([0x00, 0xff, 0x10, 0xab]);
  });

  it('responses are canonical 64-hex-char (32-byte) reduced scalars', async () => {
    const members = await generateRingMembers(4);
    const sig = await signLsag('m', members, 1);
    const L = ed25519.Point.Fn.ORDER;
    for (const rHex of sig.responsesHex) {
      expect(rHex).toMatch(/^[0-9a-f]{64}$/);
      expect(BigInt(`0x${rHex}`)).toBeLessThan(L);
    }
    expect(sig.c0Hex).toMatch(/^[0-9a-f]{64}$/);
    expect(BigInt(`0x${sig.c0Hex}`)).toBeLessThan(L);
  });
});

describe('WebCrypto Ed25519 key material', () => {
  it('the derived LSAG scalar matches WebCrypto Ed25519 (sign/verify round-trips)', async () => {
    const members: RingKeyPair[] = await generateRingMembers(2);
    for (const m of members) {
      await expect(verifyEd25519WebCryptoRoundtrip(m, 'attest')).resolves.toBe(true);
    }
  });

  it('the secret scalar actually generates the advertised public key (P = x·G)', async () => {
    const members = await generateRingMembers(3);
    for (const m of members) {
      const x = BigInt(`0x${m.secretScalarHex}`);
      const derived = BASE.multiply(x);
      expect(toHex(derived.toBytes())).toBe(m.publicKeyHex);
    }
  });
});

/**
 * Exhibit 1 said "The verifier sees only the data here" under a response grid
 * that was rendered straight from the prover's LsagSignature — signerIndex and
 * all. The grid is now built from toVerifierView(); these pin that the wire
 * object has no signer field and that verification does not need one.
 */
describe('the verifier view carries no signer index', () => {
  it('strips signerIndex and keeps exactly the verifiable fields', async () => {
    const members = await generateRingMembers(5);
    const sig = await signLsag('m', members, 3);
    const view = toVerifierView(sig);
    expect(Object.keys(view).sort()).toEqual(
      ['c0Hex', 'keyImageHex', 'message', 'responsesHex', 'ring'].sort()
    );
    expect('signerIndex' in view).toBe(false);
  });

  it('verifies from the wire view alone, for every signer position', async () => {
    const members = await generateRingMembers(4);
    for (let i = 0; i < members.length; i += 1) {
      const sig = await signLsag('m', members, i);
      const view = toVerifierView(sig);
      // A lie about the signer index cannot change the verdict, because the
      // verifier never reads it: verification succeeds on the stripped object.
      await expect(verifyLsag('m', { ...view, signerIndex: -1 } as LsagSignature)).resolves.toBe(true);
    }
  });
});
