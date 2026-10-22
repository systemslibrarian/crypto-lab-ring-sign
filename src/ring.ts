import { ed25519, ed25519_hasher } from '@noble/curves/ed25519.js';

const CURVE_ORDER = ed25519.Point.Fn.ORDER;
const BASE = ed25519.Point.BASE;
const TEXT_ENCODER = new TextEncoder();

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

const hexToBytes = (hex: string): Uint8Array => {
  if (hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(hex)) {
    throw new Error('hex must be non-empty, even-length, and contain only hexadecimal digits');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

export type RingKeyPair = {
  id: string;
  publicJwk: JsonWebKey;
  privateJwk: JsonWebKey;
  publicKeyHex: string;
  secretScalarHex: string;
};

export type RingMemberPublic = {
  id: string;
  publicKeyHex: string;
};

export type LsagSignature = {
  ring: RingMemberPublic[];
  c0Hex: string;
  responsesHex: string[];
  keyImageHex: string;
  message: string;
  signerIndex: number;
};

/**
 * Exactly what goes on the wire. `LsagSignature` is the PROVER's object and
 * carries `signerIndex` so the demo can narrate what happened; a verifier never
 * receives that field, and `verifyLsag` never reads it. Anything the page claims
 * a verifier can see is rendered from this type, so the claim is enforced by the
 * shape of the data rather than asserted in prose beside a field that is there.
 */
export type VerifierView = Omit<LsagSignature, 'signerIndex'>;

/** Strip the prover-only field. The result is what a verifier is handed. */
export const toVerifierView = (signature: LsagSignature): VerifierView => {
  const { signerIndex: _proverOnly, ...wire } = signature;
  return wire;
};

const mod = (x: bigint): bigint => {
  const r = x % CURVE_ORDER;
  return r >= 0n ? r : r + CURVE_ORDER;
};

const multiplyPoint = (point: typeof BASE, scalar: bigint): typeof BASE =>
  scalar === 0n ? ed25519.Point.ZERO : point.multiply(scalar);

const scalarToHex = (x: bigint): string => x.toString(16).padStart(64, '0');

// Wire scalars have one canonical encoding: 32 lowercase hex bytes whose value
// is already below the group order. Reducing attacker-controlled input modulo L
// accepts many byte strings for the same signature and makes signatures
// malleable (for example c0 + L verified as c0).
const hexToScalar = (hex: string): bigint => {
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error('scalar must be exactly 32 lowercase hexadecimal bytes');
  }
  const scalar = BigInt(`0x${hex}`);
  if (scalar >= CURVE_ORDER) {
    throw new Error('scalar must be canonically smaller than the curve order');
  }
  return scalar;
};

const randomScalar = (): bigint => {
  // Zero would make an LSAG nonce reveal the signer scalar through
  // s = alpha - c*x. Its probability is tiny, but the invariant is cheap to
  // enforce and belongs at the sampling boundary.
  while (true) {
    const raw = new Uint8Array(48);
    crypto.getRandomValues(raw);
    const scalar = mod(BigInt(`0x${bytesToHex(raw)}`));
    if (scalar !== 0n) return scalar;
  }
};

const utf8 = (input: string): Uint8Array => TEXT_ENCODER.encode(input);

const concatBytes = (...chunks: Uint8Array[]): Uint8Array => {
  const total = chunks.reduce((acc, c) => acc + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
};

const toArrayBuffer = (input: Uint8Array): ArrayBuffer => new Uint8Array(input).buffer;

const b64UrlToBytes = (s: string): Uint8Array => {
  const base64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const decoded = atob(padded);
  const out = new Uint8Array(decoded.length);
  for (let i = 0; i < decoded.length; i += 1) {
    out[i] = decoded.charCodeAt(i);
  }
  return out;
};

const seedToSecretScalarHex = (seedBytes: Uint8Array): string => {
  const ext = ed25519.utils.getExtendedPublicKey(seedBytes);
  return scalarToHex(mod(ext.scalar));
};

const pointFromHex = (hex: string): typeof BASE => {
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error('point must be exactly 32 lowercase hexadecimal bytes');
  }
  const point = ed25519.Point.fromHex(hex);
  if (bytesToHex(point.toBytes()) !== hex) {
    throw new Error('point encoding is not canonical');
  }
  return point;
};

const rejectDuplicatePoints = (points: (typeof BASE)[]): void => {
  const encodings = points.map((point) => bytesToHex(point.toBytes()));
  if (new Set(encodings).size !== encodings.length) {
    throw new Error('Ring public keys must be distinct');
  }
};

const hashToScalar = async (...chunks: Uint8Array[]): Promise<bigint> => {
  const data = concatBytes(...chunks);
  const digest = await crypto.subtle.digest('SHA-512', toArrayBuffer(data));
  return mod(BigInt(`0x${bytesToHex(new Uint8Array(digest))}`));
};

// Domain-separation tag for the hash-to-curve used to derive H_p(P).
// Distinct from the challenge hash so the two oracles never collide.
const HASH_TO_POINT_DST = 'crypto-lab-ring-sign:LSAG:H2P:v1';

// Map a ring member's public key to an independent curve point H_p(P) whose
// discrete log to the base point is UNKNOWN. This is the security-critical part
// of LSAG: the key image I = x·H_p(P) must not be recomputable from public data.
//
// A previous version computed H_p(P) = G·SHA512(P), i.e. H_p(P) = h·G with a
// publicly known scalar h. That let ANYONE deanonymize the signer by testing
// h_k·P_k == I for each ring member P_k, since I = x·h·G = h·(x·G) = h·P.
//
// We now use RFC 9380 hash-to-curve (Elligator2 / edwards25519_XMD:SHA-512_ELL2_RO_)
// so H_p(P) is a uniformly random point of the prime-order subgroup with no
// exploitable relation to G. The result lands on the same edwards25519 curve as
// the base point and ring public keys, so the LSAG arithmetic stays consistent.
const hashPoint = (point: typeof BASE): typeof BASE => {
  const dst = utf8(HASH_TO_POINT_DST);
  const hp = ed25519_hasher.hashToCurve(point.toBytes(), { DST: dst }) as typeof BASE;
  // Work in the prime-order subgroup so key images are torsion-free by
  // construction (verifyLsag also rejects any torsion component defensively).
  return hp.clearCofactor();
};

// Serialize the ring's public keys once per signature, in ring order, so every
// link of the challenge chain hashes the same L. Encoded as a 2-byte big-endian
// count followed by the fixed-width 32-byte compressed points, which makes the
// encoding unambiguous (no ring can be reparsed as a different ring).
const encodeRing = (pubPoints: (typeof BASE)[]): Uint8Array => {
  const header = new Uint8Array(2);
  header[0] = (pubPoints.length >> 8) & 0xff;
  header[1] = pubPoints.length & 0xff;
  return concatBytes(header, ...pubPoints.map((p) => p.toBytes()));
};

// Liu-Wei-Wong LSAG challenge: c_{i+1} = H(L, m, L_i, R_i), where L is the LIST
// OF RING PUBLIC KEYS. Hashing L is not decoration — it is what binds a
// signature to the exact ring it was produced for, and the reduction in the
// LWW security proof relies on it. Without L in the hash, a valid signature can
// be replayed against a *different* ring that happens to reproduce the same
// (L_i, R_i) sequence, and the "ring" the verifier believes in is no longer the
// ring the signer committed to.
//
// Reference: Liu, Wei & Wong, "Linkable Spontaneous Anonymous Group Signature
// for Ad Hoc Groups" (ACISP 2004), §4.
const challengeFor = async (
  ringBytes: Uint8Array,
  message: string,
  keyImage: typeof BASE,
  lPoint: typeof BASE,
  rPoint: typeof BASE
): Promise<bigint> =>
  hashToScalar(
    // V2: V1 hashed only (m, I, L_i, R_i) and left the ring unbound.
    utf8('LSAG_CHALLENGE_V2'),
    ringBytes,
    utf8(message),
    keyImage.toBytes(),
    lPoint.toBytes(),
    rPoint.toBytes()
  );

const normalizeRingSize = (size: number): number => {
  if (!Number.isInteger(size)) {
    throw new Error('Ring size must be an integer');
  }
  if (size < 2 || size > 11) {
    throw new Error('Ring size must be between 2 and 11');
  }
  return size;
};

export const generateRingMembers = async (ringSize: number): Promise<RingKeyPair[]> => {
  const size = normalizeRingSize(ringSize);
  const members: RingKeyPair[] = [];
  for (let i = 0; i < size; i += 1) {
    const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
    const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    if (!privateJwk.d || !publicJwk.x) {
      throw new Error('WebCrypto did not provide Ed25519 JWK key material');
    }
    const publicBytes = b64UrlToBytes(publicJwk.x);
    const secretSeedBytes = b64UrlToBytes(privateJwk.d);
    members.push({
      id: `M${i + 1}`,
      publicJwk,
      privateJwk,
      publicKeyHex: bytesToHex(publicBytes),
      // Ed25519 private JWK `d` is a seed; LSAG needs the clamped scalar.
      secretScalarHex: seedToSecretScalarHex(secretSeedBytes)
    });
  }
  return members;
};

export const getPublicRing = (members: RingKeyPair[]): RingMemberPublic[] =>
  members.map((m) => ({ id: m.id, publicKeyHex: m.publicKeyHex }));

const keyImageFromSecret = (secretScalar: bigint, publicPoint: typeof BASE): typeof BASE => {
  const hp = hashPoint(publicPoint);
  return hp.multiply(secretScalar);
};

export const signLsag = async (
  message: string,
  members: RingKeyPair[],
  signerIndex: number
): Promise<LsagSignature> => {
  normalizeRingSize(members.length);
  if (!Number.isInteger(signerIndex) || signerIndex < 0 || signerIndex >= members.length) {
    throw new Error('Signer index is out of range');
  }

  const n = members.length;
  const pubPoints = members.map((m) => pointFromHex(m.publicKeyHex));
  rejectDuplicatePoints(pubPoints);
  const ringBytes = encodeRing(pubPoints);
  const hpPoints = pubPoints.map((p) => hashPoint(p));
  const secret = hexToScalar(members[signerIndex].secretScalarHex);
  if (secret === 0n) {
    throw new Error('Signer scalar must be non-zero');
  }
  const keyImage = keyImageFromSecret(secret, pubPoints[signerIndex]);

  const c = new Array<bigint>(n).fill(0n);
  const s = new Array<bigint>(n).fill(0n);

  const alpha = randomScalar();
  const lSigner = multiplyPoint(BASE, alpha);
  const rSigner = multiplyPoint(hpPoints[signerIndex], alpha);
  c[(signerIndex + 1) % n] = await challengeFor(ringBytes, message, keyImage, lSigner, rSigner);

  let i = (signerIndex + 1) % n;
  while (i !== signerIndex) {
    s[i] = randomScalar();
    const l = multiplyPoint(BASE, s[i]).add(multiplyPoint(pubPoints[i], c[i]));
    const r = multiplyPoint(hpPoints[i], s[i]).add(multiplyPoint(keyImage, c[i]));
    c[(i + 1) % n] = await challengeFor(ringBytes, message, keyImage, l, r);
    i = (i + 1) % n;
  }

  s[signerIndex] = mod(alpha - c[signerIndex] * secret);

  return {
    ring: getPublicRing(members),
    c0Hex: scalarToHex(c[0]),
    responsesHex: s.map((v) => scalarToHex(v)),
    keyImageHex: bytesToHex(keyImage.toBytes()),
    message,
    signerIndex
  };
};

export const verifyLsag = async (message: string, signature: LsagSignature): Promise<boolean> => {
  // Verification is a trust boundary. Malformed wire data is an ordinary
  // invalid signature, not an exception callers must remember to catch.
  try {
    normalizeRingSize(signature.ring.length);
    if (signature.responsesHex.length !== signature.ring.length) {
      return false;
    }
    if (signature.message !== message) {
      return false;
    }

    const keyImage = pointFromHex(signature.keyImageHex);
    if (keyImage.equals(ed25519.Point.ZERO)) {
      return false;
    }
    if (keyImage.isSmallOrder() || !keyImage.isTorsionFree()) {
      return false;
    }
    const c0 = hexToScalar(signature.c0Hex);
    const pubPoints = signature.ring.map((m) => pointFromHex(m.publicKeyHex));
    rejectDuplicatePoints(pubPoints);
    if (pubPoints.some((p) => p.isSmallOrder() || !p.isTorsionFree())) {
      return false;
    }
    const ringBytes = encodeRing(pubPoints);
    const hpPoints = pubPoints.map((p) => hashPoint(p));

    let c = c0;
    for (let i = 0; i < pubPoints.length; i += 1) {
      const s = hexToScalar(signature.responsesHex[i]);
      const l = multiplyPoint(BASE, s).add(multiplyPoint(pubPoints[i], c));
      const r = multiplyPoint(hpPoints[i], s).add(multiplyPoint(keyImage, c));
      c = await challengeFor(ringBytes, message, keyImage, l, r);
    }
    return c === c0;
  } catch {
    return false;
  }
};

export const reconstructChallengeChain = async (
  message: string,
  signature: LsagSignature
): Promise<string[]> => {
  const keyImage = pointFromHex(signature.keyImageHex);
  const pubPoints = signature.ring.map((m) => pointFromHex(m.publicKeyHex));
  const ringBytes = encodeRing(pubPoints);
  const hpPoints = pubPoints.map((p) => hashPoint(p));
  const chain: string[] = [];
  let c = hexToScalar(signature.c0Hex);
  chain.push(scalarToHex(c));
  for (let i = 0; i < pubPoints.length; i += 1) {
    const s = hexToScalar(signature.responsesHex[i]);
    const l = multiplyPoint(BASE, s).add(multiplyPoint(pubPoints[i], c));
    const r = multiplyPoint(hpPoints[i], s).add(multiplyPoint(keyImage, c));
    c = await challengeFor(ringBytes, message, keyImage, l, r);
    chain.push(scalarToHex(c));
  }
  return chain;
};

// Change a scalar while keeping its wire encoding canonical. Flipping the most
// significant nibble can push a valid scalar above the curve order; the strict
// verifier then correctly rejects before reconstructing the chain, which makes
// the teaching animation preserve the old clean chain. Moving by one inside
// [0, L) guarantees both a changed signature and a recomputable broken chain.
const changeCanonicalScalar = (hex: string): string => {
  const scalar = hexToScalar(hex);
  return scalarToHex(scalar === 0n ? 1n : scalar - 1n);
};

export type TamperField = 'response' | 'c0';

// Corrupt one element of a signature so a learner can watch verification reject it.
// `response` breaks the challenge chain so it no longer closes at c0;
// `c0` changes the chain's starting point with the same effect.
export const tamperLsagSignature = (
  signature: LsagSignature,
  field: TamperField
): LsagSignature => {
  const clone: LsagSignature = {
    ...signature,
    ring: signature.ring.map((m) => ({ ...m })),
    responsesHex: [...signature.responsesHex]
  };
  if (field === 'response') {
    clone.responsesHex[0] = changeCanonicalScalar(clone.responsesHex[0]);
  } else {
    clone.c0Hex = changeCanonicalScalar(clone.c0Hex);
  }
  return clone;
};

export const detectKeyImageReuse = (keyImages: string[]): { reused: boolean; duplicates: string[] } => {
  const seen = new Set<string>();
  const duplicates = new Set<string>();
  for (const keyImage of keyImages) {
    if (seen.has(keyImage)) {
      duplicates.add(keyImage);
    } else {
      seen.add(keyImage);
    }
  }
  return {
    reused: duplicates.size > 0,
    duplicates: Array.from(duplicates)
  };
};

export const ringSignAndVerify = async (
  message: string,
  members: RingKeyPair[],
  signerIndex: number
): Promise<{ signature: LsagSignature; verified: boolean }> => {
  const signature = await signLsag(message, members, signerIndex);
  const verified = await verifyLsag(message, signature);
  return { signature, verified };
};

export const exportPublicKeyForDisplay = async (publicJwk: JsonWebKey): Promise<string> => {
  if (!publicJwk.x) {
    throw new Error('Missing public x coordinate in JWK');
  }
  return bytesToHex(b64UrlToBytes(publicJwk.x));
};

export const verifyEd25519WebCryptoRoundtrip = async (member: RingKeyPair, message: string): Promise<boolean> => {
  const privateKey = await crypto.subtle.importKey('jwk', member.privateJwk, { name: 'Ed25519' }, false, ['sign']);
  const publicKey = await crypto.subtle.importKey('jwk', member.publicJwk, { name: 'Ed25519' }, false, ['verify']);
  const msg = utf8(message);
  const sig = await crypto.subtle.sign('Ed25519', privateKey, toArrayBuffer(msg));
  return crypto.subtle.verify('Ed25519', publicKey, sig, toArrayBuffer(msg));
};

export const decodeHex = (hex: string): Uint8Array => hexToBytes(hex);
