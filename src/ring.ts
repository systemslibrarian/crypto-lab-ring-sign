import { ed25519 } from '@noble/curves/ed25519.js';

const CURVE_ORDER = ed25519.Point.Fn.ORDER;
const BASE = ed25519.Point.BASE;
const TEXT_ENCODER = new TextEncoder();

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

const hexToBytes = (hex: string): Uint8Array => {
  if (hex.length % 2 !== 0) {
    throw new Error('hex length must be even');
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

const mod = (x: bigint): bigint => {
  const r = x % CURVE_ORDER;
  return r >= 0n ? r : r + CURVE_ORDER;
};

const scalarToHex = (x: bigint): string => x.toString(16).padStart(64, '0');
const hexToScalar = (hex: string): bigint => mod(BigInt(`0x${hex}`));

const randomScalar = (): bigint => {
  const raw = new Uint8Array(48);
  crypto.getRandomValues(raw);
  return mod(BigInt(`0x${bytesToHex(raw)}`));
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

const pointFromHex = (hex: string) => ed25519.Point.fromHex(hex);

const hashToScalar = async (...chunks: Uint8Array[]): Promise<bigint> => {
  const data = concatBytes(...chunks);
  const digest = await crypto.subtle.digest('SHA-512', toArrayBuffer(data));
  return mod(BigInt(`0x${bytesToHex(new Uint8Array(digest))}`));
};

const hashPoint = async (point: typeof BASE): Promise<typeof BASE> => {
  const h = await hashToScalar(point.toBytes());
  return BASE.multiply(h === 0n ? 1n : h);
};

const challengeFor = async (
  message: string,
  keyImage: typeof BASE,
  lPoint: typeof BASE,
  rPoint: typeof BASE
): Promise<bigint> =>
  hashToScalar(
    utf8('LSAG_CHALLENGE_V1'),
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
    const secretBytes = b64UrlToBytes(privateJwk.d);
    members.push({
      id: `M${i + 1}`,
      publicJwk,
      privateJwk,
      publicKeyHex: bytesToHex(publicBytes),
      secretScalarHex: bytesToHex(secretBytes)
    });
  }
  return members;
};

export const getPublicRing = (members: RingKeyPair[]): RingMemberPublic[] =>
  members.map((m) => ({ id: m.id, publicKeyHex: m.publicKeyHex }));

const keyImageFromSecret = async (secretScalar: bigint, publicPoint: typeof BASE): Promise<typeof BASE> => {
  const hp = await hashPoint(publicPoint);
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
  const hpPoints = await Promise.all(pubPoints.map((p) => hashPoint(p)));
  const secret = hexToScalar(members[signerIndex].secretScalarHex);
  const keyImage = await keyImageFromSecret(secret, pubPoints[signerIndex]);

  const c = new Array<bigint>(n).fill(0n);
  const s = new Array<bigint>(n).fill(0n);

  const alpha = randomScalar();
  const lSigner = BASE.multiply(alpha);
  const rSigner = hpPoints[signerIndex].multiply(alpha);
  c[(signerIndex + 1) % n] = await challengeFor(message, keyImage, lSigner, rSigner);

  let i = (signerIndex + 1) % n;
  while (i !== signerIndex) {
    s[i] = randomScalar();
    const l = BASE.multiply(s[i]).add(pubPoints[i].multiply(c[i]));
    const r = hpPoints[i].multiply(s[i]).add(keyImage.multiply(c[i]));
    c[(i + 1) % n] = await challengeFor(message, keyImage, l, r);
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
  normalizeRingSize(signature.ring.length);
  if (signature.responsesHex.length !== signature.ring.length) {
    return false;
  }
  if (signature.message !== message) {
    return false;
  }

  const keyImage = pointFromHex(signature.keyImageHex);
  const c0 = hexToScalar(signature.c0Hex);
  const pubPoints = signature.ring.map((m) => pointFromHex(m.publicKeyHex));
  const hpPoints = await Promise.all(pubPoints.map((p) => hashPoint(p)));

  let c = c0;
  for (let i = 0; i < pubPoints.length; i += 1) {
    const s = hexToScalar(signature.responsesHex[i]);
    const l = BASE.multiply(s).add(pubPoints[i].multiply(c));
    const r = hpPoints[i].multiply(s).add(keyImage.multiply(c));
    c = await challengeFor(message, keyImage, l, r);
  }
  return c === c0;
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
