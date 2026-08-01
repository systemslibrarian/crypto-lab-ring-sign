const TEXT_ENCODER = new TextEncoder();

const utf8 = (input: string): Uint8Array => TEXT_ENCODER.encode(input);
const toArrayBuffer = (input: Uint8Array): ArrayBuffer => new Uint8Array(input).buffer;

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

const randomHex = (len = 16): string => {
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
};

export type GroupManager = {
  managerPrivateJwk: JsonWebKey;
  managerPublicJwk: JsonWebKey;
  registry: Map<string, string>;
};

export type GroupCredential = {
  credentialId: string;
  memberId: string;
  memberPublicJwk: JsonWebKey;
  memberPrivateJwk: JsonWebKey;
  issuedPayload: string;
  managerSignatureHex: string;
};

export type GroupSignature = {
  message: string;
  credentialId: string;
  issuedPayload: string;
  managerSignatureHex: string;
  memberPublicJwk: JsonWebKey;
  memberSignatureHex: string;
  nonceHex: string;
};

const importManagerPrivate = (jwk: JsonWebKey): Promise<CryptoKey> =>
  crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);

const importManagerPublic = (jwk: JsonWebKey): Promise<CryptoKey> =>
  crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);

const importMemberPrivate = (jwk: JsonWebKey): Promise<CryptoKey> =>
  crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);

const importMemberPublic = (jwk: JsonWebKey): Promise<CryptoKey> =>
  crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);

const signEcdsaHex = async (privateKey: CryptoKey, payload: string): Promise<string> => {
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    toArrayBuffer(utf8(payload))
  );
  return bytesToHex(new Uint8Array(sig));
};

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

const verifyEcdsaHex = async (publicKey: CryptoKey, payload: string, signatureHex: string): Promise<boolean> =>
  crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    publicKey,
    toArrayBuffer(hexToBytes(signatureHex)),
    toArrayBuffer(utf8(payload))
  );

export const createGroupManager = async (): Promise<GroupManager> => {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const managerPrivateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const managerPublicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return {
    managerPrivateJwk,
    managerPublicJwk,
    registry: new Map<string, string>()
  };
};

export const issueCredential = async (manager: GroupManager, memberId: string): Promise<GroupCredential> => {
  const memberPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const memberPrivateJwk = await crypto.subtle.exportKey('jwk', memberPair.privateKey);
  const memberPublicJwk = await crypto.subtle.exportKey('jwk', memberPair.publicKey);
  const credentialId = randomHex(12);

  const issuedPayload = JSON.stringify({
    v: 1,
    credentialId,
    memberPublicJwk,
    issuedAt: new Date().toISOString()
  });

  const managerPrivate = await importManagerPrivate(manager.managerPrivateJwk);
  const managerSignatureHex = await signEcdsaHex(managerPrivate, issuedPayload);
  manager.registry.set(credentialId, memberId);

  return {
    credentialId,
    memberId,
    memberPublicJwk,
    memberPrivateJwk,
    issuedPayload,
    managerSignatureHex
  };
};

export const groupSign = async (message: string, credential: GroupCredential): Promise<GroupSignature> => {
  const nonceHex = randomHex(16);
  const signingPayload = JSON.stringify({
    v: 1,
    message,
    credentialId: credential.credentialId,
    nonceHex
  });
  const memberPrivate = await importMemberPrivate(credential.memberPrivateJwk);
  const memberSignatureHex = await signEcdsaHex(memberPrivate, signingPayload);
  return {
    message,
    credentialId: credential.credentialId,
    issuedPayload: credential.issuedPayload,
    managerSignatureHex: credential.managerSignatureHex,
    memberPublicJwk: credential.memberPublicJwk,
    memberSignatureHex,
    nonceHex
  };
};

export const verifyGroupSignature = async (
  managerPublicJwk: JsonWebKey,
  signature: GroupSignature
): Promise<boolean> => {
  const managerPublic = await importManagerPublic(managerPublicJwk);
  const managerOk = await verifyEcdsaHex(managerPublic, signature.issuedPayload, signature.managerSignatureHex);
  if (!managerOk) {
    return false;
  }

  const payload = JSON.parse(signature.issuedPayload) as {
    credentialId: string;
    memberPublicJwk: JsonWebKey;
  };
  if (payload.credentialId !== signature.credentialId) {
    return false;
  }
  if (JSON.stringify(payload.memberPublicJwk) !== JSON.stringify(signature.memberPublicJwk)) {
    return false;
  }
  const signingPayload = JSON.stringify({
    v: 1,
    message: signature.message,
    credentialId: signature.credentialId,
    nonceHex: signature.nonceHex
  });

  const memberPublic = await importMemberPublic(payload.memberPublicJwk);
  return verifyEcdsaHex(memberPublic, signingPayload, signature.memberSignatureHex);
};

export const openGroupSignature = (manager: GroupManager, signature: GroupSignature): string | null =>
  manager.registry.get(signature.credentialId) ?? null;

/**
 * What a verifier actually learns about the signer, computed from the wire
 * bytes alone. The page used to state flatly that the signer's identity was
 * "hidden (only sees manager-issued credential proof)". It is not: every
 * signature carries a stable credentialId and the member's public key, so
 * repeat signatures from one member are trivially linkable by anybody, not just
 * the manager. This returns the pseudonym a verifier can key on, plus how many
 * of the supplied signatures collapse onto it.
 */
export type PseudonymLinkage = {
  /** The stable handle a verifier can group by. */
  pseudonym: string;
  /** How many of the supplied signatures carry this same handle. */
  linkedCount: number;
  /** Distinct pseudonyms across the supplied signatures. */
  distinctSigners: number;
  /** The fields of the signature that are constant per member. */
  stableFields: string[];
};

const memberHandle = (signature: GroupSignature): string =>
  `${signature.credentialId}:${JSON.stringify(signature.memberPublicJwk)}`;

export const linkageFromWire = (
  signature: GroupSignature,
  history: GroupSignature[]
): PseudonymLinkage => {
  const handle = memberHandle(signature);
  const handles = history.map(memberHandle);
  const stableFields: string[] = [];
  // Derived, not listed by hand: any field whose value repeats across two
  // signatures by the same handle is a correlation handle in its own right.
  const sameSigner = history.filter((s) => memberHandle(s) === handle);
  if (sameSigner.length > 1) {
    for (const key of ['credentialId', 'issuedPayload', 'managerSignatureHex'] as const) {
      if (sameSigner.every((s) => s[key] === sameSigner[0][key])) stableFields.push(key);
    }
    if (sameSigner.every((s) => JSON.stringify(s.memberPublicJwk) === JSON.stringify(sameSigner[0].memberPublicJwk))) {
      stableFields.push('memberPublicJwk');
    }
  }
  return {
    pseudonym: signature.credentialId,
    linkedCount: handles.filter((h) => h === handle).length,
    distinctSigners: new Set(handles).size,
    stableFields
  };
};

export const isRingVsGroupSummary = (): string =>
  'Ring signatures provide signer ambiguity without a manager; group signatures add a manager that can open signatures for accountability.';
