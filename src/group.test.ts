import { describe, it, expect } from 'vitest';
import {
  createGroupManager,
  issueCredential,
  groupSign,
  verifyGroupSignature,
  openGroupSignature,
  isRingVsGroupSummary,
  linkageFromWire,
  type GroupSignature
} from './group.ts';

describe('P-256 manager-issued group signatures', () => {
  it('a manager-issued credential produces a verifiable group signature', async () => {
    const manager = await createGroupManager();
    const cred = await issueCredential(manager, 'employee-42');
    const sig = await groupSign('quarterly-report', cred);
    await expect(verifyGroupSignature(manager.managerPublicJwk, sig)).resolves.toBe(true);
  });

  it('the manager can OPEN a signature to the enrolled member id', async () => {
    const manager = await createGroupManager();
    const cred = await issueCredential(manager, 'employee-42');
    const sig = await groupSign('m', cred);
    expect(openGroupSignature(manager, sig)).toBe('employee-42');
  });

  it('rejects a forged member signature (wrong message / tampered body)', async () => {
    const manager = await createGroupManager();
    const cred = await issueCredential(manager, 'alice');
    const sig = await groupSign('approve-payment', cred);
    const tampered: GroupSignature = { ...sig, message: 'approve-BIGGER-payment' };
    await expect(verifyGroupSignature(manager.managerPublicJwk, tampered)).resolves.toBe(false);
  });

  it('rejects a signature verified against a DIFFERENT manager public key', async () => {
    const managerA = await createGroupManager();
    const managerB = await createGroupManager();
    const cred = await issueCredential(managerA, 'bob');
    const sig = await groupSign('m', cred);
    await expect(verifyGroupSignature(managerB.managerPublicJwk, sig)).resolves.toBe(false);
  });

  it('SECURITY: rejects a member key NOT bound to the manager-issued credential', async () => {
    // README failure mode: "if the verifier does not ensure the presented member
    // public key matches the manager-issued credential, a forged identity binding
    // can slip through." Attacker swaps in their OWN key + valid self-signature
    // but keeps the manager-signed issuedPayload (which binds a DIFFERENT key).
    const manager = await createGroupManager();
    const legit = await issueCredential(manager, 'legit-member');

    // Attacker is an outsider with their own P-256 key pair, no manager credential.
    const attacker = await createGroupManager(); // reuse to mint a fresh keypair
    const attackerCred = await issueCredential(attacker, 'attacker');

    const legitSig = await groupSign('transfer', legit);
    // Forge: present attacker's public key + attacker's member signature, but
    // reuse the manager's issuedPayload/managerSignatureHex from the legit cred.
    const attackerSelfSig = await groupSign('transfer', attackerCred);
    const forged: GroupSignature = {
      message: 'transfer',
      credentialId: legitSig.credentialId,
      issuedPayload: legitSig.issuedPayload, // manager-signed, binds legit key
      managerSignatureHex: legitSig.managerSignatureHex,
      memberPublicJwk: attackerCred.memberPublicJwk, // attacker's key
      memberSignatureHex: attackerSelfSig.memberSignatureHex,
      nonceHex: attackerSelfSig.nonceHex
    };
    // Must fail: presented member key != key bound inside the manager credential.
    await expect(verifyGroupSignature(manager.managerPublicJwk, forged)).resolves.toBe(false);
  });

  it('rejects a mismatched credentialId (payload id != claimed id)', async () => {
    const manager = await createGroupManager();
    const cred = await issueCredential(manager, 'carol');
    const sig = await groupSign('m', cred);
    const forged: GroupSignature = { ...sig, credentialId: 'deadbeefdeadbeefdeadbeef' };
    await expect(verifyGroupSignature(manager.managerPublicJwk, forged)).resolves.toBe(false);
  });

  it('rejects a tampered manager signature (unenrolled / self-issued credential)', async () => {
    const manager = await createGroupManager();
    const cred = await issueCredential(manager, 'dave');
    const sig = await groupSign('m', cred);
    // Flip a byte of the manager signature so the credential is not manager-issued.
    const flipped =
      (sig.managerSignatureHex[0] === '0' ? '1' : '0') + sig.managerSignatureHex.slice(1);
    const forged: GroupSignature = { ...sig, managerSignatureHex: flipped };
    await expect(verifyGroupSignature(manager.managerPublicJwk, forged)).resolves.toBe(false);
  });

  it('summary distinguishes ring (no manager) vs group (manager opens)', () => {
    const s = isRingVsGroupSummary();
    expect(s).toMatch(/ambiguity/i);
    expect(s).toMatch(/manager/i);
  });
});

/**
 * Exhibit 4's live readout said "Signer identity to verifier: hidden (only sees
 * manager-issued credential proof)" as a fixed string, while every signature
 * carries a stable credentialId and the member's public key in the clear — so
 * two showings by one member are linkable by anyone. The readout is now computed
 * by linkageFromWire(); these pin what it reports.
 */
describe('what a verifier can correlate from the wire alone', () => {
  it('links repeat signatures by the same member without the manager', async () => {
    const manager = await createGroupManager();
    const alice = await issueCredential(manager, 'alice');
    const history: GroupSignature[] = [];
    history.push(await groupSign('m1', alice));
    history.push(await groupSign('m2', alice));
    const linkage = linkageFromWire(history[1], history);
    expect(linkage.linkedCount).toBe(2);
    expect(linkage.distinctSigners).toBe(1);
    expect(linkage.pseudonym).toBe(alice.credentialId);
    // The fields that stayed byte-identical across both showings ARE the handle.
    expect(linkage.stableFields).toContain('credentialId');
    expect(linkage.stableFields).toContain('memberPublicJwk');
  });

  it('separates distinct members and does not over-link them', async () => {
    const manager = await createGroupManager();
    const alice = await issueCredential(manager, 'alice');
    const bob = await issueCredential(manager, 'bob');
    const history: GroupSignature[] = [
      await groupSign('m1', alice),
      await groupSign('m2', bob),
      await groupSign('m3', bob)
    ];
    const forBob = linkageFromWire(history[2], history);
    expect(forBob.distinctSigners).toBe(2);
    expect(forBob.linkedCount).toBe(2);
    const forAlice = linkageFromWire(history[0], history);
    expect(forAlice.linkedCount).toBe(1);
    expect(forAlice.stableFields).toEqual([]);
  });
});
