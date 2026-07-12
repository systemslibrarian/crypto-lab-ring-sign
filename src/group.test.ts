import { describe, it, expect } from 'vitest';
import {
  createGroupManager,
  issueCredential,
  groupSign,
  verifyGroupSignature,
  openGroupSignature,
  isRingVsGroupSummary,
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
