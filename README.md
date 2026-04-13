# crypto-lab-ring-sign

[![crypto-lab portfolio](https://img.shields.io/badge/crypto--lab-portfolio-blue?style=flat-square)](https://systemslibrarian.github.io/crypto-lab/)

## What It Is
This demo compares two anonymous-authentication models: LSAG-style ring signatures and manager-issued group signatures. In the code, ring members are built from WebCrypto Ed25519 keys and verified with real Ed25519 curve arithmetic, while the group-signature exhibit uses P-256 ECDSA credentials issued by a manager. The problem being illustrated is how to prove membership in a set without publicly revealing which specific member acted. The security model differs by primitive: ring signatures provide signer ambiguity with linkability through key images, while the group flow adds manager-controlled opening for accountability.

## When to Use It
- Use it to explain ring signatures in privacy-preserving payments, because the LSAG flow shows how one valid signer is hidden among decoys while still producing a verifiable signature.
- Use it to demonstrate key-image-based double-spend detection, because the same signer secret yields the same linkable key image across repeated spends.
- Use it to compare anonymous authorization models, because the group-signature exhibit shows what changes when a manager can issue credentials and later open a signature.
- Use it to discuss anonymity-set tradeoffs, because the ring-size timing exhibit makes the privacy-versus-cost relationship visible with real measurements.
- Do not use it as a production wallet or enterprise group-signature implementation, because the group exhibit is a teaching model built from manager-issued P-256 credentials rather than a standardized deployable group-signature scheme.

## Live Demo
Live demo: https://systemslibrarian.github.io/crypto-lab-ring-sign/

The page lets users choose ring size, select a hidden signer, generate LSAG signatures, compare key images, and measure signing versus verification cost. It also includes explicit controls for issuing group credentials, anonymously signing as a group member, and opening the resulting signature through the manager flow.

## What Can Go Wrong
- Reused signer secret in multiple ring spends: the key image repeats, which breaks unlinkability for that signer and exposes a double-spend attempt.
- Invalid challenge-chain arithmetic: if any challenge or response is computed against the wrong ring member ordering, verification fails because the chain no longer closes at `c0`.
- Weak or malformed curve points: accepting small-order or non-torsion-free points can break security assumptions for Edwards-curve signature verification.
- Mis-bound group credentials: if the verifier does not ensure the presented member public key matches the manager-issued credential, a forged identity binding can slip through.
- Oversold anonymity set: a large nominal ring does not guarantee strong privacy if decoy selection is poor or the application leaks metadata outside the signature itself.

## Real-World Usage
- Monero: uses linkable ring signatures (today CLSAG, historically LSAG-family constructions) to hide the real input among decoys while still detecting double spends.
- MobileCoin: uses ring-signature-based transaction privacy to hide which member of an input set authorized a spend.
- Intel EPID: uses a group-signature system so devices can attest membership anonymously while allowing issuer-controlled revocation and management.
- TPM Direct Anonymous Attestation: uses a group-signature-style attestation model so a TPM can prove valid membership without revealing a unique device identity to every verifier.

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
