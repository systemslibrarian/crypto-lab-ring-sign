# crypto-lab-ring-sign

## What This Demonstrates
This browser lab demonstrates ring signatures and group signatures as two different ways to prove group membership while hiding signer identity from the verifier. It highlights how LSAG-style ring signatures provide signer ambiguity and key-image-based linkability for double-spend detection, and how group signatures add manager-controlled opening for accountability.

## How It Works
The demo uses real browser cryptography. Ring members are generated with WebCrypto Ed25519 keys, and LSAG challenge-chain construction and verification are performed with real Ed25519 curve arithmetic. Key images are derived from signer secrets and checked for reuse. The group-signature exhibit uses a P-256 group manager that issues member credentials, verifies anonymous signatures, and can open a signature to reveal the signer when required. Five interactive exhibits walk through ring formation, linkability, ring-size tradeoffs, manager-accountable anonymity, and Monero context.

## Threat Models Covered
The lab covers observer and verifier threat models where signer identity should remain hidden within a set, while still proving valid authorization. It demonstrates double-spend risk in anonymous transaction systems and how key-image reuse exposes replayed signer secrets. It also covers organizational accountability requirements where anonymous signatures need optional tracing by a trusted authority (group manager opening), contrasting non-accountable ring signatures with accountable group signatures.

## Running Locally
```bash
npm install
npm run dev
```

## Live Demo
https://systemslibrarian.github.io/crypto-lab-ring-sign/
