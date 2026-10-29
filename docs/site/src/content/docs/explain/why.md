---
title: Why post-quantum provenance now
description: Results that cannot be traced to their exact data, signatures that must outlive RSA and elliptic curves, and what sealing files with post-quantum signatures and timestamps does and does not solve.
---

## Results that cannot be traced to their data

A published figure, a table in a report, a trained model or a release
binary is the output of some files: a dataset at one moment, the code
that ran on it, the configuration it ran with. Months later, the
questions are always the same. Which version of the data was this? Is
the file I downloaded the one the authors used? Did anything change
after the result was written up?

Usually nothing can answer them. Data files are overwritten in place,
repositories are reorganised, a checksum list sits next to the files it
describes and can be edited with them, and a "final_v2" folder holds no
record of what it held on the day. The result may be right, but nobody
can show that it came from these exact bytes.

A record that answers those questions has to do three things:

1. list **every** file with a digest of its exact bytes, and notice a file
   that was added, removed or renamed, not only one that changed;
2. be **signed**, so that whoever edits the files cannot also rewrite
   the list;
3. stay **checkable for as long as the result matters**: for research
   data and software releases, decades.

The third requirement is where today's signatures fall short.

## Harvest now, forge later

The signatures most tools use today, RSA and elliptic-curve (ECDSA,
EdDSA), rest on problems that a large enough quantum computer would
solve. NIST's transition plan for post-quantum cryptography,
[NIST IR 8547](https://doi.org/10.6028/NIST.IR.8547), deprecates these
signature algorithms after 2030 and disallows them under NIST standards
after 2035 (its Table 2), and notes that past cryptographic transitions
have taken 10 to 20 years from standard to full deployment.

For encryption, the known danger is "harvest now, decrypt later":
recorded traffic is decrypted once the quantum computer exists. For
signatures that must be checked years after they were made, the
analogue is **harvest now, forge later**. A seal made today with RSA or
ECDSA is checked against a public key that is published, by design.
Once that key can be broken, anyone can make a new seal under it, for
different files, that verifies just as well as the original. The
signature then proves nothing about which files came first. A signature
used for a TLS handshake only has to hold for the length of the
connection; a seal on a dataset behind a published paper has to hold
for as long as the paper is read.

Sealing with post-quantum signatures from the start avoids that:

- **ML-DSA** ([FIPS 204](https://doi.org/10.6028/NIST.FIPS.204)), a
  lattice-based signature, small and fast; NOQTIS's default is ML-DSA-65.
- **SLH-DSA** ([FIPS 205](https://doi.org/10.6028/NIST.FIPS.205)), a
  stateless hash-based signature whose security rests on the hash
  function, the conservative choice for records meant to last.
- **ML-KEM** ([FIPS 203](https://doi.org/10.6028/NIST.FIPS.203)), for
  key establishment; NOQTIS includes it, but capsules do not use it.

NIST published all three as final standards in August 2024. They are not
the last word (cryptanalysis continues), so NOQTIS records two digests
per file (SHA-256 and SHA3-256), lets you choose SLH-DSA where its larger
signatures are acceptable, and versions the capsule format so a future
algorithm can be added.

## Why sealed files, post-quantum signatures and timestamps

Each part answers a different question:

| Part | Answers | Without it |
|---|---|---|
| a manifest of every file (size, SHA-256, SHA3-256), in canonical JSON | *which* bytes | a changed, added, removed or renamed file can go unnoticed |
| a post-quantum signature over the manifest's exact bytes | *who* sealed them | anyone who edits the files can edit the list too, and a quantum-era forger can re-sign with a classical key |
| an [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamp over the signature | *when* | the date in the manifest is only the sealer's own clock |

The timestamp matters for the long run. If a secret key later leaks, or
an algorithm is weakened, a seal whose signature a time-stamping
authority vouched for before that day is still evidence that the files
existed then. In a capsule, the timestamp token covers a digest of the
signature, so the authority never sees the files.

Checking needs no network: the folder, the manifest, the seal and the
public key are enough, offline, in C, from the command line, or from
Python, R and JavaScript.

## What NOQTIS does not solve

A passing check is a precise, limited statement. It does not show:

- **that the result is correct**, or that these were the only inputs: a
  capsule records what was in the folder, not how the result was made.
  Seal the code and record the commands in `meta`.
- **who the key holder is**: that comes from getting the public key
  through a channel you trust. Without a pinned key, a check proves only
  that *someone* sealed the files.
- **when**, without a timestamp. The command-line tool does not yet
  request timestamps (`--tsa` is reserved); the C library checks them
  today ([timestamps](/noqtis/guides/timestamps/)).
- **anything after a secret key is stolen**: whoever holds it can seal
  anything, and the format has no revocation.
- **confidentiality**: capsules are not encrypted, and the manifest lists
  every path.
- **the safety of the machine** that seals or checks: malware there, or a
  compromised compiler or package, defeats any tool.

NOQTIS has not had an external security audit. See the
[security page](/noqtis/security/) for the threat model and how the code
is tested.

## Sources

- NIST, [FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://doi.org/10.6028/NIST.FIPS.203), August 2024.
- NIST, [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://doi.org/10.6028/NIST.FIPS.204), August 2024.
- NIST, [FIPS 205: Stateless Hash-Based Digital Signature Standard](https://doi.org/10.6028/NIST.FIPS.205), August 2024.
- NIST, [IR 8547: Transition to Post-Quantum Cryptography Standards](https://doi.org/10.6028/NIST.IR.8547).
- C. Adams, P. Cain, D. Pinkas, R. Zuccherato, [RFC 3161: Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP)](https://www.rfc-editor.org/rfc/rfc3161), August 2001.
