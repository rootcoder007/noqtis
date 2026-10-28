# HQC known-answer digests

- `hqc-kat-digests.txt`: copied unchanged from rmoriebricklayer,
  `tests/testthat/hqc-kat-digests.txt` (commit 6450ab1f3ce914a4794cdfe9bb5e91b21de24058,
  2026-10-04). SHA-256
  `fea8c4548df723859f5874e28c7a5a6c3b6a651cd257e902e38ccd890de3cd21`.
- It is derived from the official HQC v5.0.0 (specification 2025-08-22) known
  answers, `kats/ref/hqc-{1,3,5}/PQCkemKAT_*.rsp` of https://gitlab.com/pqc-hqc/hqc
  (public domain): for each of the 300 vectors (100 per parameter set) the
  48-byte seed of the .rsp record and the SHA-256 of pk || sk || ct || ss.
- `tests/thqc.c` re-derives each vector's randomness as the reference KAT
  generator does, SHAKE256(seed || 0x00) read in order (seed_kem 32 bytes,
  then m and the salt), runs key generation, encapsulation and decapsulation,
  and compares the digest.
