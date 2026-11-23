# HQC known-answer vectors

Fetched 2026-11-22 from https://gitlab.com/pqc-hqc/hqc, tag v5.1.0
(commit 06567ccbad10580d78dd7863b15d23f41076d57f, 2026-10-26; public
domain), the reference implementation of the HQC specification version 5.1
(https://pqc-hqc.org/doc/hqc_specifications_v5.1.pdf, 2026-11-09, SHA-256
45be0bc16b6a44836a5f6d9f7bafbaf39e368d0bceac6aa1fea64d1320471b2f).

- `hqc-kat-digests.txt`: from `kats/ref/hqc-{1,3,5}/PQCkemKAT_32.rsp`
  (SHA-256 c3f6ce304a00685e3aa356ef7cd81dbb35d985a1ff7123610bed9582e3638c1e,
  7dcb2b670d1e108c0d7dc0c88b466c63c121de5ac4f96fd2e868c7040065a4ff,
  e5066df4ec3dbe012d60a4a66ce5e0c2f1996d11af8a8eb66333f15b51095edb): for
  each of the 300 vectors (100 per parameter set) the 48-byte seed of the
  .rsp record and the SHA-256 of pk || sk || ct || ss, computed from the
  .rsp fields. `tests/thqc.c` re-derives each vector's randomness as the
  reference KAT generator does (the NIST AES-256 CTR_DRBG seeded with the
  seed: seed_kem 32 bytes, then m, then the salt), runs key generation,
  encapsulation and decapsulation, and compares the digest.
- `hqc-rs.txt`: from `kats/rs/hqc-{1,3,5}/rs.tv` (SHA-256
  745b727bbbd679649346d41e799bd8d07afd9fab1e955c5a4c8371786b41c2a3,
  57b316d844a53d47dcdc9ee6e120cbe30d815bec4ac0aa753d8c10d0dcc81f76,
  c84b656037b87e1d880ddbee6297a06bb23ebcf4a715da738835947c0be07785): for
  each of the 2,400 samples (8 scenarios of 100 per set, from no error to
  past the correcting capacity) the corrupted codeword and the message the
  reference decoder returns, and whether the sample is a clean codeword.
- The vectors of version 5.0 (reference v5.0.0) that this directory held
  before are gone: keys, ciphertexts and known answers of 5.0 and 5.1
  differ.
