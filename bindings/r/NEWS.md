# noqtis 0.1.0

* First release: R bindings to the bundled noqtis C library.
* Signatures: `nqkeygen()`, `nqsign()` and `nqverify()` for ML-DSA-44/65/87
  (FIPS 204) and all twelve SLH-DSA parameter sets (FIPS 205), pure,
  with a context string, deterministic, and pre-hash (HashML-DSA,
  HashSLH-DSA).
* Key encapsulation: `nqkeygen()`, `nqencap()` and `nqdecap()` for
  ML-KEM-512/768/1024 (FIPS 203) and HQC-128/192/256, with implicit
  rejection.
* Hashes: `nqhash()` (SHA-2, SHA-3, SHAKE; raw vectors, strings and
  files) and `nqhmac()`.
* Key files: `nqreadkey()` and `nqwritekey()` read and write the
  command-line tool's `noqtis-key-1` files, as strictly as it reads
  them; secret key files are owner-only and never overwritten unless
  `force = TRUE`.
* Capsules: `nqseal()` and `nqcheck()`, compatible with the `noqtis`
  command-line tool.
* `nqalgs()`, `nqrand()` and `nqver()`.
