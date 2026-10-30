# noqtis 0.1.2

* Built with libnoqtis 0.1.2; no change to the R API.

# noqtis 0.1.1

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
* Capsule format 2: `nqseal(format = 2)` adds a Merkle tree over the
  files, and `inputs` records the capsules one was made from, by
  `nqcapid()`. `nqprove()` writes a proof that some files are in such a
  capsule, and `nqcheck(proof = )` checks it. `nqcheck()` also takes
  `only` (a partial check), `lineage` (capsule folders the inputs are
  found in) and `keys` (key statements). `nqfiles()` lists a manifest.
* Key statements: `nqrotate()` and `nqrevoke()`.
* DSSE envelopes: `nqdsse()` and `nqdsseverify()`.
* Ed25519 and the hybrids ML-DSA-44/65/87+Ed25519 in `nqkeygen()`,
  `nqsign()` and `nqverify()`; a hybrid key can seal a capsule.
* `nqalgs()`, `nqrand()` and `nqver()`.
