# noqtis 0.2.3

- Attaching the package in an interactive session says in one line when a newer release exists. The page of the latest release is asked for at most once a day, with a limit of two seconds, and nothing is sent but that request; a session that is not interactive never asks. `options(noqtis.update = FALSE)` or the environment variable `NOQTIS_NO_UPDATE_CHECK` turns it off (see `?noqtis`).
- No change to the functions. The README shows the project's badges.

# noqtis 0.2.2

- No change to the R package: the version follows the library.

# noqtis 0.2.1

- No change to the R package: the version follows the library, whose Java package now carries the data layer.

# noqtis 0.2.0

* `nqdrift()` reads each summarised file inside `dir` and refuses one
  reached through a symbolic link (a failed row), as `nqdpin()` does;
  it followed the link before. A file given in `current` is still read
  by its path. `nqdenv()` likewise refuses a lock file reached through
  a link, where it recorded the digest of the file behind it.
* `nqdrift()` refuses a `psiwarn`, `psifail`, `alpha` or `minn` that is not one number, zero or more: an `NA` or a text value was taken with a warning and every column then read as not drifted.

* Secret keys under a passphrase: `nqpwenc()`, `nqpwdec()` and `pass =`
  for `nqreadkey()` and `nqwritekey()`, in the format `noqtis keygen
  --pass-fd` writes.
* Signatures over a message given in pieces: `nqsigner()`,
  `nqverifier()`, `nqupdate()`, `nqfinish()`, and `nqsignfile()` and
  `nqverifyfile()` for a file, 64 KiB at a time; each signature is the
  one `nqsign()` gives.
* A message or a file sealed to an ML-KEM key: `nqkseal()`, `nqkopen()`,
  `nqbox()` and `nqunbox()` (the format of `noqtis box`, one chunk in
  memory).
* ML-DSA with an external mu (`nqmu()`, `nqsignmu()`, `nqverifymu()`),
  BLAKE2b (`nqblake2b()`), Argon2id (`nqargon2id()`) and `nqcteq()`.
* The rest of the capsule functions: `nqinspect()`, `nqsealwhy()`,
  `nqtsreq()`, `nqtsput()`, `nqersreq()`, `nqersput()`, `nqpack()`,
  `nqunpack()`, `nqcheckpack()` and `nqchain()`.
* The rest of the data record: `nqdparse()`, `nqdschk()`, `nqdsyn()`,
  `nqdcal()`, `nqdchunk()`, `nqdpiece()`, `nqdcommit()`, `nqdreveal()`,
  `nqdcite()`, `nqdreport()`, and `nqdenv()` with `nqdpkgs()`, which
  record the environment with R and its loaded packages.
* The data record's functions give an error when memory runs out, never
  a report or a record missing a part (the data layer's allocator hook,
  `nqdsetal()` in C); the tests make each allocation of the bundled
  library fail in turn to show it.

# noqtis 0.1.4

* Built with libnoqtis 0.1.4: Ed25519 signing, SLH-DSA's PRF and HQC
  decapsulation are masked against power analysis; every signature is
  checked under the public key before `nqsign()` returns it, and one that
  fails (a fault while signing) is an error, never returned.
* `nqselftest()` runs the library's known-answer self-test (every
  family, about a tenth of a second).
* Builds on R 4.1 for Windows (Rtools40), whose headers hid two Windows
  Vista functions the package uses.
* The title is the full name, as in the citation: Notary of Quantum-Safe
  Traceable Inputs and Seals (also in `citation("noqtis")` and
  `?noqtis`).
* The manual is complete: every page says how the function behaves, the
  errors it signals and the standards it implements (with their DOIs),
  links its related functions, and has examples of every option.

# noqtis 0.1.3

* Built with libnoqtis 0.1.3, which builds on glibc older than 2.25; no change to the R API.

# noqtis 0.1.2

* Built with libnoqtis 0.1.2.
* Identity cards: `nqidcard()` makes a `noqtis-idcard-1` card (a signing
  key with its holder's name and, when given, ORCID iD with its check
  digit verified, e-mail address, `https://` page and affiliation,
  signed by the key) and `nqidcheck()` checks one, from a raw vector or
  a file, giving its fields and the key's SHA-256, or `NULL` when it does
  not verify or is for another key than `pk`.

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
