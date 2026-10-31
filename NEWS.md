# noqtis 0.1.3

- NOQTIS builds on glibc older than 2.25 (CentOS and RHEL 7, the manylinux2014 and conda-forge build roots). These have the getrandom system call, which Linux has had since 3.17, but no `<sys/random.h>`; `nqrand` now calls it with `syscall(SYS_getrandom)` there. Nothing falls back to a weaker source; a failure is still `NQERNG`. The whole test suite passes on glibc 2.17.
- The live timestamp tests treat OpenSSL 1.0 like LibreSSL: both sign timestamp replies with SHA-1, which noqtis refuses, so the tests check that refusal and run the SHA-256 checks only where openssl can make such a reply.

# noqtis 0.1.2

- Identity cards (`noqtis-idcard-1`): `noqtis idcard -k <key> --name ... [--orcid] [--email] [--url] [--affil]` writes a card that binds a post-quantum signing key to its holder's name and identifiers, signed by the key itself under its own context, so a card is never taken for a seal or a key statement, nor they for a card. An ORCID iD must carry its ISO 7064 MOD 11-2 check digit; its orcid.org address is stored as the bare iD. Every field has a byte limit and is refused with a control character or invalid UTF-8. `noqtis idcard --verify <card> [-p <key.pub>]` checks a card and prints who it names and the SHA-256 of its key. The library has `nqcard` and `nqcardvrfy` (`nqcard(3)`); the format is in `noqtis-capsule(5)` and the spec's section 13.
- `noqtis check --card <file>`: when the card verifies and is for the key that made the seal, a `card` row names who sealed the folder (`--json` adds the fields); otherwise the row fails and says why.
- The Python (`idcard`, `idcheck`), JavaScript (`idcard.make`, `idcard.verify`), R (`nqidcard`, `nqidcheck`), Rust (`card::make`, `card::verify`), Go (`MakeCard`, `VerifyCard`) and Java (`IdCard.make`, `IdCard.verify`) bindings make and check cards; each guide has a section, which CI runs. `docs/examples/guide.py` now runs every program of the Python, R and JavaScript guides, not only the first.
- Tests: `tcard` refuses every changed byte of a card, cards signed for fields out of limits, another key, and signatures made under the seal and key statement contexts (and a seal and a statement signed under the card's); `fcard` fuzzes the card reader.
- `noqtis check <url>` follows a redirect only on the same server (host and port, or http on 80 to https on 443) and refuses any other, so a server can no longer make the fetch reach a host only the checking machine reaches (localhost, the local network). Code scanning flagged the redirect handling; a test server confirmed the redirect was followed to another host.
- `noqtis hash -c` refuses a listed name that is not a regular file (a folder, a FIFO, a device) without opening it: a list could otherwise make it wait forever on a FIFO or read /dev/zero to no end.
- Bounded copies where code scanning asked for them: the temporary folder of `noqtis check <url>` and a redirect's URL are written with `snprintf` (both were already length-checked), and `noqtis export --as bagit` reads the date with `gmtime_r` (`gmtime_s` on Windows) instead of `gmtime`, which is not thread-safe.
- The RPM spec owns the zsh and fish completion folders, so the openSUSE builds (Tumbleweed, 16.0) pass their file-list check.
- Releases: a pushed tag only builds, tests and dry-runs the PyPI and npm packages; they are uploaded when the GitHub release is published, from a fresh build of the tag. The ClusterFuzzLite base image is pinned by digest, and the README shows a badge for each place NOQTIS is published.

# noqtis 0.1.1

The first release. (0.1.0 reached npm alone, from an earlier commit, by a
mistake in the release process; use 0.1.1.)

- One C11 library (`libnoqtis`, header `noqtis.h`) with no dependencies:
  ML-DSA (FIPS 204), SLH-DSA (FIPS 205), ML-KEM (FIPS 203), HQC, SHA-2
  and SHA-3, checked against the NIST test vectors.
- The `noqtis` command: `keygen`, `sign`, `verify`, `enc`, `dec`, `hash`,
  `seal` and `check` (capsules: a folder sealed with a post-quantum
  signature), `algs` and `version`, with manual pages.
- Release archives for Linux (x86-64, arm64; static or shared), macOS
  (arm64, x86-64) and Windows (x64, ARM64), with SHA256SUMS, Sigstore and
  SSH signatures, an SPDX SBOM and SLSA provenance; `install.sh` and
  `install.ps1` check them before they install.
- Ed25519 (RFC 8032: Ed25519, Ed25519ctx, Ed25519ph; keys of small or
  mixed order refused) and hybrid signatures ML-DSA-44/65/87+Ed25519,
  which need both parts to verify and can seal capsules; Ed25519 alone is
  refused for seals. Tested with the RFC 8032 vectors, all 210 Wycheproof
  Ed25519 cases, byte-identical signatures against OpenSSL 3.5 and a
  constant-time check under valgrind.
- Capsule format 2 (`noqtis seal --format 2`, `nqseal2`): a Merkle tree
  (RFC 9162) over the file entries, with the seal over the manifest's
  head, so that `noqtis prove` (`nqprove`) can show some files to a
  reader without the names or digests of the others, and `noqtis check
  --proof` (`nqchkp`) checks such a proof alone or against the files.
  `check --only` checks some files of any capsule, and says so.
  `seal --input` records the capsules one was made from, by id
  (`nqcapid`), and `check --lineage` finds and checks them, to 64 levels
  (`nqchkx`). Format 1 is unchanged and stays the default; the spec has
  the new sections 11.1 to 11.6, with a worked example.
- `noqtis export` describes a checked capsule in other formats: an
  in-toto Statement v1 of its files (`--as intoto`), that statement in a
  DSSE envelope signed with a post-quantum key (`--as dsse`, `nqdsse`;
  `noqtis verify --dsse`, `nqdssevrfy`, checks one), RO-Crate 1.1
  metadata (`--as rocrate`) and a BagIt 1.0 bag with a checked copy of
  every file (`--as bagit`).
- `noqtis inspect` and `nqinsp` showed a format 2 capsule's meta as
  empty: its length was read after the buffer holding it was freed.
- Key statements: `noqtis rotate` (`nqkstmt`) says that a seal key was
  replaced by another, signed by both, and `noqtis revoke` that it must
  no longer be trusted, from a given time. `noqtis check -p <key.pub>
  --keys <file>` follows them: a seal by a key the trusted one was
  rotated to passes, and one by a key since rotated away or revoked
  only with a verified timestamp from before then.
- The bindings have the capsule format 2 API (seals with inputs,
  ids, proofs, partial and lineage checks, key statements, a
  manifest's files) and DSSE envelopes:
  - Python: `seal(format=2, inputs=)`, `capid`, `prove`, `files`,
    `check(only=, lineage=, keys=, proof=)`, `rotate`, `revoke` and
    `noqtis.dsse`;
  - JavaScript: `capsule.seal({ format, inputs })`, `capsule.id`,
    `capsule.prove`, `capsule.files`, `capsule.check({ only, lineage,
    keys, proof })`, `capsule.rotate`, `capsule.revoke` and `dsse`;
  - R: `nqseal(format = 2, inputs = )`, `nqcapid()`, `nqprove()`,
    `nqfiles()`, `nqcheck(only =, lineage =, keys =, proof =)`,
    `nqrotate()`, `nqrevoke()`, `nqdsse()` and `nqdsseverify()`, and
    Ed25519 and the hybrids in `nqkeygen()`, `nqsign()` and
    `nqverify()`.
- `noqtis check <url>` checks a capsule where it is published, over
  http:// or, with the TLS client, https://: the seal and the manifest
  are fetched and checked first, and only then the listed files, each at
  most its listed size, into a temporary folder that is checked as any
  other and emptied after; `--only` fetches only those files, and a
  `--proof` may be a URL too. `nqfiles` lists a capsule's files for it.
- Cross-checked against OpenSSL 3.5 or later (`tests/ossl/`, workflow
  `ossl.yml`): the same ML-DSA, SLH-DSA and ML-KEM keys, signatures,
  ciphertexts and secrets from the same seeds, the same digests and
  HMACs, and RSA/ECDSA signatures OpenSSL makes accepted, changed ones
  refused; a differential fuzzer (`fuzz/ossl/fdiff.c`) and a fuzzer of
  the command line's arguments (`fuzz/fcli.c`) run with the others, as
  does `fuzz/fproof.c` over proofs. The capsule fuzzer (`fuzz/fcap.c`)
  had not been fuzzing: its fixture folder was never written, so every
  input returned at once. It now writes it, and a target whose set-up
  fails stops instead of passing.
- A root certificate given as a trust anchor (`--anchor` for timestamps,
  and the TLS client's roots) may have a serial number of 0 or a negative
  one, as some old roots do: an anchor is the user's own choice and its
  serial only a label. Intermediate and leaf certificates must still
  have a positive serial (RFC 5280 4.1.2.2); every other field of an
  anchor is read as strictly as before.
- `nqsealwhy` says why a folder cannot be sealed (a link, a special
  file, a refused name, a case clash or a secret key file, with its
  path), and `noqtis seal` uses it: every refusal used to be reported as
  a secret key in the folder, and a key pair that is not one now says so.
- The constant-time check (ctgrind: secrets marked undefined to valgrind)
  now runs in CI on every push, on gcc and clang Release builds; before,
  CI ran the same tests only as ordinary tests.
- `noqtis sign` checks each new signature with `<key>.pub` when that
  file is there, and writes nothing if it does not verify (a wrong pair,
  or a fault while signing).
- HQC is marked experimental: it follows the HQC specification of
  2025-08-22, which NIST selected in March 2025 but has not yet published
  as a final standard, so its encoding may still change. ML-KEM is the
  KEM to use for anything that must last.
- The TLS client also offers P-256 and P-384 (secp256r1, secp384r1) in
  supported_groups, after X25519MLKEM768 and X25519, and answers a
  HelloRetryRequest for either with a fresh key share, so a server that
  speaks only those groups now connects. The ECDH behind it
  (`src/cls/ec.c`) is new: a fixed 4-bit window with a constant-time
  table select, checked under valgrind (`tests/tecdhct.c`) and against
  OpenSSL and the RFC 8448 trace; a server share that is compressed, off
  the curve or the wrong length is refused.
- Name constraints (RFC 5280 4.2.1.10) are checked on every path:
  before, a CA with the (always critical) nameConstraints extension
  was unusable, so the TLS client and the timestamp checks failed on any
  path through one. Permitted and excluded subtrees of DNS names (also
  in the leading-dot form), IPv4 and IPv6 addresses with masks,
  directory names and mail addresses bind every certificate below the
  CA, the anchor's too, except a self-issued intermediate; they apply to
  the subjectAltName and the subject, never the common name. A
  constraint on another form fails a certificate only when it has a
  name of that form. A subtree with a minimum or a maximum is refused.
- The TLS client asks for a stapled OCSP response (RFC 8446 4.4.2.1,
  RFC 6066 status_request) and checks one it gets with the OCSP code of
  `src/der`: a revoked certificate fails with certificate_revoked, a
  response that does not check (wrong signer, stale, about another
  certificate) with bad_certificate_status_response. No response is
  fine, unless the certificate is must-staple (TLS Feature, RFC 7633).
- Certificate Transparency for the TLS client, opt-in: `nqtlct` gives it
  a log list (Chrome's `log_list.json`, v3), and the tool reads one from
  the file `NOQTIS_CT_LOGS` names. The server's certificate must then
  carry SCTs, embedded or sent in TLS, that verify (ECDSA P-256 or RSA,
  over the certificate or the precertificate) and come from logs of two
  operators that were usable when they signed. Off without a list,
  since a list goes stale.
- Shell completions for bash, zsh and fish (`cli/completions/`, installed
  with the tool; a test checks they offer every command and option the
  manual pages list).
- A Void Linux template (`packaging/void/`), built and tested in CI like
  the other recipes; CI also runs the tests on OpenBSD, NetBSD, 32-bit
  ARM (armv7, under QEMU) and WASI (wasi-sdk, under wasmtime; temporary
  file names there use random bits, as WASI has no process ids), and
  PyPI wheels for Linux ppc64le, s390x and riscv64 are built under QEMU.
- The shared library versions its symbols (`NOQTIS_0`, `src/noqtis.map`,
  on ELF systems) and exports nothing else; CI compares its ABI with the
  last release (libabigail, `packaging/abi.sh`), and each release
  carries the report (`noqtis-<ver>-abi.txt`).
- Releases carry the side-channel results (`noqtis-<ver>-sidechannel.tar.gz`:
  dudect and simulated TVLA on the release build).
- A Rust crate (`bindings/rust`, `noqtis`) with the library compiled in by
  its build script (the `cc` crate, no bindgen): signatures, KEMs,
  hashes, capsules (format 1 and 2, proofs, lineage, inspect) and the
  CLI's key files; tested on Linux, macOS and Windows (`rust.yml`).
- A Go package (`bindings/go`, cgo) with the library compiled in from a
  vendored copy (`tools/vendor.sh`; CI checks it is current): the same
  API as the Rust crate; tested on Linux, macOS and Windows (`go.yml`).
- Java bindings (`bindings/java`) over the shared library with the
  Foreign Function and Memory API (JDK 22 or later; no JNI code to
  build): the same API as the Rust crate; tested on Linux, macOS and
  Windows (`java.yml`).
- Hardened after a manual security review before release:
  - a seal's context must be `noqtis-capsule-1`, so a signature made for
    anything else (a plain `noqtis sign` of the same bytes) is never
    taken for a seal;
  - `noqtis.json` and `noqtis.sig` are opened without blocking (a FIFO
    under either name no longer hangs `check`, `inspect`, `timestamp` or
    `seal`) and written to a temporary file that is then renamed, so a
    hard link is replaced, never written through, and a reader sees the
    old file or the new one;
  - duplicate JSON keys are found by sorting, not by a scan per key (a
    seal of many keys no longer costs minutes of CPU);
  - an OCSP response without nextUpdate counts as current for at most 7
    days;
  - `keygen --seed <hex>` warns that the command line is visible to other
    users; the timestamp guide and `noqtis-capsule(5)` say that a TSA's
    certificate is checked at genTime and not for revocation.
- Hardened after three more reviews (capsule and CLI, network and
  install, crypto API and bindings):
  - files are opened folder by folder from the capsule folder (`openat`
    with `O_NOFOLLOW` at every step; on Windows the opened file's final
    path must lie inside the folder), so a folder swapped for a link
    while a seal or check runs is refused instead of followed;
  - a listed file whose size differs is reported without being read, and
    no file is read past one byte more than its listed size (a 1 TiB
    sparse file no longer costs hours);
  - `seal` refuses a folder that holds a noqtis secret key, and an
    interrupt while `seal --tsa` waits removes the new seal;
  - a TSA request has 120 s in all, name lookup included;
  - text from file names and servers is printed with control characters
    escaped;
  - `check -p` also pins the key file's algorithm; an option given twice
    is refused; inputs are size-limited (1 GiB for a message); a file
    given where a folder is expected exits 2; `.pub` files are 0644 and
    secret keys 0600 whatever the umask; `sign` warns when asked to sign a
    capsule manifest;
  - `install.sh` and `install.ps1` check the release's SSH signature by
    default (with `ssh-keygen`, or cosign), take plain http only for
    `127.0.0.1`/`localhost` with the host parsed whole, and follow no
    redirects there; the GitHub Action runs `check` once;
  - the library: SLH-DSA signs in place correctly (sig may overlap msg),
    a keygen seed may overlap the key outputs, a failed signature keygen
    clears its outputs, and a hash context changed by its holder is
    refused (`NQESTATE`) instead of followed out of bounds.
- The OSS-Fuzz integration is checked with OSS-Fuzz's own tools every week
  (`ossfuzz.yml`), and ClusterFuzzLite fuzzes the code a pull request
  changes and, weekly, every target for an hour (`cflite.yml`).
- `acvp/run.sh` answers every ACVP request in a folder with the right
  harness, as a lab's ACVP client saves them, and the site has a
  Validation page on how an accredited lab would run ACVP against
  noqtis. There is no CAVP or CMVP certificate; this is lab-ready only.
- Bounded CBMC proofs of the parsers of untrusted bytes (`proofs/cbmc/`,
  workflow `cbmc.yml`): the DER reader, the base64 decoder and the JSON
  reader have no access out of bounds, overflow or undefined shift for
  every input up to the sizes `proofs/cbmc/README.md` gives.
- Android and iOS are tested in CI (`mobile.yml`): the library's tests
  run on an Android x86-64 emulator and on an iOS simulator; Android
  arm64 is built. Neither has the command-line tool.
- `nqwipe` uses C23's `memset_explicit` when the library is built as C23
  (`-DCMAKE_C_STANDARD=23`) on a C library that has it, and the volatile
  stores elsewhere; the default build stays C11. CI builds and tests the
  C23 path (job `c23`).
- Each release carries a reproducible source tarball, `noqtis-<version>.tar.gz`.
  Publishing a release (`publish.yml`) updates the Homebrew taps
  (`brew install rootcoder007/noqtis/noqtis`, and the `rootcoder007/morie`
  tap), pushes the container image to
  `ghcr.io/rootcoder007/noqtis`, and checks that the Go module proxy has the
  Go binding's version; r-universe builds the R package from each release.
- Java: the jar may carry the library itself (`native/<os>-<arch>/`), and
  loads that copy when no library is named; the jar on Maven Central
  (`io.github.rootcoder007:noqtis`) carries it for six platforms. A
  published release also goes to crates.io, Fedora COPR and the openSUSE
  Build Service (`publish.yml`).
- Every binding guide is run in CI and must print what its page shows
  (`docs/examples/guide.py`).
- Not yet audited: do not rely on it for anything that matters.
