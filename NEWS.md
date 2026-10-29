# noqtis 0.1.0

The first release.

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
- Not yet audited: do not rely on it for anything that matters.
