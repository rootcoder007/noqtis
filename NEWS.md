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
- Not yet audited: do not rely on it for anything that matters.
