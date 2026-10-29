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
- Not yet audited: do not rely on it for anything that matters.
