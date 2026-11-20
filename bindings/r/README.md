# noqtis <img src="man/figures/logo.png" align="right" height="139" alt="NOQTIS hex logo" />

[![Website](https://img.shields.io/badge/website-noqtis.dev-12706b)](https://noqtis.dev/)
[![ci](https://github.com/rootcoder007/noqtis/actions/workflows/ci.yml/badge.svg)](https://github.com/rootcoder007/noqtis/actions/workflows/ci.yml)
[![coverage](https://github.com/rootcoder007/noqtis/actions/workflows/cov.yml/badge.svg)](https://github.com/rootcoder007/noqtis/actions/workflows/cov.yml)
[![R-CMD-check](https://github.com/rootcoder007/noqtis/actions/workflows/r.yml/badge.svg)](https://github.com/rootcoder007/noqtis/actions/workflows/r.yml)
[![fuzz](https://github.com/rootcoder007/noqtis/actions/workflows/fuzz.yml/badge.svg)](https://github.com/rootcoder007/noqtis/actions/workflows/fuzz.yml)
[![docs](https://github.com/rootcoder007/noqtis/actions/workflows/docs.yml/badge.svg)](https://github.com/rootcoder007/noqtis/actions/workflows/docs.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16049/badge)](https://www.bestpractices.dev/projects/16049)
[![Release](https://img.shields.io/github/v/release/rootcoder007/noqtis?label=release&color=2ea44f)](https://github.com/rootcoder007/noqtis/releases/latest)
[![PyPI](https://img.shields.io/pypi/v/noqtis?label=PyPI&color=3775a9)](https://pypi.org/project/noqtis/)
[![npm](https://img.shields.io/npm/v/noqtis?label=npm&color=cb3837)](https://www.npmjs.com/package/noqtis)
[![crates.io](https://img.shields.io/crates/v/noqtis?label=crates.io&color=f0b400)](https://docs.rs/noqtis)
[![Maven Central](https://img.shields.io/maven-central/v/io.github.rootcoder007/noqtis?label=Maven%20Central&color=6f42c1)](https://central.sonatype.com/artifact/io.github.rootcoder007/noqtis)
[![Go Reference](https://pkg.go.dev/badge/github.com/rootcoder007/noqtis/bindings/go.svg)](https://pkg.go.dev/github.com/rootcoder007/noqtis/bindings/go)
[![r-universe](https://rootcoder007.r-universe.dev/badges/noqtis)](https://rootcoder007.r-universe.dev/noqtis)
[![COPR](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fcopr.fedorainfracloud.org%2Fapi_3%2Fpackage%2F%3Fownername%3Drootcoder007%26projectname%3Dnoqtis%26packagename%3Dnoqtis%26with_latest_build%3Dtrue&query=%24.builds.latest.state&label=COPR%20build&color=2ea44f)](https://copr.fedorainfracloud.org/coprs/rootcoder007/noqtis/)
[![OBS](https://build.opensuse.org/projects/home:rootcoder007/packages/noqtis/badge.svg?type=default)](https://build.opensuse.org/package/show/home:rootcoder007/noqtis)

Seal the exact files behind a result with a post-quantum signature, so
anyone can check later, offline, that nothing changed. The `noqtis` R
package bundles the NOQTIS C library: ML-DSA (FIPS 204) and SLH-DSA
(FIPS 205) signatures, ML-KEM (FIPS 203), SHA-2 and SHA-3, and sealed
folders (capsules). Nothing else to install.

> **Status: unaudited.** The code has not had an external security
> audit; do not rely on it for anything that matters yet.

## Install

```r
install.packages("noqtis", repos = c("https://rootcoder007.r-universe.dev",
                                     "https://cloud.r-project.org"))
```

## Seal a folder, check it

```r
library(noqtis)
d <- file.path(tempdir(), "results")
dir.create(file.path(d, "data"), recursive = TRUE)
writeLines(c("a,b", "1,2"), file.path(d, "data", "in.csv"))

k <- nqkeygen("ML-DSA-65")
nqseal(d, k$sk, k$pk, "ML-DSA-65")
attr(nqcheck(d, k$pk), "ok")
```

The guide, with signatures, KEMs and partial checks:
https://noqtis.dev/guides/r/

## Passphrase keys, streams and sealed files

```r
nqwritekey("me", k$sk, "ML-DSA-65", "sec", pass = "a passphrase")
sk <- nqreadkey("me", pass = "a passphrase")$key
sig <- nqsignfile("big.csv", sk, "ML-DSA-65")   # 64 KiB at a time
nqbox("big.csv", "big.csv.nqk", kem$pk, "ML-KEM-768")
```

`nqsigner()`, `nqverifier()`, `nqupdate()` and `nqfinish()` stream a
message given in pieces; `nqkseal()` and `nqkopen()` seal a message to
an ML-KEM key, `nqunbox()` opens a file; `nqmu()`, `nqsignmu()` and
`nqverifymu()` are ML-DSA with an external mu; `nqblake2b()`,
`nqargon2id()`, `nqcteq()`, `nqpwenc()` and `nqpwdec()` the primitives.
`nqinspect()`, `nqsealwhy()`, `nqtsreq()`, `nqtsput()`, `nqersreq()`,
`nqersput()`, `nqpack()`, `nqunpack()`, `nqcheckpack()` and `nqchain()`
reach the rest of the capsule functions; `nqdparse()`, `nqdschk()`,
`nqdsyn()`, `nqdcal()`, `nqdchunk()`, `nqdpiece()`, `nqdcommit()`,
`nqdreveal()`, `nqdcite()`, `nqdreport()` and `nqdenv()` the rest of
the data record (`nqdenv()` records R and its loaded packages).

`nqkt()` is KangarooTwelve (RFC 9861); `nqsivenc()` / `nqsivdec()`
AES-SIV (RFC 5297) and `nqgsivenc()` / `nqgsivdec()` AES-GCM-SIV (RFC
8452), authenticated encryption; `nqchacha20()` the ChaCha20 stream of
RFC 8439, which is not authenticated.

## Citation

> Ruhela, V. S. (2026). *NOQTIS: Notary of Quantum-Safe Traceable Inputs
> and Seals.* <https://github.com/rootcoder007/noqtis>

[CITATION.cff](https://github.com/rootcoder007/noqtis/blob/main/CITATION.cff)
in the repository holds the same reference, with the version, for
reference managers.
