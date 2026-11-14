# noqtis <img src="man/figures/logo.png" align="right" height="139" alt="NOQTIS hex logo" />

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
