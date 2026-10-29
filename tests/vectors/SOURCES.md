# Test vector sources

- `acvp/`: NIST ACVP-Server, https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
  (folder names unchanged; prompt.json and expectedResults.json per set).
- `wycheproof/`: C2SP Wycheproof, https://github.com/C2SP/wycheproof/tree/main/testvectors_v1
- `hqc/hqc-kat-digests.txt`: SHA-256 digests of the HQC v5.0.0 (2025-08-22)
  reference KAT records, copied unchanged from rmoriebricklayer
  (tests/testthat/hqc-kat-digests.txt, commit 6450ab1); see hqc/SOURCES.md.
- `wycheproof/` also holds the RSA PKCS#1 v1.5, RSA-PSS and ECDSA (P-256, P-384, P-521; DER and P1363) sets used by `tests/tcls.c`, from the same C2SP testvectors_v1 folder.
- `ossl/cls.json`: OpenSSL 3.5 differential set for `tests/tcls.c`: keys and signatures made by `openssl`, plus mutated copies, each with OpenSSL's own verdict; `ossl/gen.py` regenerates it (`python3 -I gen.py <workdir> <out.json>`, fixed seed 20261028).
- `der/`: certificates, OCSP responses, CRLs and RFC 3161 tokens for `tests/tder.c`, `tests/tx509.c` and `tests/ttsp.c`: a local PKI made by `der/gen.sh`, real public TSA tokens, and files from rmoriebricklayer; see `der/SOURCES.md`.
- `cavp/sha1/`: NIST CAVP SHA-1 byte-oriented vectors (SHA1ShortMsg.rsp, SHA1LongMsg.rsp, SHA1Monte.rsp, CAVS 11.0/11.1), unchanged from shabytetestvectors.zip, https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip (fetched 2026-10-28, zip SHA-256 929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8), used by `tests/tsha1.c`.
- `cap/`: the golden capsule `sample/` for `tests/tcap.c` (ML-DSA-44 key from seed 00..1f, all-zero signing randomness, fixed creation time; `tcap gen` regenerates it) and `tsa/`, a throwaway OpenSSL 3.5 TSA root, a same-subject other root and a token over the sample's signature, made by `cap/tsa.sh`.
- `interop/bl/`: made by rmoriebricklayer 1.0.3 with `tests/interop/gen.sh` (one run; every run makes new keys): `mldsa/` and `slh/`, capsules in the noqtis format sealed with its ML-DSA-65 and SLH-DSA-SHA2-128s signatures (`tests/interop/blseal.R`; the SHA3-256 digests come from `noqtis hash`, since rmoriebricklayer has none), with their public keys `mldsa.pub` and `slh.pub`; and `bundle/`, one of its own `capsule_bundle.json` bundles with the exact bytes its attestation signed, the signature, the key and the file digests taken out of it (`tests/interop/blbndl.R`). Used by `tests/cli/tcli.c`.
