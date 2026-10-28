# Test vector sources

- `acvp/`: NIST ACVP-Server, https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
  (folder names unchanged; prompt.json and expectedResults.json per set).
- `wycheproof/`: C2SP Wycheproof, https://github.com/C2SP/wycheproof/tree/main/testvectors_v1
- `hqc/hqc-kat-digests.txt`: SHA-256 digests of the HQC v5.0.0 (2025-08-22)
  reference KAT records, copied unchanged from rmoriebricklayer
  (tests/testthat/hqc-kat-digests.txt, commit 6450ab1); see hqc/SOURCES.md.
