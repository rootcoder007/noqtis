# ACVP harnesses

One program per algorithm family. Each reads an ACVP request (the
"prompt" JSON of one vector set, as an ACVP server or a CAVP lab's
client hands it over) and writes the ACVP response for that vector set,
computed by the noqtis library itself. They are built with the tests
(`-DNQTESTS=ON`, the default) and land in `build/acvp/`.

| Program | ACVP algorithm, revision | Modes and tests |
|---|---|---|
| `acvsh` | SHA2-224, SHA2-256, SHA2-384, SHA2-512, SHA2-512/224, SHA2-512/256 (1.0); SHA3-224 ... SHA3-512 (2.0); SHAKE-128, SHAKE-256 (FIPS202) | AFT, MCT (SHA-2 standard and alternate; SHA-3 standard), LDT, SHAKE VOT and MCT |
| `acvhm` | HMAC-SHA2-224 ... HMAC-SHA2-512/256, HMAC-SHA3-224 ... HMAC-SHA3-512 (2.0) | AFT, truncated tags |
| `acvdr` | hmacDRBG (1.0), modes SHA2-256 and SHA2-512 | AFT, with and without prediction resistance and reseed |
| `acvmd` | ML-DSA (FIPS204) | keyGen; sigGen and sigVer, external (pure and pre-hash, with a context) and internal (message or external mu), deterministic and hedged |
| `acvsl` | SLH-DSA (FIPS205), all twelve parameter sets | keyGen; sigGen and sigVer, external (pure and pre-hash) and internal, deterministic and hedged |
| `acvmk` | ML-KEM (FIPS203), ML-KEM-512/768/1024 | keyGen; encapDecap: encapsulation, decapsulation, encapsulation and decapsulation key checks |

## Running one

```sh
build/acvp/acvmd request.json response.json
```

The request may be the vector set object itself (the form of the
ACVP-Server `gen-val` files in `tests/vectors/acvp/`) or the form a live
server sends, `[{"acvVersion": "1.0"}, {vector set}]`; the response
takes the same form, with the vector set's `vsId`, `algorithm`, `mode`,
`revision` and `isSample` copied from the request and one entry per
test (`tgId`, `tcId` and the results). Hex is written in upper case.

With a third argument, an expected-results file, the program also
compares its response with it: the same tests, and in each the same
fields with equal values (key order and hex case do not matter). This
is how `ctest` checks every harness against every vector set in
`tests/vectors/acvp/` (tests `acvp-*`).

The exit status is 0 when the response was written (and, with expected
results, matches them) and 1 otherwise. A test the harness cannot
answer (a missing or malformed field) stops it with a message naming
the `tgId` and `tcId`, and no response is written.

## With a CAVP lab

1. Register the capabilities the module claims: the algorithms, modes,
   parameter sets and lengths in the table above. Do not register
   SHA-3 with the alternate Monte Carlo test, or HMAC_DRBG with hashes
   other than SHA2-256 and SHA2-512: noqtis does not provide them, and
   the harnesses leave such groups out of the response with a message.
2. For each vector set the lab's ACVP client downloads, run the
   harness for its algorithm on the request file and give the response
   file back to the client to upload.
3. Run the harnesses with `NQFAST` and `NQSLSUB` unset. Those variables
   are the test suite's sampling switches: `NQFAST=1` leaves out the
   large-data hash tests (`acvsh`) and three of every four SLH-DSA "s"
   signing tests (`acvsl`); `NQSLSUB=k` answers only every k-th
   SLH-DSA test. A harness that left tests out says so on stderr ("not
   a complete response"); such a response is not for submission.

Signing an SLH-DSA "s" parameter set takes seconds per test, and the
large-data hash tests hash up to 8 GiB each, so a full run of those
vector sets takes minutes.

ML-DSA signing goes through the library's masked signer and ML-KEM
decapsulation through its masked decapsulation, the code paths the
public API uses. A signature or key check that fails for any reason
(it does not verify, it does not decode, a length is wrong) is answered
`"testPassed": false`.
