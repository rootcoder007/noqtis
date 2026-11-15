# The rOpenSci general standards (G1.0 to G5.12) in this package

How the R package `noqtis` meets each general standard for statistical
software (rOpenSci, "Statistical Software Peer Review", version 0.2),
or why one does not apply. Most functions take bytes, keys, algorithm
names and paths rather than numbers or tables; the functions that do
statistics on data are the data record's: `nqdpin()`, `nqdrift()`,
`nqdcal()`, `nqschema()`, `nqschk()`, `nqdschk()`, `nqdiff()`,
`nqdsyn()` and `nqdcheck()`.

- G1.0: met. The help pages of the cryptographic and timestamp functions cite their standards under References (FIPS 203, 204 and 205, RFC 8032, 7693, 9106, 3161, 4998, 4648, the HQC specification); `nqschema()` names RFC 4180 in its text; `nqdpin()` and `nqdrift()` name the tests they run and point to noqtis-drift(1), which cites them.
- G1.1: met. The package help page, section "Algorithms", says the package implements published standards and existing statistics in its bundled C library and no new algorithm.
- G1.2: met. The package help page has a "Life cycle" section; README.md states the audit status.
- G1.3: met. The statistics are named and defined where they are used: `nqdpin()` and `nqdrift()` define the summaries and tests (quantile sketch, population stability index, Jensen-Shannon divergence, chi-square of homogeneity, Benford's test) and the thresholds; `nqdcal()` defines what calibration records.
- G1.4: met. Every exported function has roxygen2 documentation with an example that runs.
- G1.4a: met. Every internal function has a roxygen2 block ending in `@noRd`.
- G1.5: does not apply: the package makes no performance claim in a publication.
- G1.6: does not apply: no performance claim compared with other R packages is made.
- G2.0: met. Each argument's length is asserted by the shared checks in R/util.R (`.is1()`, `.count1()`, `.flag1()`, `.path1()`, `.file1e()`) and the C glue, which refuse a vector where one value is wanted.
- G2.0a: met. Each `@param` says "one string", "a raw vector", "one number" or "names ..." for every argument.
- G2.1: met. Types are asserted before any work: raw vectors (`.rawarg()`), strings (`.is1()`), whole numbers (`.count1()`, `.u32()`, `.u53()`), logicals (`.flag1()`), data frames (`nqdenv()`'s `pkgs`).
- G2.1a: met. Each `@param` states the type it takes; messages name the argument and the type wanted.
- G2.2: met. A vector of length other than one is refused for every argument documented as one value (tests in test-util.R, test-stream.R, test-capx.R).
- G2.3: met. Character arguments with a fixed set of values use `match.arg()` (`kind`, `format`); algorithm and hash names are matched without regard to case.
- G2.3a: met. `match.arg()` for `kind` in `nqwritekey()` and `nqdcommit()`, `format` in `nqdcite()` and `nqdreport()`.
- G2.3b: met. Algorithm and hash names are compared with `toupper()` and `tolower()`; the documentation says case is ignored.
- G2.4: met. Values are converted explicitly before they reach C, as below.
- G2.4a: met. Counts and lengths go through `as.integer()` (`nqblake2b()`, `nqargon2id()`, `nqbox()`).
- G2.4b: met. Costs, seeds, offsets and chunk sizes go through `as.double()` (`nqargon2id()`, `nqpwenc()`, `nqdsyn()`, `nqdchunk()`, `nqdpiece()`).
- G2.4c: met. `nqdenv()` converts each `pkgs` column with `as.character()`; strings are passed as UTF-8 with `enc2utf8()`.
- G2.4d: does not apply: no function takes or returns a factor.
- G2.4e: met. A factor column of `nqdenv()`'s `pkgs` is taken as its labels through `as.character()` (tested in test-capx.R).
- G2.5: does not apply: no input is a factor.
- G2.6: met. One-dimensional inputs (raw vectors, strings) are used through their values only: a string message becomes its UTF-8 bytes (`.bytes()`), and attributes play no part.
- G2.7: met for the one tabular input, `nqdenv()`'s `pkgs`: any data frame, including tibbles and data.tables (they are data frames). The data functions take CSV files, read by the C library, not R tables.
- G2.8: met. `nqdenv()` takes the three columns it needs, converts them to character and passes nothing else on.
- G2.9: does not apply: no conversion loses information (factor labels are what the record stores).
- G2.10: met. Columns of `pkgs` are taken by name with `[` on the three names, the same for data frames, tibbles and data.tables.
- G2.11: met. Columns of any atomic class are converted with `as.character()`.
- G2.12: met. A list column in `pkgs` is refused with a message (tested).
- G2.13: met. Missing values are refused in R arguments (`NA` is refused by every check in R/util.R); in CSV files, `""` and `NA` are the documented missing values, counted and recorded by `nqschema()` and `nqdpin()`.
- G2.14: met. In CSV data, missing values are part of the schema (`nulls`) and of each column's counts; a missing value where the schema forbids one fails the check.
- G2.14a: met. A missing value is an error for every R argument, and a failed row for a CSV column whose schema says it has none.
- G2.14b: does not apply: missing values are never ignored silently; they are counted.
- G2.14c: does not apply: no value is imputed; the record pins the data as it is.
- G2.15: met. The C library counts missing values apart before any statistic; the R code calls no base function with `na.rm` on data.
- G2.16: met. `NaN`, `Inf` and `-Inf` are refused for every numeric argument (`.count1()`, `.u32()`, `.u53()`); in CSV data, a column holding `Inf` or `NaN` is inferred as text, not as a number (both tested in test-edge.R).
- G3.0: met. The R code compares numbers for equality only to test that a value is whole (`v == floor(v)`); the tests compare statistics with a relative tolerance (test-data.R): the Kolmogorov-Smirnov statistic against R's `ks.test()` run in the test, the chi-square values against those `chisq.test()` gave, stored in fixtures/nqd/drift/expect.txt.
- G3.1: does not apply: no covariance is computed.
- G3.1a: does not apply: no covariance is computed.
- G4.0: does not apply: the files written (key files, bundles, sealed streams, records) have formats of their own with no required suffix; each is written under the exact name given, as the command-line tool writes it, so the two read each other's files.
- G5.0: met. The tests use published known answers: NIST ACVP records for ML-DSA with an external mu, RFC 7693 and the BLAKE2 reference's BLAKE2b answers, RFC 9106 and OpenSSL's Argon2id answers, and the repository's own known answers for passphrase-protected keys, sealed messages and sealed streams, which were recomputed apart with OpenSSL and Python's `cryptography` (tests/testthat/fixtures/kat.txt, copied from the repository's tests/vectors; their sources are listed in tests/vectors/SOURCES.md there); and the repository's golden capsule (inst/extdata/capsule).
- G5.1: met. The known answers ship with the package's tests (tests/testthat/fixtures) and the golden capsule in inst/extdata, both in the source package; every example builds its own data.
- G5.2: met. Errors are tested with `expect_error()` and the message they must carry, in every test file.
- G5.2a: met. Each `stop()` call in R/ has its own message; checks used by several functions are one helper with one message that names the argument (`.path1()`, `.file1e()`, `.bundle1()`).
- G5.2b: met in part. Most `expect_error()` calls give a pattern the error message must match; some, mostly refusals of damaged or invalid input by the C library, check only that an error is raised. The package raises no warnings (no `warning()` in R/, no `Rf_warning()` in the C interface), so no test checks a warning message.
- G5.3: met. Tests check that returned values hold no missing values where none may appear (`nqdpkgs()`, keys, digests and signatures of fixed lengths; test-capx.R).
- G5.4: met. Correctness is tested against fixed known answers (G5.0) and, for the drift statistics, against R's `ks.test()` on the same data and the values `chisq.test()` gave for it (fixtures/nqd/drift, made by tests/nqd/drift.R in the repository; test-data.R).
- G5.4a: does not apply: no method is new.
- G5.4b: met. The statistics are compared with R's implementations; the cryptography with the published answers of other implementations (ACVP, OpenSSL, the BLAKE2 reference).
- G5.4c: met. Stored values come from published answers (ACVP, RFC 7693, RFC 9106) and from the repository's own known answers, which were checked against other implementations (G5.0).
- G5.5: met. Correctness tests use fixed seeds and fixed randomness (`seed =` for keys, `det = TRUE` or `rnd =` for signatures, `seed =` for synthetic data); none depends on R's random number generator, which the package never uses.
- G5.6: does not apply: no parameter is estimated from data.
- G5.6a: does not apply: no parameter is estimated.
- G5.6b: does not apply: no parameter is estimated.
- G5.7: does not apply: the functions' results do not converge with data size; the drift sketch's error bound is tested in the repository's C tests (tests/nqd/kserr.c), not in R.
- G5.8: met. Edge conditions are tested, as below.
- G5.8a: met. Zero-length inputs: an empty message is hashed against its known answer (test-hash.R) and signed and verified (test-sig.R); BLAKE2b and mu are computed over an empty message (test-capx.R); a DSSE envelope is made over an empty payload (test-cap2.R); an empty file is hashed (test-hash.R), and boxed and opened back to an empty file (test-edge.R); the golden capsule holds a zero-length file.
- G5.8b: met. Unsupported types (a number or complex where bytes are wanted, a list where a data frame is wanted) are errors (test-stream.R, test-capx.R, test-util.R).
- G5.8c: met. A CSV column of only missing values and a constant column are inferred, checked and pinned without error (test-capx.R).
- G5.8d: met. Inputs outside the scope (a chunk size out of range, a mu that is not 64 bytes, an algorithm that cannot stream, a stand-in over real data) fail with an error (test-stream.R, test-capx.R, test-edge.R).
- G5.9: met. Noise susceptibility is tested, as below.
- G5.9a: met. Adding noise at the scale of `.Machine$double.eps` to a column does not change the drift verdict (test-capx.R).
- G5.9b: met. Key pairs made with fresh randomness sign and verify (test-sig.R); the same seed gives the same synthetic data twice (test-capx.R); `nqrand()` leaves R's random number state as it was (test-algs.R).
- G5.10: does not apply: the whole test suite runs in every check; there is no extended set.
- G5.11: does not apply: no test downloads data.
- G5.11a: does not apply: no test downloads data.
- G5.12: does not apply: there are no extended tests.
