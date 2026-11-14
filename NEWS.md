# Unreleased

- The data layer, nqd: a library of its own (`include/nqd.h`, `nqd/`, `-lnqd`) on the public API of noqtis only, outside the audited core, which is unchanged. A capsule can now carry a data record, `noqtis.data.json` (format `noqtis-data-1`, `noqtis-data(5)`): where each file came from (URL, portal resolver, retrieval time, ETag and Last-Modified, licence, publisher, an archived copy, mirrors, a flag for synthetic stand-ins), the schemas of its CSV files, column summaries for drift checks, the environment, the steps applied, the results of checks made elsewhere, sealed commitments and how to cite it. The record is canonical JSON (RFC 8785), so every binding writes the same bytes, and an ordinary file of the capsule: the manifest lists it and the seal covers it. Its reader is strict: an unknown member, a key given twice, a wrong type, a missing required member or a non-canonical file is refused with a sentence that names the member (`sources[0].sha256: must be 64 lower-case hex digits`). `noqtis data init|add|put|del|fmt|show|check` makes and checks it; `check` compares every source file with its recorded SHA-256 (in constant time) and size, and lists recorded checks that failed. The library has `nqdnew`, `nqdparse`, `nqdload`, `nqdjson`, `nqdsave`, `nqdrfree`, `nqdlen`, `nqdat`, `nqdput`, `nqdset`, `nqddel`, `nqdsrc` (`nqdnew(3)`) and `nqdchk` with its report (`nqdchk(3)`). Tests: `tdrec` (the RFC 8785 number examples, the reader's refusals, the record API) and `tdcli` (the commands from a POSIX shell); a fuzz target `fdrec` checks that every record read writes and reads back to the same bytes. CMake option `NQDATA` (on; the tool needs it).
- CSV schemas: `noqtis schema infer [--put]` reads a CSV file (RFC 4180: any one-byte delimiter, LF or CRLF, quoted fields with doubled quotes and line breaks, a UTF-8 byte order mark) and pins its schema in the data record: the columns, the narrowest type of each (bool, int, real, date, text; a leading zero keeps a code text), missing values, the row count and, with `--ranges`, each number and date range. `noqtis schema check` (and `noqtis data check`) checks the files against it: the header, each line's fields, types, missing-value codes, ranges and sets, and declarative rules (`unique` over one or more columns, `notnull`, `range`, `set`, `incr`, `complete`, `distinct`, `rows`, `cols`), naming the line of the first problems. The reader is strict and bounded (a quote inside an unquoted field, text after a closing quote, a lone carriage return, invalid UTF-8 or a NUL is refused with its line; a field 1 MiB, a line 16 MiB or 16,384 fields), with no locale. The library has `nqdinfer` and `nqdschk` (`nqdinfer(3)`); `tdcsv` tests the reader, the types and every rule, and a fuzz target `fdcsv` reads any bytes.
- `noqtis diff <dir> <dir>` says what changed between two capsules: the files added, removed or changed between their manifests, and in their data records the sources (field by field), schemas (columns added, removed or retyped, row bounds), summaries (counts, medians, the population stability index between the two), environment, steps, checks, commitments and citation; exit 1 when something differs, `--json` for a machine. The library has `nqddiff` (`nqddiff(3)`), which reads the manifests through the public `nqfiles`.
- `noqtis seal -r` and `noqtis check -r` work on every capsule under a folder: `seal -r` seals each folder that holds a manifest or a data record, deepest first so a capsule inside another is sealed before it; `check -r` checks each sealed folder with the same options and counts them on standard error. The search stops 64 levels down and never follows a link: it walks by descriptor (`openat` with `O_NOFOLLOW` from the folder above), and each folder is reached the same way again when its turn comes, so a folder replaced by a link between the listing and the run is refused rather than sealed or checked through.
- Drift without keeping the data: `noqtis drift pin` records, per CSV file, summaries of a fixed size in the data record (a quantile sketch of 1,001 points, exact up to 1,001 values; the population stability index's decile bins and counts; first-digit counts; the 1,000 most frequent values of a categorical column), and `noqtis drift check [<file>=<current-file>]` compares a later file with them: the two-sample Kolmogorov-Smirnov test (exact p-value for small samples without ties, else the Kolmogorov limit), PSI and Jensen-Shannon divergence, the chi-square test of homogeneity for categorical columns and Benford's first-digit test. Exit 0, 1 (a column failed: PSI at or over 0.25 on at least 1,000 values each), 3 (a warning only) or 2, for CI; `--json` gives every number. The statistics match R 4.6.2's `ks.test` and `chisq.test` on the committed vectors to 1e-9 or better (`tests/nqd/drift.R` made them), and the PSI, Jensen-Shannon and Benford values match their definitions written out in R; the sketch's KS statistic stays within its stated error (about 0.001) of the exact one, measured by `tests/nqd/kserr.c` up to a million values (`noqtis-drift(1)`). The library has `nqdstats`, `nqddrift` (`nqdstats(3)`) and `nqdrepj`, the numbers of a report row as JSON; `tddft` tests them, and a fuzz target `fddft` compares any summary with any file.
- `noqtis env` records the environment in the data record: platform, noqtis version, locale, time zone, the random number generator and its seed, and the SHA-256 of lock files (`renv.lock`, `uv.lock`, `Cargo.lock` and others found, or those named).
- Rules: `regex` (`col`, `pattern`) passes a value the pattern matches somewhere (anchor with `^` and `$`); the pattern is a small subset (literals, classes and `\d`, `\w`, `\s`, `.`, anchors, `*`, `+`, `?`, alternation, groups), anything else refused when the record is read, matched over code points by a set of states (Thompson's construction), so a match takes time linear in the value whatever the pattern. `mad` (`col`, `max`) fails a value further from the median than `max` times the scaled MAD (1.4826 times the median absolute deviation, R's `mad()`). `tdrx` checks the matcher against Python's `re.search`, patterns exponential for a backtracking matcher on 200,000 characters, and the MAD rule against R; a fuzz target `fdrx` compiles and runs any pattern.
- `noqtis data check` (`nqdchk`) recomputes what the record holds: a recorded check with numbers holds when |observed - expected| <= `tol` (0 when not given), with strings when they are equal, and one recorded as `pass` that does not hold fails; a step with a `script` and its `sha256` gets a `step` row that checks the file (a recode's mapping, a program); each file's drift summaries are made again and must be the recorded bytes (a `stats` row). A `stats` element keeps its delimiter and a false `header` when not the default, so it is read again the same way, by `drift check` too; `tol` must be at least 0.
- Drift calibration: `noqtis drift cal <dir> <file>=<unchanged-file>...` (`nqddcal`) compares a summary with files known not to have drifted (a re-fetch, the other half of a split) and records per column, as `cal`, the largest PSI and the smallest KS or chi-square and Benford p-values seen; `drift check` then warns of that column only beyond them as well as beyond its levels, and says so; failures do not change. `tddft` checks the recorded values against R's.
- Reports: `noqtis report [-p <key>] [-f md|txt] [-o <file>] [--json] [--github] <dir>` (`nqdrpt`) checks a capsule and its data record once and writes a report: the result and counts, every check, and what the record says (sources, schemas, drift summaries, environment, steps, recorded checks, commitments, citation). A value never breaks its line or table cell: a line break is a space, and in Markdown each markup character gets one backslash. `--json` gives the status, the counts (`failed`, `verified`, `changed`) and every check; `--github` a workflow annotation per failed check. A folder that is not sealed fails.
- Synthetic data: `noqtis data syn --seed <n> [--rows <n>] <dir> <file>` (`nqdsyn`) writes a CSV file from the schema pinned for it (columns, types, ranges, sets, missing values, delimiter, header), the same bytes for the same seed on every platform (draws from SHA-256 in counter mode, by rejection), and records it as a source marked `synthetic`; it never writes over a file not so marked. `tdcli` compares its output with a file made by a separate Python implementation.
- The GitHub Action has a `report` mode, and `check` and `report` run `noqtis report` once, so they also check the data record: each failed check is an error annotation, the Markdown report goes to the job summary, and new outputs give `status`, `verified`, `changed`, `failed` and the `report` file; `json` is now the `noqtis report --json` line. `report` lets the step pass. The action's build cache now covers `nqd/`.
- Sealed commitments: `noqtis commit <dir> <file>` records SHA3-256 of a domain tag, a fresh 32-byte secret salt and the file (a randomisation list, an analysis plan), writes the salt beside the file (owner-only), and `noqtis reveal <dir> <file> <salt>` checks a file against every recorded commitment in constant time; sealed with a timestamp, the commitment is dated. `noqtis cite [--format cff|bibtex]` prints a CITATION.cff or a BibTeX entry from the record's `cite`. The library has `nqdcommit`, `nqdreveal` and `nqdcite` (`nqdcommit(3)`); `tdrec` checks the commitment against Python's `hashlib.sha3_256` over the same bytes.
- A capsule in one file: `noqtis export --as bundle -o results.nqb results` writes a bundle (`noqtis-bundle-1`: the format's line, then each file's path, size and bytes, in byte order of the paths, then an end mark) holding the seal, the manifest, the evidence record when there is one and every listed file, or with `--no-files` only the data record; the same capsule gives the same bytes. `noqtis check results.nqb` checks it as it is: it is read into a temporary folder, checked there (a bundle without its files as a partial check of what it carries) and removed. The reader is strict and refuses a bundle whole, leaving nothing behind: a path a capsule cannot hold (absolute, `..`, a backslash, a colon and so a drive letter, a control character, invalid UTF-8, over 64 folders deep; on Windows a device name), paths out of order or repeated, no seal or manifest, a seal over 1 MiB, a manifest over 512 MiB, a cut bundle or bytes after its end; every file is created new inside the folder, never over a file or through a link. The library has `nqdpack` and `nqdunpack` (`nqdpack(3)`); `tdbnd` tests each refusal and a bundle cut at every byte, and a fuzz target `fdbnd` reads any bytes. The format is in the capsule specification, section 14, and `noqtis-capsule(5)`.
- Reproducibility bundles: `noqtis pack init --template plain|r|python` lays out a project (`data/`, the code folder, `output/`, a README, an empty data record); `pack build -k <key> -o <file>` records the environment and lock files (`noqtis env`), seals and writes the bundle; `pack check` checks, before shipping, the capsule, the data record and that the environment and at least one lock file are recorded; `pack unpack` opens a bundle into a new folder (`noqtis-pack(1)`). `noqtis data check` (`nqdchk`) now also checks each lock file `env` recorded against its SHA-256 (`lock` rows).
- Chunk digests of a large file: `noqtis chunk pin [--size <bytes>]` records in the data record (new member `chunks`: path, size, chunk, digests) the SHA-256 of each run of bytes of a file, read once and never split; `noqtis chunk check [--at <offset>] <dir> <file> [<piece>]` checks a piece of the file (a range fetched alone, the part that survived) without the rest, and `data check` checks the whole file. The library has `nqdchunk` and `nqdpiece` (`nqdchunk(3)`), tested by `tdcnk` against SHA-256 computed apart.
- Chains: `noqtis chain [-p <key.pub>] <dir>...` checks an append-only log of capsules, each sealed with the one before as its only input (`noqtis seal --input prev=<last>`): every link checks, each follows the one before it with no fork or gap, and one key sealed them all; its head is the last link's id. Each link's inputs are read from the head its seal signs and bound to it by its id. Unlike `check --lineage`, it goes one link at a time, at any length. The library has `nqdchain` (`nqdchain(3)`).
- The data layer in the Rust, Go and Java bindings: `noqtis::data`, the Go functions `DataAdd`, `DataPut`, `DataDel`, `DataKey`, `DataText`, `DataCanon`, `DataCheck`, `Schema`, `SchemaCheck`, `Pin`, `Drift` and `Diff`, and the Java class `Data` add sources, put and remove elements, read and check a record, infer and check CSV schemas, pin summaries and check drift, and compare two capsules, as R's `nqd*` functions and Python's `noqtis.data` do. Each binding's tests check a record, a schema, drift statistics and a diff against the values the C tests check on `tests/vectors/nqd`, as the R package's tests now do too. The Rust crate and the Go module compile `nqd/` in; Java loads `libnqd` beside libnoqtis (`-Dnoqtis.nqd`), which the Maven Central jar does not carry yet. The Rust crate builds with `-ffp-contract=off` where the compiler takes it.
- The R package builds with the floating-point flags of the CMake build: a `configure` script (and `configure.win`) adds `-ffp-contract=off`, and on 32-bit x86 `-msse2 -mfpmath=sse`, to `src/Makevars` (made from `src/Makevars.in`), each only when R's C compiler takes it, so a data record's statistics come out to the same bits in R as from the command line.
- Sources, fetched and checked: `noqtis src add --url <url>` or `--portal ckan|socrata|arcgis --base <portal> --id <dataset> [--resource <id>] [--format <fmt>] [--layer <n>]` records a file of a capsule as a source and fetches it when it is not there yet (with its ETag, Last-Modified and time), `--mirror` and `--archived` record copies and `--wayback` pins the Wayback Machine's copy; `src fetch` restores each missing file from the first address that gives the recorded size and SHA-256 (the URL, the portal, each mirror, then the archived copy as raw bytes), says which copy it used and never writes other bytes; `src refresh` fetches each source again and says whether it is unchanged, changed (old and new SHA-256 and size) or unreachable (exit 0, 1, 3), and only with `--write` takes the new bytes and records them; `src resolve` asks each portal where its file is now; `src list` shows the addresses in the order they are tried; `--json` everywhere. Transfers follow at most 5 redirects, to the same server only, take at most `--max` bytes (1 GiB; a fetch its recorded size) and `--timeout` seconds, and resume a cut transfer with an If-Range request when the server allows. The library has the pure parts (`nqdaddr(3)`): `nqdaddr` (a source's addresses in order), `nqdvrfy` (fetched bytes against the record), `nqdfld` (one field of an element), `nqdrslv` and `nqdrsp` (the request to a CKAN, Socrata, ArcGIS or Wayback Machine portal and the reading of its reply) and `nqdwb` (a Wayback copy's raw address); it still makes no network request. The data record's format is unchanged. Tested by `tdsrc` (each portal's request and replies shaped as each documents them, every refusal), `tdcli` (against a local server: the fallback order, other bytes refused, larger and cut replies, redirect loops and redirects away, a resumed transfer, each portal, the Wayback Machine through a test hook) and the fuzz target `fdrsp`.
- The tool reads a reply into a buffer that grows to the limit instead of taking the whole limit at once, and keeps reply sizes in `size_t`: a body's length went through a `long`, 32 bits on Windows, and a TLS reply over 64 MiB from a server that closes without close_notify was refused.
- The GitHub Action has `drift` and `refresh` modes: `drift` checks the folder's files against their pinned summaries, or with `fetch: "true"` the sources fetched again, with `psi-warn` and `psi-fail`; `refresh` fetches each source again and says whether it changed, and with `write: "true"` records the new bytes. `fail-on: error|drift|warn|never` decides when the step fails, each finding is an annotation, the report is a table in the job summary, and `status` (now also `warned`), `changed`, `ok` and `report` say what happened. With any reporting mode, `base-ref` compares the capsule with its copy at another commit (`noqtis diff`; output `differs`), and `comment: "true"` posts the report on the pull request as one comment that later runs update rather than repeat (needs `pull-requests: write`; `token` defaults to `github.token`; `dry-run` writes it to a file). The data steps are POSIX sh in `action/run.sh`; the existing modes are unchanged.

# noqtis 0.1.4

- On Windows, `noqtis.exe` in the release archives (and so `install.ps1`, Scoop and winget) carries its own C runtime: it was linked against the Visual C++ runtime DLL (VCRUNTIME140.dll) and did not start on a Windows without it. The static library in the archives still uses the DLL runtime, as the programs that link it do. The Maven Central jar's Windows libraries carry their runtime too.
- Ed25519 signing (alone and in the ML-DSA + Ed25519 hybrids) is first-order masked: the secret scalar is split into two fresh shares modulo the group order on every call, the public key is the sum of one ladder per share, every ladder starts from the base point in random projective coordinates, and S is computed share by share. `nqsign` hedges the nonce: SHA-512 also takes 32 fresh random bytes, which fill a block with the secret prefix, so a power analysis of the nonce hash never sees the prefix mixed with message bytes (the attack of Samwel et al., CT-RSA 2018). The signatures verify as any RFC 8032 ones; `nqsignd` (and `noqtis sign -d`) still gives RFC 8032's deterministic signature. The simulated TVLA has an Ed25519 target (no leaking point at 10,000 traces) and its masks-zero control.
- SLH-DSA signing and key generation mask PRF, the one function keyed with SK.seed: SK.seed is held as two fresh shares, and every PRF call is a masked SHAKE256 (the SHAKE sets) or a masked SHA-256 compression (the SHA-2 sets), the latter bitsliced over 64 calls at once, with ripple-carry additions on shares. This is the function a differential power analysis of SLH-DSA attacks (Kannwischer et al., SAC 2018); a WOTS+ or FORS secret it outputs meets only its own address afterwards. Signatures are unchanged byte for byte. Masking costs time: about 2.5 times for the SHAKE sets and about 6 times for the SHA-2 sets (SLH-DSA-SHA2-128s: 5.8 s per signature on a laptop core instead of 1.0 s; 128f: 0.34 s instead of 0.05 s); the SHA-2 PRF batches the WOTS+ secrets of 16 key pairs at a time, runs its public first five rounds in the clear and draws its masks from ChaCha12. The simulated TVLA has an SLH-DSA PRF target per family, each with its masks-zero control.
- HQC decapsulation is first-order masked from the key to the shared secret (`src/hqc/mdec.c`): y split afresh into two dense shares; the Reed-Muller decoder on arithmetic shares (Goubin's conversion, the Hadamard transform share by share, a masked peak search); the Reed-Solomon decoder with masked GF(256) products, Berlekamp's degrees and conditions as masked integers, and masked error values; G and J (keyed with sigma, split afresh) as masked SHA-3; the re-encryption with Sendrier's sampler masked (multiply-high, collision repair, the vectors from masked positions); the comparison and the choice of key in shares. It gives the same shared secret as the unmasked decapsulation (`nqhqdecp`) on every ciphertext tested, valid, tampered, random and past the decoder's capacity. HQC-128 decapsulation takes about 22 ms instead of 1.1 ms. The simulated TVLA has an HQC-128 target (no leaking point in 6,008,081 samples) and its masks-zero control.
- Every signature is checked before it leaves the library: `nqsign` and `nqsignd` verify an ML-DSA, SLH-DSA or Ed25519 signature (each half of a hybrid) under the public key held in the secret key, and return the new error `NQEFLT` (-11), with the signature zeroed, when it does not verify. A signature made in a disturbed computation (a voltage or clock glitch, a flipped memory bit) can give away the key (Bindel et al. 2016 for ML-DSA, Castelnovi et al. 2018 for SLH-DSA, Romailler and Pelissier 2017 for Ed25519). ML-DSA checks from the message representative it already has and SLH-DSA from the digest, so the cost is one verification. `tapi` damages a secret key of each kind and expects `NQEFLT` and a zeroed output.
- `nqselftest()` and `noqtis selftest` run known answers for every family (SHA-2, SHA-3 and SHAKE, HMAC, the three ML-KEM sets, the three ML-DSA sets, SLH-DSA key generation, HQC-128, Ed25519 and a hybrid) in about a tenth of a second, the power-on self-test a FIPS 140-3 module runs; a mismatch is the new error `NQEKAT` (-12) and exit status 1. The answers are SHA-256 hashes of every output, made where the test suite checks the same functions against the NIST vectors, and equal to those of 0.1.3. The bindings have the two new errors, and each runs the self-test: `selftest()` in Python and JavaScript, `noqtis::selftest()` in Rust, `SelfTest()` in Go, `Noqtis.selfTest()` in Java and `nqselftest()` in R.
- A freestanding build, `cmake -DNQFREE=ON`, for firmware, kernels and other places with no operating system: the algorithms alone (hashes, DRBG, ML-DSA, SLH-DSA, ML-KEM, HQC, Ed25519, the masking gadgets and the one-call API), without the command, files, capsules, JSON or TLS, and with no default allocator. The library then needs only `memcpy`, `memmove`, `memset` and `strcmp` from outside, which CI checks with `nm` for gcc and clang; it is built with `-fno-stack-protector -U_FORTIFY_SOURCE`, so a compiler that hardens by default (Ubuntu's, Debian's) adds no `__stack_chk_fail` or `__memcpy_chk`; `-DNQFREESSP=ON` keeps stack protection (`-fstack-protector-strong`) for a target that provides its own `__stack_chk_fail`, as the Linux kernel and many RTOSes do. Randomness comes from the caller: `nqsetrng(fn, user)` (also in the full build, for a hardware source) sets the function `nqrand` takes its bytes from; until it is set, `nqrand` fails with `NQERNG`. `tests/free/tfree.c` runs the self-test, a signature and a KEM round trip on such a build.
- Evidence records (RFC 4998) keep a capsule's time provable for decades: `noqtis ers --tsa <url> <dir>` writes `noqtis.ers` beside the seal, an EvidenceRecord whose data object is the seal file, and each later run renews it, with a timestamp over the last one (before the TSA certificate expires) or, with `--hash sha384` or `sha512`, a new chain over the seal and the record so far (before the hash weakens). The record there is checked before it is extended. `noqtis check --anchor` checks it in an `ers` row: the first timestamp over this seal, each next one over the one before, each TSA certificate valid at its own time and at the next one's, the last valid now. Records made elsewhere with reduced hash trees, digestAlgorithm and cryptoInfos are read too. While a record is there, `noqtis seal` and `noqtis timestamp` refuse the folder (`NQESTATE`), since either would change the seal it proves. The library has `nqersreq` and `nqersput` (`nqersput(3)`); the CLI tests run them against two local TSAs, a new fuzz target `fers` reads records.
- A progress bar for the long commands: `noqtis seal` and `noqtis check` show the bytes of the folder hashed so far, and signing with SLH-DSA the trees made (FORS, then each hypertree layer), on standard error, only when it is a terminal and the work takes more than a third of a second; the line is cleared when the work ends, so nothing of it reaches a file or a pipe. `NOQTIS_PROGRESS=0` turns it off. The library reports this through a new hook, `nqsetprog(fn, user)` (`nqsetprog(3)`), with only counts a caller could know; `tcap` checks every stage's calls.
- Fuzzing: the differential fuzzer's seed corpus (`fuzz/corpus/fdiff`) has 94 more inputs, found by fuzzing against OpenSSL 3.5 and kept by `libFuzzer -merge=1` because each reaches code the seeds did not (207 more coverage edges), so the two-minute run on every push starts deeper; `fuzz/build.sh` says how to add more.
- The library builds with older MinGW headers too, such as R 4.1's Rtools40 on Windows: those default to Windows XP and hid two Windows Vista functions the folder walk uses (`GetFinalPathNameByHandleW`, `WC_ERR_INVALID_CHARS`), so `src/cap/walk.c` now asks for Vista. CI checks the R package on R 4.1 on Linux, macOS and Windows.
- The full name is written "Notary of Quantum-Safe Traceable Inputs and Seals" everywhere (headers, README, design notes, the documentation site, `CITATION.cff`), and it is now the R package's title. The Fedora and Debian package changelogs list this release's changes.
- Releases: the release run stops before building anything unless every file that names the version (headers, bindings and their tests, package recipes, changelogs) names this one (`packaging/vercheck.sh`, also run by CI on every push), and unless the Go binding's tag `bindings/go/vX.Y.Z` is on the release commit, so the Go module proxy never caches the version as missing.

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
