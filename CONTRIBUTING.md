# Contributing to NOQTIS

Thank you for helping. NOQTIS is a small C11 library and command-line
tool for post-quantum signatures and sealed file capsules, so every
change is read closely: keep it small, tested and easy to review.

Security problems are not reported here: see [SECURITY.md](SECURITY.md).
Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Build

You need a C11 compiler (GCC, Clang, MSVC or MinGW-w64) and CMake 3.20
or later. Nothing else.

```sh
git clone https://github.com/rootcoder007/noqtis.git
cd noqtis
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j4
```

Options (all `-D...` at configure time):

| Option | Default | Effect |
|---|---|---|
| `NQSHARED=ON` | off | a shared library instead of a static one |
| `NQSAN=ON` | off | AddressSanitizer and UBSan |
| `NQCLI=OFF` | on | skip the `noqtis` command-line tool |
| `NQTESTS=OFF` | on | skip the tests |
| `NQMAN=OFF` | on | do not install the manual pages |
| `NQWERROR=OFF` | on | do not treat warnings as errors |
| `NQTLS=ON` | off | the TLS 1.3 client (`src/tls`) in the public API and `https://` in the tool; not yet reviewed |

Warnings are errors: `-Wall -Wextra -Wpedantic -Wconversion -Wshadow
-Wstrict-prototypes -Wcast-qual -Wvla`. A change that adds a warning on
any compiler in CI fails.

## Tests

```sh
ctest --test-dir build -j4 --output-on-failure
```

runs every module's tests, including every NIST ACVP and Wycheproof
vector in `tests/vectors/`. The small SLH-DSA parameter sets ("s") take
seconds per signature, so a few environment variables sample the slow
parts:

| Variable | Effect |
|---|---|
| `NQFAST=1` | `tapi` signs with no small SLH-DSA set |
| `NQSLSUB=k` | `tslh` runs only every k-th SLH-DSA sigGen test (and every k-th keyGen and sigVer test) |
| `NQSLOW=1` | the opposite: every check on every set, every "s" sigGen vector |
| `NQCLIALL=1` | `tcli` runs keygen/sign/verify for all twelve SLH-DSA sets |
| `NQCLIWRAP="valgrind -q --error-exitcode=9 --leak-check=full"` | `tcli` runs every command under a wrapper |
| `NQNET=1` | `tlnet` talks TLS to public HTTPS servers (`tests/tls/net.sh`); skipped otherwise |

For a quick loop while you work, sample as the Debug CI jobs do:

```sh
NQSLSUB=8 NQFAST=1 ctest --test-dir build -j4 --output-on-failure
```

Before you open a pull request, run the full suite once (no variables),
and once with sanitizers:

```sh
cmake -S . -B build-san -DNQSAN=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build-san -j4
NQSLSUB=8 NQFAST=1 ctest --test-dir build-san -j4 --output-on-failure
```

CI also runs every test under valgrind (with the sampling in
`.github/workflows/ci.yml`), the constant-time (ctgrind) tests, 32-bit
and big-endian Linux, macOS, Windows, FreeBSD and a dozen Linux
distributions. A change that touches secret data needs a ctgrind test
(`tests/t*ct.c`); a change to a parser needs tests for what it refuses.

The bindings have their own tests: `bindings/py` (`pytest`),
`bindings/npm` (`npm test`, after `sh build.sh` with emscripten) and
`bindings/r` (`R CMD check`). If you change `src/` or `include/`, run
`sh bindings/r/tools/vendor.sh` so the R package carries the same
sources; CI checks that it does.

## Rules for the code

- **ISO C11 only**, no compiler extensions, no VLAs, no recursion in
  parsers, no `malloc` in the algorithm code (the capsule layer allocates
  through the `nqsetal` hook). Platform code stays in its one file per
  concern behind `#if` blocks.
- **No new dependencies.** The library has none at run time and its
  build needs only CMake and a C compiler; a pull request that adds a
  library, a generator or a tool to the build will not be merged.
- **Short names everywhere.** Public functions are `nq` plus a short
  word (`nqsign`, `nqvrfy`, `nqseal`, `nqchk`), types likewise (`nqhctx`,
  `nqsalg`), constants `NQ` plus a short word (`NQOK`, `NQEVRFY`). Files
  and folders too (`src/slh/`, `rand.c`, `tcap.c`). No long snake_case
  names, in code or file names.
- **ASCII** in source files, unless the file already holds other text
  (test vectors, translations).
- **Fail closed.** A parser rejects anything the standard does not
  define; a verifier returns a failure for anything it cannot check.
  Verification failure is `NQEVRFY`, never 0.
- **Secrets are wiped** with `nqwipe` on every path before a function
  returns, and handled in constant time.
- Every public function has its manual page in `man/` and its entry on
  the site's C API page; an example on the site or in a manual page is
  compiled and run in CI (`docs/examples/`).

## Commits

Commits follow the Linux kernel and Git style:

```text
area: summary in the imperative, lower case, no full stop

The body says why the change is needed and what it changes, wrapped at
72 columns. Name the bug, the standard's section or the test that
shows the problem.

Signed-off-by: Your Name <your address>
```

- `area` is the module or folder: `mldsa`, `slh`, `mlkem`, `hqc`,
  `hash`, `drbg`, `der`, `cap`, `cli`, `core`, `docs`, `github`, `py`,
  `npm`, `r`, `packaging`, ...
- One logical change per commit; a fix and its test belong together.
- The `Signed-off-by` line is your
  [Developer Certificate of Origin](https://developercertificate.org/):
  you certify that you wrote the change or have the right to submit it
  under the project's licence. `git commit -s` adds it. Commits without
  it cannot be merged.
- Signed commits (`git commit -S`, GPG or SSH) are welcome.

## The documentation site

The site is Astro Starlight in `docs/site`, built in CI with a check of
every internal link. To work on it you need Node 22.12 or later:

```sh
cd docs/site
npm ci
npm run dev        # http://localhost:4321/noqtis/
npm run build      # what CI runs; fails on a broken internal link
```

After a change to a manual page in `man/`, `npm run man` (needs
`mandoc`) renders the pages into `src/content/docs/reference/man/`;
commit the result with the page.

`NQPAGEFIND=0 npm run build` skips the search index where Pagefind's
binary does not run. Version numbers never appear typed into a page:
they come from the release you install.

## Pull requests

1. Open an issue first for anything bigger than a small fix, so we can
   agree on the approach.
2. Keep the pull request to one topic; fill in the template.
3. CI must be green. A maintainer reviews every line; expect questions.

By contributing you agree that your contribution is licensed under the
project's licence, Apache-2.0 WITH LLVM-exception.
