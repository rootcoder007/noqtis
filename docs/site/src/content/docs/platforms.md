---
title: Platforms
description: Operating systems, CPUs and compilers NOQTIS builds and tests on, and its portability rules.
---

A platform counts as supported only when the full test suite passes on
it in CI. Every vector runs in the release builds; the debug, sanitizer,
emulated and mobile jobs sample the slowest ones (every eighth SLH-DSA
vector, no large-data hash tests) to stay within a job's time.

| OS | CPUs | Compilers | Notes |
|---|---|---|---|
| Linux (glibc) | x86-64, arm64 | GCC, Clang | Ubuntu, Fedora, Debian stable and testing, Arch, openSUSE Tumbleweed, Rocky 9 and 10, Amazon Linux 2023, Wolfi, Void, Gentoo and Nix, each with its own compiler |
| Linux (musl) | x86-64 (arm64: the Python wheels) | GCC | Alpine; static binaries |
| Linux, 32-bit | i686, armv7 (QEMU) | GCC | catches `size_t` and shift assumptions |
| Linux, big-endian | s390x (QEMU) | GCC | catches byte-order bugs |
| macOS | arm64, x86-64 | Apple Clang | a release archive for each |
| Windows | x86-64, arm64 | MSVC, clang-cl, MinGW-w64 | `BCryptGenRandom`; wide-character paths |
| FreeBSD, OpenBSD, NetBSD | x86-64 | Clang; GCC on NetBSD | `arc4random_buf` |
| WebAssembly | wasm32 | emscripten, wasi-sdk | emscripten: the library's tests under Node; wasi-sdk: the library's tests under wasmtime (no command-line tool) and the npm package on Node 22, 24 and 26, Deno and Bun |
| Android | x86-64; arm64 built only | NDK Clang | the library's tests on an emulator (API 34, built for API 28 and later); `getrandom`; no command-line tool |
| iOS | arm64 (simulator) | Apple Clang | the library's tests on a simulator with `xcrun simctl spawn`; `arc4random_buf`; no command-line tool |

Android arm64 is built in CI but its tests do not run there: no GitHub
runner can boot an arm64 Android emulator in useful time.

Every job runs on every push and pull request, and weekly. Linux ppc64le,
s390x and riscv64 Python wheels are built (and their tests run) under QEMU
on release tags, weekly and on demand.

## Randomness

Each platform uses its operating system's source: `getrandom` on Linux,
`arc4random_buf` on macOS, iOS and the BSDs, `BCryptGenRandom` on Windows,
WebCrypto `getRandomValues` (emscripten; and the npm package, whose WASI `random_get` calls it) or WASI `random_get` (wasi-sdk under wasmtime).
There is no fallback: if the source fails, the call fails with `NQERNG`.

## Portability rules

- ISO C11 only, `-std=c11 -pedantic`, no compiler extensions, no VLAs.
  Zero warnings with `-Wall -Wextra -Wpedantic -Wconversion -Wshadow
  -Wstrict-prototypes -Wcast-qual -Wvla -Wmissing-prototypes`.
- No assumption about endianness, `long` size, buffer alignment or `char`
  signedness; loads and stores go through byte helpers.
- Platform code sits in one file per concern (`src/core/rand.c`,
  `src/cap/walk.c`) behind `#if` blocks.
- The public header compiles as C11, C++11 and later, and under MSVC.
- File paths at the API are UTF-8 on every OS; Windows converts them to
  UTF-16 and opens files with the wide functions.

## Freestanding build

`cmake -DNQFREE=ON` builds the algorithms alone, for firmware, kernels
and other places with no operating system: the hashes, the DRBG,
ML-DSA, SLH-DSA, ML-KEM, HQC, Ed25519, the masking gadgets and the
one-call API, without the command, files, capsules, JSON or TLS, and
with no default allocator. The library then needs only `memcpy`,
`memmove`, `memset` and `strcmp` from outside, which CI checks with `nm`
for GCC and Clang. It is compiled with `-fno-stack-protector` and
`-U_FORTIFY_SOURCE`, since a compiler that turns those on by default
(Ubuntu's, Debian's) would otherwise make it call `__stack_chk_fail` and
`__memcpy_chk`, which a target with no C library does not have. A target
that does provide `__stack_chk_fail` (and `__stack_chk_guard`, on CPUs that
keep the canary in memory), as the Linux kernel and many RTOSes do, keeps
stack protection with `-DNQFREESSP=ON` (`-fstack-protector-strong`);
`_FORTIFY_SOURCE` stays off, since its `__*_chk` functions are the C
library's. Randomness comes from the caller: `nqsetrng(fn, user)`
names the function `nqrand` takes its bytes from (a hardware random
number generator, or a DRBG seeded from one); until it is set, `nqrand`
fails with `NQERNG`. `tests/free/tfree.c` runs the self-test, a
signature and a KEM round trip on such a build.

## Library form

- Static and shared builds from the same sources. A shared build exports
  only the public functions (`-fvisibility=hidden`, `__declspec` on
  Windows; on ELF systems every one carries the symbol version
  `NOQTIS_0`) and the ABI version: `libnoqtis.so.0`, `libnoqtis.0.dylib`,
  `noqtis-0.dll`. CI compares the shared library's ABI with the last
  release (libabigail); an incompatible change needs a new major version.
- `noqtis.pc` (pkg-config) and a CMake package (`find_package(noqtis)`) are
  installed with the library; CI builds a consumer program against each
  install both ways.
- `nqver()` and `NQVMAJ`, `NQVMIN`, `NQVPAT` give the version at run time
  and compile time.
