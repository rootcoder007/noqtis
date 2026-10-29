---
title: Platforms
description: Operating systems, CPUs and compilers NOQTIS builds and tests on, and its portability rules.
---

A platform counts as supported only when the full test suite, including
every ACVP vector, passes on it in CI.

| OS | CPUs | Compilers | Notes |
|---|---|---|---|
| Linux (glibc) | x86-64, arm64 | GCC, Clang | Ubuntu, Fedora, Debian stable and testing, Arch, openSUSE Tumbleweed, Rocky 9 and 10, Amazon Linux 2023, Wolfi, Void, Gentoo and Nix, each with its own compiler |
| Linux (musl) | x86-64, arm64 | GCC | Alpine; static binaries |
| Linux, 32-bit | i686, armv7 (QEMU) | GCC | catches `size_t` and shift assumptions |
| Linux, big-endian | s390x (QEMU) | GCC | catches byte-order bugs |
| macOS | arm64, x86-64 | Apple Clang | universal binaries for releases |
| Windows | x86-64, arm64 | MSVC, clang-cl, MinGW-w64 | `BCryptGenRandom`; wide-character paths |
| FreeBSD, OpenBSD, NetBSD | x86-64 | Clang; GCC on NetBSD | `arc4random_buf` |
| WebAssembly | wasm32 | emscripten, wasi-sdk | emscripten: the library's tests under Node, the npm package on Node 22, 24 and 26, Deno and Bun; wasi-sdk: the library's tests under wasmtime (no command-line tool) |

Not tested in CI yet, so not listed as supported: Android and iOS
([issue 15](https://github.com/rootcoder007/noqtis/issues/15)). The code
already has their randomness sources (`getrandom`, `arc4random_buf`).

Every job runs on every push and pull request, and weekly. Linux ppc64le,
s390x and riscv64 Python wheels are built (and their tests run) under QEMU
on release tags, weekly and on demand.

## Randomness

Each platform uses its operating system's source: `getrandom` on Linux,
`arc4random_buf` on macOS and the BSDs, `BCryptGenRandom` on Windows,
WebCrypto `getRandomValues` (emscripten) or WASI `random_get` (wasi-sdk).
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
