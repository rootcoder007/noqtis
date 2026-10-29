---
title: Platforms
description: Operating systems, CPUs and compilers noqtis builds and tests on, and its portability rules.
---

A platform counts as supported only when the full test suite, including
every ACVP vector, passes on it in CI.

| OS | CPUs | Compilers | Notes |
|---|---|---|---|
| Linux (glibc) | x86-64, arm64 | GCC, Clang | Ubuntu, Fedora, Debian stable and testing, Arch, openSUSE Tumbleweed, Rocky 9 and 10, Amazon Linux 2023, Wolfi, Void, Gentoo and Nix, each with its own compiler |
| Linux (musl) | x86-64, arm64 | GCC | Alpine; static binaries |
| Linux, 32-bit | i686, armv7 | GCC | catches `size_t` and shift assumptions |
| Linux, big-endian | s390x (QEMU) | GCC | catches byte-order bugs |
| macOS | arm64, x86-64 | Apple Clang | universal binaries for releases |
| Windows | x86-64, arm64 | MSVC, clang-cl, MinGW-w64 | `BCryptGenRandom`; wide-character paths |
| FreeBSD, OpenBSD | x86-64 | Clang | `arc4random_buf` |
| WebAssembly | wasm32 | emscripten, wasi-sdk | browsers, Node, Deno, Bun, WASI runtimes |
| Android, iOS | arm64 | NDK Clang, Xcode | libraries only, no command-line tool |

While the repository is private, the arm64, macOS, Windows, FreeBSD and
emulated big-endian jobs run weekly and on demand; once it is public they
run on every push. The x86-64 Linux, distribution, Nix, container and
package jobs run on every push.

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
  Windows) and carries the ABI version: `libnoqtis.so.0`,
  `libnoqtis.0.dylib`, `noqtis-0.dll`.
- `noqtis.pc` (pkg-config) and a CMake package (`find_package(noqtis)`) are
  installed with the library; CI builds a consumer program against each
  install both ways.
- `nqver()` and `NQVMAJ`, `NQVMIN`, `NQVPAT` give the version at run time
  and compile time.
