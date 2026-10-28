# noqtis

**N**otary **O**f **Q**uantum-safe **T**raceable **I**nputs and **S**eals.

A small C11 library and command-line tool that records the exact files a
result came from, signs that record with post-quantum signatures (ML-DSA,
SLH-DSA) and timestamps it, so anyone can check later that nothing changed.

> **Status: under construction and unaudited.** Do not rely on it yet.

See [DESIGN.md](DESIGN.md) for the modules, the capsule format and the checks
each module must pass.

## Build

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```
