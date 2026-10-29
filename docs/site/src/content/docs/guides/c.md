---
title: Use the C library
description: Build a program against libnoqtis with CMake or pkg-config, seal and check a folder, and sign and verify a message.
---

NOQTIS is one C11 library, `libnoqtis`, with one header, `noqtis.h`.
This tutorial builds a small program that seals a folder, checks it,
signs a message, and then shows a check failing after a file changes.

## Install the library

Build and install it from source (see [Install](/noqtis/start/install/)
for the package managers):

```sh
git clone https://github.com/rootcoder007/noqtis.git
cmake -S noqtis -B nqbuild -DNQTESTS=OFF
cmake --build nqbuild
cmake --install nqbuild --prefix "$HOME/.local"
```

The install puts `noqtis.h`, the library, `noqtis.pc` (pkg-config) and a
CMake package (`noqtisConfig.cmake`) under the prefix.

## The program

Save this as `prov.c`:

```c
/* prov.c: seal a folder, check it, then sign and verify one message.
 * Usage: prov <dir> */
#include <noqtis.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void show(const nqrep *rep) {
  size_t i;
  for (i = 0; i < nqrepn(rep); i++) {
    const char *check, *detail;
    int ok;
    if (nqrepi(rep, i, &check, &ok, &detail) == NQOK && !ok)
      printf("FAIL %s: %s\n", check, detail);
  }
}

int main(int argc, char **argv) {
  const nqsalg alg = NQMLDSA65;
  const char *msg = "the results in table 2";
  nqssz sz;
  uint8_t *pk, *sk, *sig;
  size_t n = 0;
  nqrep *rep = NULL;
  int rc;

  if (argc != 2) {
    fprintf(stderr, "usage: prov <dir>\n");
    return 2;
  }
  /* sizes at run time, so the same code works for every algorithm */
  rc = nqssize(alg, &sz);
  if (rc != NQOK)
    return 2;
  pk = malloc(sz.pk);
  sk = malloc(sz.sk);
  sig = malloc(sz.sig);
  if (pk == NULL || sk == NULL || sig == NULL)
    return 2;

  rc = nqskg(alg, pk, sz.pk, sk, sz.sk);

  /* 1. seal the folder: writes noqtis.json and noqtis.sig into it */
  if (rc == NQOK)
    rc = nqseal(argv[1], alg, sk, sz.sk, pk, sz.pk,
                "{\"project\":\"tutorial\"}", NULL);
  if (rc != NQOK) {
    fprintf(stderr, "seal: %s\n", nqerr(rc));
    return 2;
  }

  /* 2. check it, pinning the public key we expect */
  rc = nqchk(argv[1], pk, sz.pk, &rep);
  printf("check: %s (%zu checks)\n", nqerr(rc), nqrepn(rep));
  nqrepfree(rep);
  rep = NULL;

  /* 3. sign and verify a message, with a context string */
  rc = nqsign(alg, sk, sz.sk, (const uint8_t *)msg, strlen(msg),
              (const uint8_t *)"app-v1", 6, 0, sig, sz.sig, &n);
  nqwipe(sk, sz.sk); /* done with the secret key */
  if (rc == NQOK)
    rc = nqvrfy(alg, pk, sz.pk, (const uint8_t *)msg, strlen(msg),
                (const uint8_t *)"app-v1", 6, 0, sig, n);
  printf("signature: %zu bytes, verify: %s\n", n, nqerr(rc));

  /* 4. change a file and check again: the check fails and says why */
  {
    char path[4096];
    FILE *f;
    snprintf(path, sizeof path, "%s/report.txt", argv[1]);
    f = fopen(path, "ab");
    if (f != NULL) {
      fputs("edited\n", f);
      fclose(f);
    }
  }
  rc = nqchk(argv[1], pk, sz.pk, &rep);
  printf("check after edit: %s\n", nqerr(rc));
  show(rep);
  nqrepfree(rep);

  free(pk);
  free(sk);
  free(sig);
  return rc == NQEVRFY ? 0 : 1;
}
```

Every function returns `NQOK` (0) or a negative `NQE*` code, and
`nqerr()` turns a code into text. A failed check or signature is
`NQEVRFY`, never `NQOK`. Sizes come from `nqssize()`, so changing `alg`
to `NQSLHK128S` (SLH-DSA-SHAKE-128s) or `NQMLDSA87` is the only edit needed for another
algorithm. The secret key is wiped with `nqwipe()` as soon as it is no
longer needed.

## Build with CMake

`CMakeLists.txt` next to `prov.c`:

```cmake
cmake_minimum_required(VERSION 3.20)
project(prov LANGUAGES C)

find_package(noqtis CONFIG REQUIRED)

add_executable(prov prov.c)
target_link_libraries(prov PRIVATE noqtis::noqtis)
```

```sh
cmake -S . -B build -DCMAKE_PREFIX_PATH="$HOME/.local"
cmake --build build
```

`find_package(noqtis CONFIG)` gives the target `noqtis::noqtis`, which
carries the include path and the link flags.

## Build with pkg-config

```sh
export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig:$HOME/.local/lib64/pkgconfig"
cc -std=c11 -Wall -Wextra -o prov prov.c $(pkg-config --cflags --libs noqtis)
```

## Run it

```sh
$ mkdir -p results/data
$ printf 'a,b\n1,2\n' > results/data/in.csv
$ printf 'r\n' > results/report.txt
$ ./prov results
check: success (22 checks)
signature: 3309 bytes, verify: success
check after edit: verification failed
FAIL file: report.txt: size differs
```

The folder now holds `noqtis.json` and `noqtis.sig`, which the
`noqtis` command checks too: `noqtis check results` (without `-p` it
accepts the key in the seal and says so).

## Next

- [Seal and check a capsule](/noqtis/guides/seal/): what a seal records
  and what it refuses.
- [C API](/noqtis/reference/c-api/): every function, with its errors.
- [nqseal(3)](/noqtis/reference/man/nqseal-3/),
  [nqchk(3)](/noqtis/reference/man/nqchk-3/),
  [nqsign(3)](/noqtis/reference/man/nqsign-3/).
