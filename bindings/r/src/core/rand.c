/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The operating system's CSPRNG. Never falls back to a weaker source: when
 * the OS call fails, the caller gets NQERNG. */
#if defined(__linux__)
#define _GNU_SOURCE /* getrandom() in glibc's <sys/random.h> */
#elif defined(__EMSCRIPTEN__) || defined(__wasi__)
#define _DEFAULT_SOURCE /* getentropy() is hidden under strict -std=c11 */
#endif

#include "noqtis.h"

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#elif defined(__EMSCRIPTEN__) || defined(__wasi__)
#include <unistd.h> /* getentropy: crypto.getRandomValues / WASI random_get */
#elif defined(__linux__)
#include <errno.h>
#include <sys/random.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || \
    defined(__NetBSD__)
#include <stdlib.h> /* arc4random_buf */
#else
#error "noqtis: no CSPRNG known for this platform"
#endif

int nqrand(uint8_t *buf, size_t len) {
  if (buf == NULL && len != 0) {
    return NQEARG;
  }
#if defined(_WIN32)
  while (len > 0) {
    ULONG chunk = len > 0x10000000u ? 0x10000000u : (ULONG)len;
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, buf, chunk,
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
      return NQERNG;
    }
    buf += chunk;
    len -= chunk;
  }
  return NQOK;
#elif defined(__EMSCRIPTEN__) || defined(__wasi__)
  while (len > 0) {
    /* getentropy() gives at most 256 bytes per call */
    size_t chunk = len > 256 ? 256 : len;
    if (getentropy(buf, chunk) != 0) {
      return NQERNG;
    }
    buf += chunk;
    len -= chunk;
  }
  return NQOK;
#elif defined(__linux__)
  while (len > 0) {
    /* at most 32 MiB per call; blocks until the pool is seeded */
    ssize_t n = getrandom(buf, len, 0);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return NQERNG;
    }
    buf += (size_t)n;
    len -= (size_t)n;
  }
  return NQOK;
#else
  arc4random_buf(buf, len);
  return NQOK;
#endif
}
