/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The lock of the hooks nqdsetal and nqdsettmp: src/core/lock.h of the
 * library, which this one does not include, word for word. */
#ifndef NQLOCK_H
#define NQLOCK_H

#if defined(NQFREE)
#define NQLKDEF(n) typedef char n
#define nqlk(n) ((void)0)
#define nqul(n) ((void)0)
#define NQTLOC
#elif defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#define NQLKDEF(n) static volatile long n = 0
#define nqlk(n)                                 \
  do {                                          \
  } while (_InterlockedExchange(&(n), 1) != 0)
#define nqul(n) ((void)_InterlockedExchange(&(n), 0))
#define NQTLOC __declspec(thread)
#else
#define NQLKDEF(n) static volatile char n = 0
#define nqlk(n)                                              \
  do {                                                       \
  } while (__atomic_test_and_set(&(n), __ATOMIC_ACQUIRE))
#define nqul(n) __atomic_clear(&(n), __ATOMIC_RELEASE)
#define NQTLOC _Thread_local
#endif

#endif /* NQLOCK_H */
