/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* What makes the hooks (nqsetrng, nqsetprog, nqsetstop, nqsettmp,
 * nqsetal) safe to set while other threads work: a spin lock around the
 * two or three words each hook keeps, so a function and its user pointer
 * are always read as the pair that was set, and storage of the thread's
 * own for a state that belongs to one call. The lock is held for a few
 * instructions, never across a call to the hook. A freestanding build
 * (NQFREE) has no threads: there both are nothing. */
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
