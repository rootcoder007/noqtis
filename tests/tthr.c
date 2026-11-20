/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The hooks under threads: one thread keeps setting each hook to one of
 * two (function, user pointer) pairs, or to none, while others make the
 * calls that read them. Every call must see a pair that was set, never
 * the function of one with the pointer of the other, and the progress
 * of a stage must stay that of the thread that began it. Built with
 * -fsanitize=thread this is also the proof that no read races a write.
 * POSIX threads only; elsewhere the test says so and passes. */
#include "noqtis.h"

#include <stdio.h>

#if defined(_WIN32) || defined(__wasi__) || defined(__EMSCRIPTEN__) || \
    defined(NQFREE)
int main(void) {
  puts("tthr: no POSIX threads here, skipped");
  return 0;
}
#else

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "core/int.h"
#include "nqt.h"

#define NW 4      /* threads that work */
#define ROUNDS 20000

static int ta, tb; /* the two user pointers */
static int bad;    /* a pair that was never set */
static int halt;

static void mark(void) {
  __atomic_store_n(&bad, 1, __ATOMIC_RELAXED);
}

static int rnga(uint8_t *b, size_t n, void *u) {
  if (u != &ta) mark();
  memset(b, 0xa1, n);
  return 0;
}
static int rngb(uint8_t *b, size_t n, void *u) {
  if (u != &tb) mark();
  memset(b, 0xb2, n);
  return 0;
}

static void *mala(size_t n, void *u) {
  if (u != &ta) mark();
  return malloc(n);
}
static void *malb(size_t n, void *u) {
  if (u != &tb) mark();
  return malloc(n);
}
static void frea(void *p, size_t n, void *u) {
  (void)n;
  if (u != &ta) mark();
  free(p);
}
static void freb(void *p, size_t n, void *u) {
  (void)n;
  if (u != &tb) mark();
  free(p);
}

static int stopa(void *u) {
  if (u != &ta) mark();
  return 0;
}
static int stopb(void *u) {
  if (u != &tb) mark();
  return 0;
}

static void tmpa(int ev, const char *p, void *u) {
  (void)ev;
  (void)p;
  if (u != &ta) mark();
}
static void tmpb(int ev, const char *p, void *u) {
  (void)ev;
  (void)p;
  if (u != &tb) mark();
}

/* a stage's total is its thread's own number: a call that reported
 * another thread's would show here */
static void proga(int st, uint64_t done, uint64_t total, void *u) {
  if (u != &ta || done > total || total != (uint64_t)st * 1000) mark();
}
static void progb(int st, uint64_t done, uint64_t total, void *u) {
  if (u != &tb || done > total || total != (uint64_t)st * 1000) mark();
}

static void *setter(void *v) {
  unsigned i = 0;
  (void)v;
  while (!__atomic_load_n(&halt, __ATOMIC_RELAXED)) {
    switch (i++ % 3) {
    case 0:
      nqsetrng(rnga, &ta);
      nqsetal(mala, frea, &ta);
      nqsetstop(stopa, &ta);
      nqsettmp(tmpa, &ta);
      nqsetprog(proga, &ta);
      break;
    case 1:
      nqsetrng(rngb, &tb);
      nqsetal(malb, freb, &tb);
      nqsetstop(stopb, &tb);
      nqsettmp(tmpb, &tb);
      nqsetprog(progb, &tb);
      break;
    default:
      nqsetrng(NULL, NULL);
      nqsetal(NULL, NULL, NULL);
      nqsetstop(NULL, NULL);
      nqsettmp(NULL, NULL);
      nqsetprog(NULL, NULL);
      break;
    }
  }
  return NULL;
}

static void *worker(void *v) {
  int id = (int)(size_t)v + 1, i;
  uint8_t b[32];
  for (i = 0; i < ROUNDS; i++) {
    void *p;
    if (nqrand(b, sizeof b) != NQOK) mark();
    p = nqmal(64);
    if (p == NULL) mark();
    nqfree(p, 64);
    (void)nqstop();
    nqtmpev(NQTPRE, "x");
    nqpbeg(id, (uint64_t)id * 1000);
    nqpstep(1);
    nqpstep(2);
    nqpend();
  }
  return NULL;
}

int main(void) {
  pthread_t s, w[NW];
  size_t i;
  NQTEQI(pthread_create(&s, NULL, setter, NULL), 0);
  for (i = 0; i < NW; i++)
    NQTEQI(pthread_create(&w[i], NULL, worker, (void *)i), 0);
  for (i = 0; i < NW; i++) NQTEQI(pthread_join(w[i], NULL), 0);
  __atomic_store_n(&halt, 1, __ATOMIC_RELAXED);
  NQTEQI(pthread_join(s, NULL), 0);
  NQTEQI(__atomic_load_n(&bad, __ATOMIC_RELAXED), 0);
  nqsetrng(NULL, NULL);
  nqsetal(NULL, NULL, NULL);
  nqsetstop(NULL, NULL);
  nqsettmp(NULL, NULL);
  nqsetprog(NULL, NULL);
  return nqtdone("tthr");
}
#endif
