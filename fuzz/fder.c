/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* libFuzzer target over the DER reader itself: one element, a cursor
 * walk of every level (to the depth limit), and the primitive decoders
 * (INTEGER, BOOLEAN, OID, BIT STRING, NULL, times, Names, extensions,
 * algorithm identifiers, SubjectPublicKeyInfo) on every element met.
 * The certificate, OCSP, CRL and RFC 3161 parsers have their own targets
 * (fx509, focsp, ftsp).
 *
 *   fuzz/build.sh                  (all targets, into build-fuzz/)
 *   build-fuzz/fder fuzz/corpus/fder -dict=fuzz/der.dict */
#include "fz.h"
#include "der/der.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  fzinit(argv);
  return 0;
}

/* the last signature algorithm met, for nqxkeyok on the next key */
static nqxsig last = {NQXRSA, NQS256, (nqsalg)0};

/* the decoders on one element */
static void prim(const nqdtlv *t) {
  int64_t v;
  uint32_t ns, nb;
  nqspan s;
  unsigned un;
  int b, neg, empty;
  nqxsig sg;
  nqxkey k;
  nqhalg h;
  if (t->cls == NQDUNI && !t->con) {
    (void)nqdprim(t->tag, t->v.p, t->v.n);
  }
  (void)nqdi64(t, &v);
  (void)nqdenum(t, &v);
  (void)nqdint(t, &s, &neg);
  (void)nqdbool(t, &b);
  (void)nqdoid(t, &s);
  (void)nqdbits(t, &s, &un);
  (void)nqdbit0(t, &s);
  (void)nqdnbits(t, &nb);
  (void)nqdnull(t);
  (void)nqdtime(t, NQDTFRAC, &v, &ns);
  (void)nqdtime(t, NQDT5280, &v, &ns);
  (void)nqdtime(t, 0, &v, &ns);
  (void)nqxname(t, &empty);
  (void)nqxgext(t);
  if (nqxsalg(t, &sg) == NQOK) last = sg;
  (void)nqxhalg(t, 1, &h);
  (void)nqxhalg(t, 0, &h);
  if (nqxspki(t, &k) == NQOK) {
    (void)nqxkeyok(&k, &last);
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  nqdcur st[NQDDEPTH + 2];
  nqdtlv t;
  size_t d = 0;
  int r;
  (void)nqdone(data, size, &t);
  (void)nqdwalk(data, size);
  (void)nqdhdr(data, size, &t);
  /* every element of every level, depth first */
  nqdinit(&st[0], data, size);
  for (;;) {
    r = nqdnext(&st[d], &t);
    if (r != NQOK) {
      if (d == 0) break;
      (void)nqddone(&st[d]);
      d--;
      continue;
    }
    prim(&t);
    if (t.con && d + 1 < sizeof st / sizeof st[0] &&
        nqddown(&t, &st[d + 1]) == NQOK) {
      d++;
    }
  }
  /* a Name compared with itself */
  {
    nqspan a;
    a.p = data;
    a.n = size;
    (void)nqxneq(a, a);
  }
  return 0;
}
