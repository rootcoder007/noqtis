/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* noqtis box and unbox: a file sealed to an ML-KEM public key in chunks
 * (noqtis-kstream-1, nqkfeini(3)), in memory of one chunk; to several
 * keys, or signed by its sender, it is noqtis-kstream-2 (nqkmeini(3)).
 * unbox reads either, writes a chunk's plaintext only once its tag has
 * verified, and on any failure, a signature that does not verify among
 * them, removes the output file it was writing (on stdout it stops:
 * what was written had verified, but the stream is cut or its sender is
 * not known). */
#include "cli.h"

#include <stdlib.h>
#include <string.h>

/* unbox reads an armored stream through ain; box -a writes one
 * through aout */
static ncar ain;
static ncaw aout;
static int armout = 0;

/* reads up to n bytes (fewer only at the end); *got, or NQEIO */
static int fill(FILE *f, uint8_t *b, size_t n, size_t *got) {
  if (ain.on && ain.f == f) {
    int rc = ncarget(&ain, b, n, got);
    if (rc != NQOK && ain.dec)
      ncmsg("unbox", "the armor is not whole: its text was changed or "
            "cut, or text follows it");
    return rc;
  }
  *got = 0;
  while (*got < n) {
    size_t k = fread(b + *got, 1, n - *got, f);
    if (k == 0) break;
    *got += k;
  }
  return ferror(f) ? NQEIO : NQOK;
}

/* whether f has another byte: 1 with it in *c, 0 at the end */
static int peek(FILE *f, uint8_t *c) {
  int x;
  if (ain.on && ain.f == f) return ncarpeek(&ain, c);
  x = fgetc(f);
  if (x == EOF) return 0;
  *c = (uint8_t)x;
  return 1;
}

static FILE *opin(const char *cmd, const char *p) {
  FILE *f = strcmp(p, "-") == 0 ? stdin : ncfopen(p, "rb");
  if (f == NULL) ncmsg(cmd, "cannot read %s%s", p, ncwhy());
  return f;
}

/* the output: stdout for "-", else a new file (sec: owner-only) */
static FILE *opout(const char *cmd, const char *p, int force, int sec) {
  FILE *f = stdout;
  if (strcmp(p, "-") != 0) {
    f = ncopen(p, force, sec);
    if (f == NULL) {
      ncwfail(cmd, p, force);
      return NULL;
    }
  }
  /* a BEGIN line that cannot be written shows at the next write */
  (void)ncawbeg(&aout, f, armout ? NCLBOX : NULL);
  return f;
}

static int put(const uint8_t *b, size_t n) {
  return ncawput(&aout, b, n);
}

static void endout(const char *cmd, FILE *f, const char *p, int bad,
                   int *ret) {
  if (!bad && ncawend(&aout) != NQOK) {
    ncmsg(cmd, "cannot write %s%s", p, ncwhy());
    *ret = NCUSE;
    bad = 1;
  }
  if (f == stdout) {
    if (fflush(f) != 0) *ret = NCUSE;
  } else if (ncclose(f, p, bad) != NQOK && !bad) {
    ncmsg(cmd, "cannot write %s%s", p, ncwhy());
    *ret = NCUSE;
  }
}

static int kemkey(const char *cmd, const char *path, const nckey *k) {
  int a = k->a.alg;
  if (!k->a.kem || (a != (int)NQMLKEM512 && a != (int)NQMLKEM768 &&
                    a != (int)NQMLKEM1024)) {
    ncmsg(cmd, "%s is a %s key; box and unbox take an ML-KEM key", path,
          k->a.name);
    return NCUSE;
  }
  return NCOK;
}

/* box to several keys, or signed (noqtis-kstream-2): kps[0..nk) the
 * recipients' public key files, sp the sender's secret key file or NULL */
static int boxm(const char **kps, int nk, const char *sp, const ncpw *pwo,
                const char *out, const char *ctx, size_t cl,
                unsigned long chunk, int force, const char *inp) {
  nckey k[NCMAXV], sk = {{0, 0, NULL}, 0, NULL, 0};
  nqkrcp r[NCMAXV];
  nqkmctx c;
  nqssz sz = {0, 0, 0};
  uint8_t *h = NULL, *a = NULL, *e = NULL, nx = 0;
  size_t hl = 0, got = 0, en = 0, ecap;
  FILE *in = NULL, *of = NULL;
  int i, nr = 0, rc, ret = NCUSE, bad = 1, more;

  for (i = 0; i < nk; i++) {
    if (nckrd("box", kps[i], &k[nr]) != NCOK) goto done;
    nr++;
    if (kemkey("box", kps[i], &k[i]) != NCOK) goto done;
    r[i].alg = (nqkalg)k[i].a.alg;
    r[i].pk = k[i].b;
    r[i].pklen = k[i].n;
  }
  if (sp != NULL) {
    if (ncskrd("box", sp, pwo, "pass", &sk) != NCOK) goto done;
    if (sk.a.kem || nqssize((nqsalg)sk.a.alg, &sz) != NQOK) {
      ncmsg("box", "%s is a %s key; --sign takes a signature key", sp,
            sk.a.name);
      goto done;
    }
  }
  if (nqkmhlen(r, (size_t)nk, &hl) != NQOK) {
    nclib("box", "the recipients", NQEARG);
    goto done;
  }
  ncbin();
  ecap = chunk + 16 + (sp != NULL ? sz.sig + 16 : 0);
  h = (uint8_t *)malloc(hl);
  a = (uint8_t *)malloc(chunk);
  e = (uint8_t *)malloc(ecap);
  if (h == NULL || a == NULL || e == NULL) {
    nclib("box", "memory", NQEMEM);
    goto done;
  }
  in = opin("box", inp);
  if (in == NULL) goto done;
  of = opout("box", out, force, 0);
  if (of == NULL) goto done;
  rc = nqkmeini(&c, r, (size_t)nk, sp != NULL ? (nqsalg)sk.a.alg : (nqsalg)0,
                (const uint8_t *)ctx, cl, (uint32_t)chunk, h, hl, &hl);
  if (rc != NQOK) {
    nclib("box", "sealing", rc);
    goto done;
  }
  if (put(h, hl) != NQOK) {
    ncmsg("box", "cannot write %s%s", out, ncwhy());
    nqwipe(&c, sizeof c);
    goto done;
  }
  /* a chunk is the last when no byte follows it */
  for (;;) {
    size_t pre = 0;
    if (got > 0) {
      a[0] = nx;
      pre = 1;
    }
    if (fill(in, a + pre, chunk - pre, &got) != NQOK) {
      ncmsg("box", "cannot read %s%s", inp, ncwhy());
      nqwipe(&c, sizeof c);
      goto done;
    }
    got += pre;
    more = got == chunk && peek(in, &nx);
    rc = more ? nqkmeupd(&c, a, got, e, ecap, &en)
              : nqkmefin(&c, a, got, sp != NULL ? sk.b : NULL,
                         sp != NULL ? sk.n : 0, e, ecap, &en);
    if (rc != NQOK) {
      nclib("box", more || sp == NULL ? "sealing" : "sealing and signing",
            rc);
      goto done;
    }
    if (put(e, en) != NQOK) {
      ncmsg("box", "cannot write %s%s", out, ncwhy());
      if (more) nqwipe(&c, sizeof c);
      goto done;
    }
    if (!more) break;
  }
  bad = 0;
  ret = NCOK;
done:
  if (of != NULL) endout("box", of, out, bad, &ret);
  if (in != NULL && in != stdin) fclose(in);
  if (a != NULL) ncfree(a, chunk, 1);
  free(e);
  free(h);
  for (i = 0; i < nr; i++) nckfree(&k[i]);
  nckfree(&sk);
  return ret;
}

int ncbox(int argc, char **argv) {
  const char *kps[NCMAXV], *out = NULL, *ctx = NULL, *cs = NULL, *sp = NULL;
  const char *kp = NULL;
  int force = 0, help = 0, np, rc, ret = NCUSE, nkp = 0, arm = 0;
  ncpw pwo = {NULL, NULL};
  ncopt o[] = {
    {'p', "pub", NCMANY, kps, &nkp},
    {'o', "out", 1, &out, NULL},
    {'c', "ctx", 1, &ctx, NULL},
    {'\0', "chunk", 1, &cs, NULL},
    {'s', "sign", 1, &sp, NULL},
    {'a', "armor", 0, NULL, &arm},
    {'\0', "pass-fd", 1, &pwo.fd, NULL},
    {'\0', "pass-env", 1, &pwo.env, NULL},
    {'f', "force", 0, NULL, &force}
  };
  nckey k = {{0, 0, NULL}, 0, NULL, 0};
  nqkfctx c;
  nqksz z = {0, 0, 0, 0};
  uint8_t h[NQKFHDR + 1568], *a = NULL, *e = NULL, nx = 0;
  size_t hl = 0, cl, got = 0, en = 0;
  unsigned long chunk = NQKFCHUNK;
  FILE *in = NULL, *of = NULL;
  int bad = 1, more;

  if (ncargs("box", argc, argv, o, sizeof o / sizeof o[0], &np, &help) !=
      NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "box");
    return NCOK;
  }
  if (nkp == 0 || out == NULL || np != 1) {
    ncuse(stderr, "box");
    return NCUSE;
  }
  kp = kps[0];
  armout = arm;
  if (sp == NULL && (pwo.fd != NULL || pwo.env != NULL)) {
    ncmsg("box", "--pass-fd and --pass-env give the passphrase of the "
          "--sign key; there is none");
    return NCUSE;
  }
  if (pwo.fd != NULL && strcmp(pwo.fd, "0") == 0 &&
      strcmp(argv[0], "-") == 0) {
    ncmsg("box", "--pass-fd 0 and a file on stdin cannot share it");
    return NCUSE;
  }
  cl = ctx != NULL ? strlen(ctx) : 0;
  if (cl > 255) {
    ncmsg("box", "the context is %lu bytes; at most 255 are allowed",
          (unsigned long)cl);
    return NCUSE;
  }
  if (cs != NULL) {
    char *end;
    chunk = strtoul(cs, &end, 10);
    if (*cs == '\0' || *end != '\0' || chunk < NQKFCMIN ||
        chunk > NQKFCMAX) {
      ncmsg("box", "--chunk takes %u to %u bytes", NQKFCMIN, NQKFCMAX);
      return NCUSE;
    }
  }
  /* one key and no signature: the stream of one recipient, as before */
  if (nkp > 1 || sp != NULL)
    return boxm(kps, nkp, sp, &pwo, out, ctx, cl, chunk, force, argv[0]);
  if (nckrd("box", kp, &k) != NCOK)
    return NCUSE;
  if (kemkey("box", kp, &k) != NCOK || nqksize((nqkalg)k.a.alg, &z) != NQOK)
    goto done;
  ncbin();
  a = (uint8_t *)malloc(chunk);
  e = (uint8_t *)malloc(chunk + 16);
  if (a == NULL || e == NULL) {
    nclib("box", "memory", NQEMEM);
    goto done;
  }
  in = opin("box", argv[0]);
  if (in == NULL)
    goto done;
  of = opout("box", out, force, 0);
  if (of == NULL)
    goto done;
  rc = nqkfeini(&c, (nqkalg)k.a.alg, k.b, k.n, (const uint8_t *)ctx, cl,
                (uint32_t)chunk, h, sizeof h, &hl);
  if (rc != NQOK) {
    nclib("box", "sealing", rc);
    goto done;
  }
  if (put(h, hl) != NQOK) {
    ncmsg("box", "cannot write %s%s", out, ncwhy());
    nqwipe(&c, sizeof c);
    goto done;
  }
  /* a chunk is the last when no byte follows it */
  for (;;) {
    size_t pre = 0;
    if (got > 0) {
      a[0] = nx;
      pre = 1;
    }
    if (fill(in, a + pre, chunk - pre, &got) != NQOK) {
      ncmsg("box", "cannot read %s%s", argv[0], ncwhy());
      nqwipe(&c, sizeof c);
      goto done;
    }
    got += pre;
    more = got == chunk && peek(in, &nx);
    rc = more ? nqkfeupd(&c, a, got, e, chunk + 16, &en)
              : nqkfefin(&c, a, got, e, chunk + 16, &en);
    if (rc != NQOK) {
      nclib("box", "sealing", rc);
      goto done;
    }
    if (put(e, en) != NQOK) {
      ncmsg("box", "cannot write %s%s", out, ncwhy());
      if (more) nqwipe(&c, sizeof c);
      goto done;
    }
    if (!more)
      break;
  }
  bad = 0;
  ret = NCOK;
done:
  if (of != NULL)
    endout("box", of, out, bad, &ret);
  if (in != NULL && in != stdin)
    fclose(in);
  if (a != NULL)
    ncfree(a, chunk, 1);
  free(e);
  nckfree(&k);
  return ret;
}

/* unbox of a stream to several keys (noqtis-kstream-2), whose first
 * NQKMFIX bytes are at fx: k the reader's key; sp the sender's public
 * key file or NULL, any 1 to open a signed stream without it */
static int unboxm(FILE *in, const char *inp, const uint8_t *fx,
                  const nckey *k, const char *sp, int any, const char *out,
                  const char *ctx, size_t cl, int force) {
  nckey spk = {{0, 0, NULL}, 0, NULL, 0};
  nqkmctx c;
  nqsalg sg = (nqsalg)0;
  nqssz sz = {0, 0, 0};
  uint8_t *h = NULL, *e = NULL, *a = NULL;
  size_t hl = 0, nr = 0, got = 0, an = 0, rec = 0, full, win, have = 0;
  uint32_t chunk = 0;
  FILE *of = NULL;
  int rc, ret = NCUSE, bad = 1;

  rc = nqkmpeek(fx, NQKMFIX, &hl, &sg, &nr);
  if (rc != NQOK) {
    ncmsg("unbox", "%s is not a boxed stream this noqtis reads (%s)", inp,
          rc == NQELIM ? "its sizes are out of range"
          : rc == NQENOSUP ? "its signature algorithm is not known"
                           : "another format");
    return NCUSE;
  }
  if (sg != 0 && sp == NULL && !any) {
    ncmsg("unbox", "%s is signed by its sender (%s): give the sender's "
          "public key with -s, or --any-sender to open it without knowing "
          "who sent it", inp, nqsname(sg));
    return NCUSE;
  }
  if (sg == 0 && sp != NULL) {
    ncmsg("unbox", "%s is not signed: nothing shows it comes from the "
          "holder of %s; without -s it opens as a stream from anyone", inp,
          sp);
    return NCUSE;
  }
  if (sp != NULL) {
    if (nckrd("unbox", sp, &spk) != NCOK) return NCUSE;
    if (spk.a.kem || spk.a.alg != (int)sg) {
      ncmsg("unbox", "%s is signed with %s, and %s is a %s key", inp,
            nqsname(sg), sp, spk.a.name);
      goto done;
    }
  }
  if (sg != 0) {
    (void)nqssize(sg, &sz);
    rec = sz.sig + 16;
  }
  /* what nqkmpeek let through is within these; the allocations say
   * so themselves */
  if (hl < NQKMFIX || hl > NQKMFIX + NQKMRCP * (size_t)(1 + 8 + 1568 + 48) ||
      rec > 65536) {
    nclib("unbox", "opening", NQELIM);
    goto done;
  }
  h = (uint8_t *)malloc(hl);
  if (h == NULL) {
    nclib("unbox", "memory", NQEMEM);
    goto done;
  }
  memcpy(h, fx, NQKMFIX);
  if (fill(in, h + NQKMFIX, hl - NQKMFIX, &got) != NQOK ||
      got != hl - NQKMFIX) {
    ncmsg("unbox", "%s is cut short: its header is %lu bytes", inp,
          (unsigned long)hl);
    goto done;
  }
  rc = nqkmdini(&c, (nqkalg)k->a.alg, k->b, k->n, (const uint8_t *)ctx, cl,
                h, hl, &chunk, NULL);
  if (rc == NQEVRFY) {
    ncmsg("unbox", "%s is not sealed to this key (it names %lu "
          "recipient%s), or was sealed with another context", inp,
          (unsigned long)nr, nr == 1 ? "" : "s");
    goto done;
  }
  if (rc == NQEDEC || rc == NQELIM) {
    ncmsg("unbox", "%s is not a boxed stream this noqtis reads (its "
          "header is damaged)", inp);
    goto done;
  }
  if (rc != NQOK) {
    nclib("unbox", "opening", rc);
    goto done;
  }
  /* the window: one chunk, the record after the last, and one byte
   * more; full, a chunk is not the last */
  if (chunk < NQKFCMIN || chunk > NQKFCMAX) {
    nqwipe(&c, sizeof c);
    nclib("unbox", "opening", NQELIM);
    goto done;
  }
  full = (size_t)chunk + 16;
  win = full + rec + 1;
  e = (uint8_t *)malloc(win);
  a = (uint8_t *)malloc(chunk);
  if (e == NULL || a == NULL) {
    nqwipe(&c, sizeof c);
    nclib("unbox", "memory", NQEMEM);
    goto done;
  }
  of = opout("unbox", out, force, 1);
  if (of == NULL) {
    nqwipe(&c, sizeof c);
    goto done;
  }
  for (;;) {
    int more;
    if (fill(in, e + have, win - have, &got) != NQOK) {
      ncmsg("unbox", "cannot read %s%s", inp, ncwhy());
      nqwipe(&c, sizeof c);
      goto done;
    }
    have += got;
    more = have == win;
    rc = more ? nqkmdupd(&c, e, full, a, chunk, &an)
              : nqkmdfin(&c, e, have, sp != NULL ? spk.b : NULL,
                         sp != NULL ? spk.n : 0, a, chunk, &an);
    if (rc != NQOK) {
      ncmsg("unbox", "%s does not verify: it was changed or cut%s%s", inp,
            sp != NULL ? ", or was not signed by the holder of the -s key"
                       : "",
            of == stdout ? "; what was written before stops here"
                         : "; nothing was kept");
      goto done;
    }
    if (fwrite(a, 1, an, of) != an) {
      ncmsg("unbox", "cannot write %s%s", out, ncwhy());
      if (more) nqwipe(&c, sizeof c);
      goto done;
    }
    if (!more) break;
    have -= full;
    memmove(e, e + full, have);
  }
  if (!ncarok(&ain)) {
    ncmsg("unbox", "%s: its armor does not end as one%s", inp,
          of == stdout ? "; what was written is whole"
                       : "; nothing was kept");
    goto done;
  }
  bad = 0;
  ret = NCOK;
done:
  if (of != NULL) endout("unbox", of, out, bad, &ret);
  if (ret != NCOK && of == stdout) ret = NCUSE;
  if (a != NULL) ncfree(a, chunk, 1);
  free(e);
  free(h);
  nckfree(&spk);
  return ret;
}

int ncunbox(int argc, char **argv) {
  const char *kp = NULL, *out = NULL, *ctx = NULL, *sp = NULL;
  int force = 0, help = 0, np, rc, ret = NCUSE, bad = 1, more, any = 0;
  ncpw pwo = {NULL, NULL};
  ncopt o[] = {
    {'k', "key", 1, &kp, NULL},
    {'o', "out", 1, &out, NULL},
    {'c', "ctx", 1, &ctx, NULL},
    {'s', "sender", 1, &sp, NULL},
    {'\0', "any-sender", 0, NULL, &any},
    {'\0', "pass-fd", 1, &pwo.fd, NULL},
    {'\0', "pass-env", 1, &pwo.env, NULL},
    {'f', "force", 0, NULL, &force}
  };
  nckey k = {{0, 0, NULL}, 0, NULL, 0};
  nqkfctx c;
  nqksz z = {0, 0, 0, 0};
  uint8_t h[NQKFHDR + 1568], *e = NULL, *a = NULL, nx = 0;
  size_t cl, got = 0, an = 0, hn = 0;
  uint32_t chunk = 0;
  FILE *in = NULL, *of = NULL;

  if (ncargs("unbox", argc, argv, o, sizeof o / sizeof o[0], &np, &help) !=
      NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "unbox");
    return NCOK;
  }
  if (kp == NULL || out == NULL || np != 1 || (sp != NULL && any)) {
    ncuse(stderr, "unbox");
    return NCUSE;
  }
  cl = ctx != NULL ? strlen(ctx) : 0;
  if (cl > 255) {
    ncmsg("unbox", "the context is %lu bytes; at most 255 are allowed",
          (unsigned long)cl);
    return NCUSE;
  }
  if (pwo.fd != NULL && strcmp(pwo.fd, "0") == 0 &&
      strcmp(argv[0], "-") == 0) {
    ncmsg("unbox", "--pass-fd 0 and a stream on stdin cannot share it");
    return NCUSE;
  }
  if (ncskrd("unbox", kp, &pwo, "pass", &k) != NCOK)
    return NCUSE;
  if (kemkey("unbox", kp, &k) != NCOK ||
      nqksize((nqkalg)k.a.alg, &z) != NQOK)
    goto done;
  ncbin();
  in = opin("unbox", argv[0]);
  if (in == NULL)
    goto done;
  if (ncarbeg(&ain, in, NCLBOX) != NQOK) {
    ncmsg("unbox", "%s is armored, but not as a sealed stream (-----BEGIN "
          NCLBOX "-----)", argv[0]);
    goto done;
  }
  /* the first bytes say which stream it is */
  if (fill(in, h, NQKMFIX, &hn) != NQOK || hn != NQKMFIX) {
    ncmsg("unbox", "%s is not a stream boxed for a %s key (too short)",
          argv[0], k.a.name);
    goto done;
  }
  if (memcmp(h, "NQKM", 4) == 0) {
    ret = unboxm(in, argv[0], h, &k, sp, any, out, ctx, cl, force);
    goto done;
  }
  if (sp != NULL) {
    ncmsg("unbox", "%s is not signed (a stream to one key carries no "
          "signature): nothing shows it comes from the holder of %s; "
          "without -s it opens as a stream from anyone", argv[0], sp);
    goto done;
  }
  if (fill(in, h + NQKMFIX, NQKFHDR + z.ct - NQKMFIX, &hn) != NQOK ||
      hn != NQKFHDR + z.ct - NQKMFIX) {
    ncmsg("unbox", "%s is not a stream boxed for a %s key (too short)",
          argv[0], k.a.name);
    goto done;
  }
  hn = NQKFHDR + z.ct;
  rc = nqkfdini(&c, (nqkalg)k.a.alg, k.b, k.n, (const uint8_t *)ctx, cl, h,
                hn, &chunk);
  if (rc == NQEDEC || rc == NQELIM) {
    ncmsg("unbox", "%s is not a stream boxed for a %s key (%s)", argv[0],
          k.a.name, rc == NQELIM ? "its chunk size is out of range"
                                 : "another format or key");
    goto done;
  }
  if (rc != NQOK) {
    nclib("unbox", "opening", rc);
    goto done;
  }
  /* the library took the chunk size only within its limits; the
   * allocation says so itself */
  if (chunk < NQKFCMIN || chunk > NQKFCMAX) {
    nqwipe(&c, sizeof c);
    nclib("unbox", "opening", NQELIM);
    goto done;
  }
  e = (uint8_t *)malloc((size_t)chunk + 16);
  a = (uint8_t *)malloc(chunk);
  if (e == NULL || a == NULL) {
    nqwipe(&c, sizeof c);
    nclib("unbox", "memory", NQEMEM);
    goto done;
  }
  of = opout("unbox", out, force, 1);
  if (of == NULL) {
    nqwipe(&c, sizeof c);
    goto done;
  }
  for (;;) {
    size_t pre = 0;
    if (got > 0) {
      e[0] = nx;
      pre = 1;
    }
    if (fill(in, e + pre, (size_t)chunk + 16 - pre, &got) != NQOK) {
      ncmsg("unbox", "cannot read %s%s", argv[0], ncwhy());
      nqwipe(&c, sizeof c);
      goto done;
    }
    got += pre;
    more = got == (size_t)chunk + 16 && peek(in, &nx);
    rc = more ? nqkfdupd(&c, e, got, a, chunk, &an)
              : nqkfdfin(&c, e, got, a, chunk, &an);
    if (rc != NQOK) {
      ncmsg("unbox", "%s does not verify: it was changed or cut, or is "
            "not for this key or context%s", argv[0],
            of == stdout ? "; what was written before stops here"
                         : "; nothing was kept");
      goto done;
    }
    if (fwrite(a, 1, an, of) != an) {
      ncmsg("unbox", "cannot write %s%s", out, ncwhy());
      if (more) nqwipe(&c, sizeof c);
      goto done;
    }
    if (!more)
      break;
  }
  if (!ncarok(&ain)) {
    ncmsg("unbox", "%s: its armor does not end as one%s", argv[0],
          of == stdout ? "; what was written is whole"
                       : "; nothing was kept");
    goto done;
  }
  bad = 0;
  ret = NCOK;
done:
  if (of != NULL)
    endout("unbox", of, out, bad, &ret);
  if (ret != NCOK && of == stdout)
    ret = NCUSE;
  if (in != NULL && in != stdin)
    fclose(in);
  if (a != NULL)
    ncfree(a, chunk, 1);
  free(e);
  nckfree(&k);
  return ret;
}
