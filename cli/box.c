/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis box and unbox: a file sealed to an ML-KEM public key in chunks
 * (noqtis-kstream-1, nqkfeini(3)), in memory of one chunk. unbox writes
 * a chunk's plaintext only once its tag has verified, and on any
 * failure removes the output file it was writing (on stdout it stops:
 * what was written had verified, but the stream is cut). */
#include "cli.h"

#include <stdlib.h>
#include <string.h>

/* reads up to n bytes (fewer only at the end); *got, or NQEIO */
static int fill(FILE *f, uint8_t *b, size_t n, size_t *got) {
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
  int x = fgetc(f);
  if (x == EOF) return 0;
  *c = (uint8_t)x;
  return 1;
}

static FILE *opin(const char *cmd, const char *p) {
  FILE *f = strcmp(p, "-") == 0 ? stdin : ncfopen(p, "rb");
  if (f == NULL) ncmsg(cmd, "cannot read %s", p);
  return f;
}

/* the output: stdout for "-", else a new file (sec: owner-only) */
static FILE *opout(const char *cmd, const char *p, int force, int sec) {
  FILE *f;
  if (strcmp(p, "-") == 0) return stdout;
  f = ncopen(p, force, sec);
  if (f == NULL) ncwfail(cmd, p, force);
  return f;
}

static void endout(const char *cmd, FILE *f, const char *p, int bad,
                   int *ret) {
  if (f == stdout) {
    if (fflush(f) != 0) *ret = NCUSE;
  } else if (ncclose(f, p, bad) != NQOK && !bad) {
    ncmsg(cmd, "cannot write %s", p);
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

int ncbox(int argc, char **argv) {
  const char *kp = NULL, *out = NULL, *ctx = NULL, *cs = NULL;
  int force = 0, help = 0, np, rc, ret = NCUSE;
  ncopt o[] = {
    {'p', "pub", 1, &kp, NULL},
    {'o', "out", 1, &out, NULL},
    {'c', "ctx", 1, &ctx, NULL},
    {'\0', "chunk", 1, &cs, NULL},
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
  if (kp == NULL || out == NULL || np != 1) {
    ncuse(stderr, "box");
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
  if (nckrd("box", kp, 0, &k) != NCOK)
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
  if (fwrite(h, 1, hl, of) != hl) {
    ncmsg("box", "cannot write %s", out);
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
      ncmsg("box", "cannot read %s", argv[0]);
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
    if (fwrite(e, 1, en, of) != en) {
      ncmsg("box", "cannot write %s", out);
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

int ncunbox(int argc, char **argv) {
  const char *kp = NULL, *out = NULL, *ctx = NULL;
  int force = 0, help = 0, np, rc, ret = NCUSE, bad = 1, more;
  ncpw pwo = {NULL, NULL};
  ncopt o[] = {
    {'k', "key", 1, &kp, NULL},
    {'o', "out", 1, &out, NULL},
    {'c', "ctx", 1, &ctx, NULL},
    {'\0', "pass-fd", 1, &pwo.fd, NULL},
    {'\0', "pass-env", 1, &pwo.env, NULL},
    {'f', "force", 0, NULL, &force}
  };
  nckey k = {{0, 0, NULL}, 0, NULL, 0};
  nqkfctx c;
  nqksz z = {0, 0, 0, 0};
  uint8_t h[NQKFHDR + 1568], *e = NULL, *a = NULL, *pw = NULL, nx = 0;
  size_t cl, got = 0, pn = 0, an = 0, hn = 0;
  uint32_t chunk = 0;
  FILE *in = NULL, *of = NULL;

  if (ncargs("unbox", argc, argv, o, sizeof o / sizeof o[0], &np, &help) !=
      NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "unbox");
    return NCOK;
  }
  if (kp == NULL || out == NULL || np != 1) {
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
  if (ncpwget("unbox", &pwo, &pw, &pn) != NCOK)
    return NCUSE;
  rc = nckrdp("unbox", kp, 1, pw, pn, &k);
  ncfree(pw, NQPWLEN, 1);
  if (rc != NCOK)
    return NCUSE;
  if (kemkey("unbox", kp, &k) != NCOK ||
      nqksize((nqkalg)k.a.alg, &z) != NQOK)
    goto done;
  ncbin();
  in = opin("unbox", argv[0]);
  if (in == NULL)
    goto done;
  if (fill(in, h, NQKFHDR + z.ct, &hn) != NQOK || hn != NQKFHDR + z.ct) {
    ncmsg("unbox", "%s is not a stream boxed for a %s key (too short)",
          argv[0], k.a.name);
    goto done;
  }
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
      ncmsg("unbox", "cannot read %s", argv[0]);
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
      ncmsg("unbox", "cannot write %s", out);
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
