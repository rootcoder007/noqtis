/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * noqtis: algorithm names and key files.
 *
 * A key file is text: one header line
 *   noqtis-key-1 <algorithm> <pub|sec>
 * then the key bytes, in the standard's encoding, as base64 (RFC 4648,
 * padded) in lines of 64 characters. See DESIGN.md, "CLI".
 */
#include "cli.h"

#include <stdlib.h>
#include <string.h>

#define NCMAGIC "noqtis-key-1"

static int lower(int c) {
  return c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c;
}

static int same(const char *a, const char *b) {
  for (; *a != '\0' && *b != '\0'; a++, b++) {
    if (lower((unsigned char)*a) != lower((unsigned char)*b))
      return 0;
  }
  return *a == *b;
}

int ncfind(const char *name, ncalg *a) {
  int i;
  for (i = 1; i <= 64; i++) {
    const char *n = nqsname((nqsalg)i);
    if (n == NULL)
      break;
    if (same(n, name)) {
      a->kem = 0;
      a->alg = i;
      a->name = n;
      return NQOK;
    }
  }
  for (i = 1; i <= 64; i++) {
    const char *n = nqkname((nqkalg)i);
    if (n == NULL)
      break;
    if (same(n, name)) {
      a->kem = 1;
      a->alg = i;
      a->name = n;
      return NQOK;
    }
  }
  return NQENOSUP;
}

int ncksz(const ncalg *a, size_t *pk, size_t *sk) {
  int rc;
  if (a->kem) {
    nqksz z = {0, 0, 0, 0};
    rc = nqksize((nqkalg)a->alg, &z);
    *pk = z.pk;
    *sk = z.sk;
  } else {
    nqssz z = {0, 0, 0};
    rc = nqssize((nqsalg)a->alg, &z);
    *pk = z.pk;
    *sk = z.sk;
  }
  return rc;
}

void nckfree(nckey *k) {
  ncfree(k->b, k->n, k->sec);
  k->b = NULL;
  k->n = 0;
}

int nckrd(const char *cmd, const char *path, int sec, nckey *k) {
  uint8_t *t;
  size_t tn, hl, pk, sk, want, i;
  char hdr[96], *alg, *kind;
  int rc;
  k->b = NULL;
  k->n = 0;
  k->sec = sec;
  rc = ncrdx(path, 1, NCRDSMALL, &t, &tn);
  if (rc != NQOK) {
    ncmsg(cmd, "cannot read key file %s (missing or unreadable; give a key "
          "file `noqtis keygen` wrote)", path);
    return NCUSE;
  }
  for (hl = 0; hl < tn && t[hl] != '\n'; hl++)
    ;
  if (hl == tn || hl >= sizeof hdr)
    goto bad;
  memcpy(hdr, t, hl);
  hdr[hl] = '\0';
  if (hl > 0 && hdr[hl - 1] == '\r')
    hdr[hl - 1] = '\0';
  alg = strchr(hdr, ' ');
  if (alg == NULL)
    goto bad;
  *alg++ = '\0';
  kind = strchr(alg, ' ');
  if (kind == NULL)
    goto bad;
  *kind++ = '\0';
  if (strcmp(hdr, NCMAGIC) != 0 || strchr(kind, ' ') != NULL)
    goto bad;
  if (strcmp(kind, "sec") == 0) {
    if (!sec) {
      ncmsg(cmd, "%s is a secret key; give the public key (.pub)", path);
      ncfree(t, tn, 1);
      return NCUSE;
    }
  } else if (strcmp(kind, "pub") == 0) {
    if (sec) {
      ncmsg(cmd, "%s is a public key; give the secret key", path);
      ncfree(t, tn, 1);
      return NCUSE;
    }
  } else {
    goto bad;
  }
  if (ncfind(alg, &k->a) != NQOK) {
    ncmsg(cmd, "%s: unknown algorithm %s (this noqtis knows the names "
          "`noqtis algs` lists)", path, alg);
    ncfree(t, tn, 1);
    return NCUSE;
  }
  if (ncksz(&k->a, &pk, &sk) != NQOK)
    goto bad;
  want = sec ? sk : pk;
  k->b = (uint8_t *)malloc(want);
  if (k->b == NULL) {
    ncfree(t, tn, 1);
    return nclib(cmd, path, NQEMEM);
  }
  rc = ncb64d((const char *)t + hl + 1, tn - hl - 1, k->b, want, &i);
  ncfree(t, tn, 1);
  if (rc != NQOK || i != want) {
    ncfree(k->b, want, 1);
    k->b = NULL;
    ncmsg(cmd, "%s: the key is not %lu bytes of base64 for %s (the file "
          "is damaged or cut short; use the file keygen wrote)", path,
          (unsigned long)want, k->a.name);
    return NCUSE;
  }
  k->n = want;
  return NCOK;
bad:
  ncfree(t, tn, 1);
  ncmsg(cmd, "%s is not a noqtis key file (want a first line \""
        NCMAGIC " <alg> <pub|sec>\")", path);
  return NCUSE;
}

int nckwr(FILE *f, const ncalg *a, int sec, const uint8_t *b, size_t n) {
  size_t en = ncb64n(n);
  char *e = (char *)malloc(en);
  int ok;
  if (e == NULL)
    return NQEMEM;
  ncb64e(b, n, e);
  ok = fprintf(f, NCMAGIC " %s %s\n", a->name, sec ? "sec" : "pub") > 0 &&
       fwrite(e, 1, en, f) == en;
  ncfree(e, en, sec);
  return ok ? NQOK : NQEIO;
}
