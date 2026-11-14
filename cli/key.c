/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * noqtis: algorithm names and key files.
 *
 * A key file is text: one header line
 *   noqtis-key-1 <algorithm> <pub|sec>
 * then the key bytes, in the standard's encoding, as base64 (RFC 4648,
 * padded) in lines of 64 characters. See DESIGN.md, "CLI". A secret key
 * under a passphrase has the same first line; its body is the
 * noqtis-pwkey-1 bytes of nqpwenc (NQPWOVH bytes longer than the key,
 * starting "NQPW"), with that line, as nckwrp writes it, for their
 * associated data.
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

/* the first line of a secret key file of a, the passphrase's ad */
static size_t adof(const ncalg *a, char *ad, size_t cap) {
  int n = snprintf(ad, cap, NCMAGIC " %s sec", a->name);
  return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

int nckrd(const char *cmd, const char *path, int sec, nckey *k) {
  return nckrdp(cmd, path, sec, NULL, 0, k);
}

int nckrdp(const char *cmd, const char *path, int sec, const uint8_t *pw,
           size_t pwn, nckey *k) {
  uint8_t *t, *d;
  size_t tn, hl, pk, sk, want, i, dn;
  char hdr[96], ad[96], *alg, *kind;
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
  /* room for a key under a passphrase too */
  dn = want + (sec ? NQPWOVH : 0);
  d = (uint8_t *)malloc(dn);
  if (d == NULL) {
    ncfree(t, tn, 1);
    return nclib(cmd, path, NQEMEM);
  }
  rc = ncb64d((const char *)t + hl + 1, tn - hl - 1, d, dn, &i);
  ncfree(t, tn, 1);
  if (rc == NQOK && sec && i == dn && memcmp(d, "NQPW", 4) == 0) {
    size_t an = adof(&k->a, ad, sizeof ad), got = 0;
    if (pw == NULL) {
      ncfree(d, dn, 1);
      ncmsg(cmd, "%s is protected by a passphrase: give it with --pass-fd "
            "<n> or --pass-env <name> (keygen, sign and dec take them)",
            path);
      return NCUSE;
    }
    k->b = (uint8_t *)malloc(want);
    rc = k->b == NULL ? NQEMEM
                      : nqpwdec(pw, pwn, (const uint8_t *)ad, an, d, dn,
                                k->b, want, &got);
    ncfree(d, dn, 1);
    if (rc != NQOK || got != want) {
      ncfree(k->b, want, 1);
      k->b = NULL;
      if (rc == NQEVRFY)
        ncmsg(cmd, "%s: wrong passphrase, or the key file was changed",
              path);
      else if (rc == NQELIM)
        ncmsg(cmd, "%s asks for more memory or passes than noqtis allows "
              "(at most %u MiB, %u passes, %u lanes); it was not written "
              "by noqtis keygen", path, NQPWMMAX / 1024, NQPWTMAX,
              NQPWPMAX);
      else if (rc == NQEMEM)
        nclib(cmd, path, NQEMEM);
      else
        ncmsg(cmd, "%s: the passphrase-protected key is damaged (%s)", path,
              nqerr(rc));
      return NCUSE;
    }
    k->n = want;
    return NCOK;
  }
  if (rc != NQOK || i != want) {
    ncfree(d, dn, 1);
    ncmsg(cmd, "%s: the key is not %lu bytes of base64 for %s (the file "
          "is damaged or cut short; use the file keygen wrote)", path,
          (unsigned long)want, k->a.name);
    return NCUSE;
  }
  if (pw != NULL)
    ncmsg(cmd, "warning: %s is not protected by a passphrase; the "
          "passphrase was not used", path);
  k->b = d;
  k->n = want;
  return NCOK;
bad:
  ncfree(t, tn, 1);
  ncmsg(cmd, "%s is not a noqtis key file (want a first line \""
        NCMAGIC " <alg> <pub|sec>\")", path);
  return NCUSE;
}

int nckwrp(FILE *f, const ncalg *a, const uint8_t *pw, size_t pwn,
           const uint8_t *b, size_t n) {
  char ad[96];
  size_t an = adof(a, ad, sizeof ad), on = 0;
  uint8_t *e = (uint8_t *)malloc(n + NQPWOVH);
  int rc;
  if (e == NULL)
    return NQEMEM;
  rc = nqpwenc(pw, pwn, (const uint8_t *)ad, an, 0, 0, 0, b, n, e,
               n + NQPWOVH, &on);
  if (rc == NQOK)
    rc = nckwr(f, a, 1, e, on);
  ncfree(e, n + NQPWOVH, 1);
  return rc;
}

/* the decimal descriptor number of --pass-fd; -1 if it is not one */
static int fdnum(const char *s) {
  long v = 0;
  if (*s == '\0')
    return -1;
  for (; *s != '\0'; s++) {
    if (*s < '0' || *s > '9' || v > 100000)
      return -1;
    v = v * 10 + (*s - '0');
  }
  return (int)v;
}

int ncpwget(const char *cmd, const ncpw *o, uint8_t **b, size_t *n) {
  *b = NULL;
  *n = 0;
  if (o->fd == NULL && o->env == NULL)
    return NCOK;
  if (o->fd != NULL && o->env != NULL) {
    ncmsg(cmd, "give one of --pass-fd and --pass-env, not both");
    return NCUSE;
  }
  *b = (uint8_t *)malloc(NQPWLEN);
  if (*b == NULL)
    return nclib(cmd, "memory", NQEMEM);
  if (o->fd != NULL) {
    int fd = fdnum(o->fd), rc;
    if (fd < 0) {
      ncmsg(cmd, "--pass-fd wants a descriptor number, not %s",
            ncesc(o->fd));
      goto fail;
    }
    rc = ncrdfd(fd, *b, NQPWLEN, n);
    if (rc == NQELIM) {
      ncmsg(cmd, "the passphrase on descriptor %d is over %u bytes", fd,
            NQPWLEN);
      goto fail;
    }
    if (rc != NQOK) {
      ncmsg(cmd, "cannot read a passphrase from descriptor %d", fd);
      goto fail;
    }
  } else {
    const char *v = getenv(o->env);
    size_t l = v != NULL ? strlen(v) : 0;
    if (l > NQPWLEN) {
      ncmsg(cmd, "the passphrase in %s is over %u bytes", ncesc(o->env),
            NQPWLEN);
      goto fail;
    }
    if (l > 0)
      memcpy(*b, v, l);
    *n = l;
  }
  if (*n == 0) {
    if (o->fd != NULL)
      ncmsg(cmd, "descriptor %s gave an empty passphrase", ncesc(o->fd));
    else
      ncmsg(cmd, "%s is not set, or empty", ncesc(o->env));
    goto fail;
  }
  return NCOK;
fail:
  ncfree(*b, NQPWLEN, 1);
  *b = NULL;
  *n = 0;
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
