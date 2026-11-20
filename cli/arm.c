/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * noqtis: ASCII armor (RFC 7468) as files are written and read, a line at
 * a time, so that a stream of any length can be armored; the commands
 * armor and dearmor; and ncunarm for what is small (a signature).
 */
#include "cli.h"

#include <stdlib.h>
#include <string.h>

static int ws(int c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/* ---- writing ---- */

int ncawbeg(ncaw *w, FILE *f, const char *label) {
  size_t n;
  w->f = f;
  w->n = 0;
  w->on = label != NULL;
  if (!w->on) return NQOK;
  /* a label this noqtis would read back */
  if (nqarmlen(label, 0, &n) != NQOK) return NQEARG;
  memcpy(w->lab, label, strlen(label) + 1);
  return fprintf(f, "-----BEGIN %s-----\n", label) < 0 ? NQEIO : NQOK;
}

static int line(ncaw *w) {
  char t[66];
  ncb64e(w->b, w->n, t);
  if (fwrite(t, 1, ncb64n(w->n), w->f) != ncb64n(w->n)) return NQEIO;
  w->n = 0;
  return NQOK;
}

int ncawput(ncaw *w, const uint8_t *p, size_t n) {
  if (!w->on) return fwrite(p, 1, n, w->f) == n ? NQOK : NQEIO;
  while (n > 0) {
    size_t k = sizeof w->b - w->n;
    if (k > n) k = n;
    memcpy(w->b + w->n, p, k);
    w->n += k;
    p += k;
    n -= k;
    if (w->n == sizeof w->b && line(w) != NQOK) return NQEIO;
  }
  return NQOK;
}

int ncawend(ncaw *w) {
  if (!w->on) return NQOK;
  w->on = 0;
  if (w->n > 0 && line(w) != NQOK) return NQEIO;
  return fprintf(w->f, "-----END %s-----\n", w->lab) < 0 ? NQEIO : NQOK;
}

/* ---- reading ---- */

/* the rest of a line "-----<word> <label>-----" whose first dash was
 * read: NQOK with the label in lab */
static int edge(FILE *f, const char *word, char *lab) {
  char t[16 + NQARMLAB];
  size_t n = 0, wl = strlen(word), k;
  int c;
  while ((c = fgetc(f)) != EOF && c != '\n' && n + 1 < sizeof t)
    t[n++] = (char)c;
  while (n > 0 && ws(t[n - 1])) n--;
  t[n] = '\0';
  if (c != '\n' && c != EOF) return NQEDEC;
  if (n < 4 + wl + 1 + 1 + 5 || memcmp(t, "----", 4) != 0 ||
      memcmp(t + 4, word, wl) != 0 || t[4 + wl] != ' ' ||
      memcmp(t + n - 5, "-----", 5) != 0)
    return NQEDEC;
  k = n - 5 - (4 + wl + 1);
  memcpy(lab, t + 4 + wl + 1, k);
  lab[k] = '\0';
  /* a label as nqarmenc takes them */
  return nqarmlen(lab, 0, &k) == NQOK ? NQOK : NQEDEC;
}

int ncarbeg(ncar *r, FILE *f, const char *label) {
  int c;
  memset(r, 0, sizeof *r);
  r->f = f;
  c = fgetc(f);
  if (c == EOF) return NQOK;
  if (c != '-') {
    ungetc(c, f);
    return NQOK;
  }
  if (edge(f, "BEGIN", r->lab) != NQOK) return NQEDEC;
  if (label != NULL && strcmp(label, r->lab) != 0) return NQEDEC;
  r->on = 1;
  r->bol = 1;
  return NQOK;
}

/* more bytes into r->b, or the END line: NQEDEC when the armor is not
 * one, NQEIO when the file cannot be read */
static int more(ncar *r) {
  char q[4];
  size_t nq = 0, k;
  r->at = 0;
  r->n = 0;
  while (r->n + 3 <= sizeof r->b && !r->end) {
    int c = fgetc(r->f);
    if (c == EOF) return ferror(r->f) ? NQEIO : NQEDEC;
    if (ws(c)) {
      if (c == '\n') r->bol = 1;
      continue;
    }
    if (c == '-') {
      char lab[NQARMLAB];
      if (nq != 0 || !r->bol || edge(r->f, "END", lab) != NQOK ||
          strcmp(lab, r->lab) != 0)
        return NQEDEC;
      while ((c = fgetc(r->f)) != EOF) {
        if (!ws(c)) return NQEDEC;
      }
      if (ferror(r->f)) return NQEIO;
      r->end = 1;
      break;
    }
    r->bol = 0;
    if (r->pad) return NQEDEC;
    q[nq++] = (char)c;
    if (nq < 4) continue;
    nq = 0;
    r->pad = q[3] == '=';
    if (ncb64d(q, 4, r->b + r->n, 3, &k) != NQOK) return NQEDEC;
    r->n += k;
  }
  return NQOK;
}

int ncarget(ncar *r, uint8_t *p, size_t n, size_t *got) {
  *got = 0;
  if (!r->on) {
    while (*got < n) {
      size_t k = fread(p + *got, 1, n - *got, r->f);
      if (k == 0) break;
      *got += k;
    }
    return ferror(r->f) ? NQEIO : NQOK;
  }
  while (*got < n) {
    size_t k;
    if (r->at == r->n) {
      int rc;
      if (r->end) break;
      rc = more(r);
      if (rc != NQOK) {
        r->bad = 1;
        r->dec = rc == NQEDEC;
        return NQEIO;
      }
      continue;
    }
    k = r->n - r->at;
    if (k > n - *got) k = n - *got;
    memcpy(p + *got, r->b + r->at, k);
    r->at += k;
    *got += k;
  }
  return NQOK;
}

int ncarpeek(ncar *r, uint8_t *c) {
  if (!r->on) {
    int x = fgetc(r->f);
    if (x == EOF) return 0;
    *c = (uint8_t)x;
    return 1;
  }
  if (r->at == r->n) {
    int rc;
    if (r->end) return 0;
    rc = more(r);
    if (rc != NQOK) {
      /* the caller sees an end; ncarok says it was not one */
      r->bad = 1;
      return 0;
    }
    if (r->n == 0) return 0;
  }
  *c = r->b[r->at++];
  return 1;
}

int ncarok(const ncar *r) {
  return !r->on || (r->end && !r->bad && r->at == r->n);
}

int ncunarm(const char *label, uint8_t *b, size_t *n) {
  char lab[NQARMLAB];
  size_t i = 0, k;
  uint8_t *o;
  int rc;
  while (i < *n && ws(b[i])) i++;
  if (*n - i < 10 || memcmp(b + i, "-----BEGIN", 10) != 0) return NQOK;
  o = (uint8_t *)malloc(*n);
  if (o == NULL) return NQEMEM;
  rc = nqarmdec((const char *)b, *n, lab, sizeof lab, o, *n, &k);
  if (rc == NQOK && strcmp(lab, label) != 0) rc = NQEDEC;
  if (rc == NQOK) {
    memcpy(b, o, k);
    *n = k;
  }
  free(o);
  return rc;
}

/* ---- the commands ---- */

static int run(const char *cmd, int argc, char **argv, int arm) {
  const char *out = NULL, *lab = NULL, *inp = "-";
  int force = 0, help = 0, np, ret = NCUSE, bad = 1, rc = NQOK;
  ncopt oa[] = {
    {'o', "out", 1, &out, NULL},
    {'f', "force", 0, NULL, &force},
    {'l', "label", 1, &lab, NULL}
  };
  uint8_t buf[4096];
  size_t got = 0;
  FILE *in = NULL, *of = NULL;
  ncaw w;
  ncar r;

  if (ncargs(cmd, argc, argv, oa, arm ? 3 : 2, &np, &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, cmd);
    return NCOK;
  }
  if (np > 1) {
    ncuse(stderr, cmd);
    return NCUSE;
  }
  if (np == 1) inp = argv[0];
  if (lab == NULL) lab = NCLDATA;
  if (arm && nqarmlen(lab, 0, &got) != NQOK) {
    ncmsg(cmd, "a label is capitals and digits with single spaces between "
          "them, at most %u characters", (unsigned)NQARMLAB - 1);
    return NCUSE;
  }
  ncbin();
  in = strcmp(inp, "-") == 0 ? stdin : ncfopen(inp, "rb");
  if (in == NULL) {
    ncmsg(cmd, "cannot read %s%s", inp, ncwhy());
    return NCUSE;
  }
  if (!arm) {
    if (ncarbeg(&r, in, NULL) != NQOK || !r.on) {
      ncmsg(cmd, "%s is not armored: it does not start with a line "
            "-----BEGIN <label>-----", inp);
      goto done;
    }
  } else {
    memset(&r, 0, sizeof r);
    r.f = in;
  }
  if (out == NULL || strcmp(out, "-") == 0) {
    of = stdout;
    out = "-";
  } else {
    of = ncopen(out, force, 0);
    if (of == NULL) {
      ncwfail(cmd, out, force);
      goto done;
    }
  }
  if (ncawbeg(&w, of, arm ? lab : NULL) != NQOK) rc = NQEIO;
  while (rc == NQOK) {
    if (ncarget(&r, buf, sizeof buf, &got) != NQOK) {
      if (r.dec)
        ncmsg(cmd, "%s is not one whole armor: its text was changed or "
              "cut", inp);
      else
        ncmsg(cmd, "cannot read %s%s", inp, ncwhy());
      goto done;
    }
    if (got == 0) break;
    rc = ncawput(&w, buf, got);
  }
  if (rc == NQOK) rc = ncawend(&w);
  if (rc != NQOK) {
    ncmsg(cmd, "cannot write %s%s", out, ncwhy());
    goto done;
  }
  bad = 0;
  ret = NCOK;
done:
  if (of == stdout) {
    if (fflush(of) != 0) ret = NCUSE;
  } else if (of != NULL && ncclose(of, out, bad) != NQOK && !bad) {
    ncmsg(cmd, "cannot write %s%s", out, ncwhy());
    ret = NCUSE;
  }
  if (in != stdin) fclose(in);
  return ret;
}

int ncarmor(int argc, char **argv) {
  return run("armor", argc, argv, 1);
}

int ncdearmor(int argc, char **argv) {
  return run("dearmor", argc, argv, 0);
}
