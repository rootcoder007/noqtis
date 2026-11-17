/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqdsetal: every public function of nqd under an allocator that fails
 * the Nth allocation, for N = 0, 1, ... until a call makes no more than
 * N: each failing call returns NQEMEM, frees all it took (none in use
 * after it) and gives qdfree the size each block was allocated with;
 * the call that no allocation fails returns what it does without the
 * hook. The hook's own checks: one NULL refused, both NULL restore
 * malloc. Run from tests/ (the fixtures in vectors/). */
#include "nqd/int.h"
#include "nqt.h"

#include <stdlib.h>
#include <string.h>

/* ---- an allocator that knows each block and can fail one ---- */

#define TSZ 65536 /* open addressing; far more than any call here holds */

static void *tp[TSZ];
static size_t ts[TSZ];
static size_t live;
static long left = -1; /* allocations before the one that fails */
static int failed, badfree;

/* the address alone: the block may not be written yet */
static size_t slot(uintptr_t p) {
  size_t i = (size_t)((p >> 4) * 2654435761u) & (TSZ - 1);
  while (tp[i] != NULL && (uintptr_t)tp[i] != p)
    i = (i + 1) & (TSZ - 1);
  return i;
}

static void *tmal(size_t n, void *u) {
  void *p = NULL;
  (void)u;
  if (left == 0) {
    left = -1;
    failed = 1;
    return NULL;
  }
  if (left > 0)
    left--;
  if (n == 0 || live >= TSZ / 2 || (p = malloc(n)) == NULL)
    return NULL;
  tp[slot((uintptr_t)p)] = p;
  ts[slot((uintptr_t)p)] = n;
  live++;
  return p;
}

static void tfree(void *p, size_t n, void *u) {
  size_t i = slot((uintptr_t)p), j;
  (void)u;
  if (tp[i] != p || ts[i] != n) {
    badfree++;
    fprintf(stderr, "tdal: a block of %lu bytes freed as %lu\n",
            (unsigned long)(tp[i] == p ? ts[i] : 0), (unsigned long)n);
    return; /* kept: a wrong size is the failure, not a second one */
  }
  free(p);
  tp[i] = NULL;
  live--;
  /* close the gap: move later entries of the run back */
  for (j = (i + 1) & (TSZ - 1); tp[j] != NULL; j = (j + 1) & (TSZ - 1)) {
    void *q = tp[j];
    size_t s = ts[j];
    tp[j] = NULL;
    tp[slot((uintptr_t)q)] = q;
    ts[slot((uintptr_t)q)] = s;
  }
}

/* ---- the sweep ---- */

static char tmp[400];
static char out[1 << 16], why[600];
static size_t on;

static const char *at(const char *name) {
  static char p[4][600];
  static int k = 0;
  k = (k + 1) % 4;
  qdwhy(p[k], sizeof p[k], "%s/%s", tmp, name);
  return p[k];
}

/* f once without a failure for its result, then with the Nth
 * allocation failing until none does; tidy runs after each call */
static void sweep(const char *name, int (*f)(void), void (*tidy)(void)) {
  int rc0, rc;
  long n;
  left = -1;
  rc0 = f();
  if (tidy != NULL)
    tidy();
  NQTEQI(live, 0);
  for (n = 0;; n++) {
    size_t b = live;
    failed = 0;
    left = n;
    rc = f();
    left = -1;
    if (tidy != NULL)
      tidy();
    if (live != b || badfree) {
      fprintf(stderr, "tdal: %s, allocation %ld failing: %lu blocks kept, "
              "%d bad frees\n", name, n, (unsigned long)(live - b),
              badfree);
      NQTCHK(0);
      badfree = 0;
    }
    if (!failed) {
      NQTEQI(rc, rc0);
      break;
    }
    if (rc != NQEMEM) {
      fprintf(stderr, "tdal: %s: allocation %ld failed, the call says "
              "%d, not NQEMEM\n", name, n, rc);
      NQTCHK(0);
    }
  }
  fprintf(stderr, "tdal: %s: %ld allocations swept\n", name, n);
}

/* ---- the calls ---- */

static char full[1 << 16], sch[4096], st[1 << 16], dst[1 << 16];
static size_t fulln, schn, stn, dstn;

static int fparse(void) {
  nqdrec *r = NULL;
  int rc = nqdparse(full, fulln, &r, why, sizeof why);
  if (rc == NQOK)
    rc = nqdjson(r, out, sizeof out, &on);
  nqdrfree(r);
  return rc;
}

/* a new record, changed every way, saved and read back */
static int fedit(void) {
  nqdrec *r = NULL;
  int rc = nqdnew(&r);
  if (rc == NQOK)
    rc = nqdsrc(r, "vectors/nqd/cap", "data/a.csv", why, sizeof why);
  if (rc == NQOK)
    rc = nqdset(r, "sources", "data/a.csv", "url",
                "\"https://example.org/a.csv\"", 27, why, sizeof why);
  if (rc == NQOK)
    rc = nqdput(r, "checks", "{\"name\":\"n\",\"status\":\"pass\"}", 29,
                why, sizeof why);
  if (rc == NQOK)
    rc = nqddel(r, "checks", "n");
  if (rc == NQOK)
    rc = nqdsave(r, tmp);
  nqdrfree(r);
  r = NULL;
  if (rc == NQOK)
    rc = nqdload(tmp, &r, why, sizeof why);
  nqdrfree(r);
  return rc;
}

/* a loaded record read every way */
static int fread1(void) {
  nqdrec *r = NULL;
  int rc = nqdload("vectors/nqd/cap", &r, why, sizeof why), k;
  size_t i;
  if (rc == NQOK && nqdlen(r, "sources") != 2)
    rc = NQEIO;
  if (rc == NQOK)
    rc = nqdat(r, "sources", 0, out, sizeof out, &on);
  if (rc == NQOK)
    rc = nqdkey(r, "sources", "data/b.csv", out, sizeof out, &on);
  if (rc == NQOK)
    rc = nqdfld(r, "sources", 0, "url", out, sizeof out, &on);
  for (i = 0; rc == NQOK; i++) {
    int a = nqdaddr(r, "data/a.csv", i, &k, out, sizeof out, &on);
    if (a != NQOK) {
      if (a != NQEARG && a != NQEIO)
        rc = a;
      break;
    }
  }
  if (rc == NQOK)
    rc = nqdvrfy(r, "data/b.csv", (const uint8_t *)"x\n1\n2\n", 6);
  if (rc == NQOK || rc == NQEVRFY)
    rc = nqdcite(r, NQDBIB, out, sizeof out, &on);
  nqdrfree(r);
  return rc;
}

static int fcommit(void) {
  static const uint8_t salt[32] = {1};
  char hx[65];
  nqdrec *r = NULL;
  size_t ix;
  int rc = nqdcommit(salt, 32, (const uint8_t *)"abc", 3, hx);
  if (rc == NQOK)
    rc = nqdnew(&r);
  if (rc == NQOK) {
    char j[200];
    qdwhy(j, sizeof j, "{\"name\":\"c\",\"sha256\":\"%s\"}", hx);
    rc = nqdput(r, "commitments", j, strlen(j), why, sizeof why);
  }
  if (rc == NQOK)
    rc = nqdreveal(r, salt, 32, (const uint8_t *)"abc", 3, &ix);
  nqdrfree(r);
  return rc;
}

static int finfer(void) {
  nqdcsvopt o;
  memset(&o, 0, sizeof o);
  o.ranges = 1;
  return nqdinfer("vectors/nqd/cap", "data/a.csv", &o, out, sizeof out, &on,
                  why, sizeof why);
}

static int frep(int rc, nqdrep *r) {
  if (r != NULL && nqdrepn(r) > 0) {
    const char *c = NULL, *d = NULL;
    nqdrepi(r, 0, &c, NULL, &d);
    (void)nqdrepj(r, 0);
  }
  nqdrepfree(r);
  return rc;
}

static int fschk(void) {
  nqdrep *r = NULL;
  int rc = nqdschk("vectors/nqd/cap", sch, schn, &r);
  return frep(rc, r);
}

/* the rules of a schema, each kind (vectors/nqd/rules) */
static int frules(void) {
  static const char s[] =
      "{\"path\":\"m.csv\",\"kind\":\"csv\",\"rules\":["
      "{\"kind\":\"regex\",\"col\":\"code\",\"pattern\":\"^[A-Z]+-\\\\d+$\"},"
      "{\"kind\":\"mad\",\"col\":\"x\",\"max\":3.5},"
      "{\"kind\":\"unique\",\"cols\":[\"id\",\"code\"]},"
      "{\"kind\":\"incr\",\"col\":\"id\"}]}";
  nqdrep *r = NULL;
  int rc = nqdschk("vectors/nqd/rules", s, strlen(s), &r);
  return frep(rc, r);
}

static int fstats(void) {
  return nqdstats("vectors/nqd/drift", "ref.csv", NULL, out, sizeof out, &on,
                  why, sizeof why);
}

static int fdrift(void) {
  nqdrep *r = NULL;
  int rc = nqddrift(st, stn, "vectors/nqd/drift/cur.csv", NULL, NULL, &r);
  return frep(rc, r);
}

static int fdcal(void) {
  static const char *const fs[] = {"vectors/nqd/drift/cur.csv",
                                   "vectors/nqd/drift/cur2.csv"};
  return nqddcal(st, stn, fs, 2, NULL, out, sizeof out, &on, why,
                 sizeof why);
}

static int fchunk(void) {
  nqdrep *r = NULL;
  int rc = nqdchunk("vectors/nqd/drift", "ref.csv", 1024, dst, sizeof dst,
                    &dstn, why, sizeof why);
  if (rc != NQOK)
    return rc;
  rc = nqdpiece(dst, dstn, "vectors/nqd/drift/ref.csv", 0, &r);
  return frep(rc, r);
}

static int fsyn(void) {
  nqdrec *r = NULL;
  int rc = nqdnew(&r);
  if (rc == NQOK)
    rc = nqdput(r, "schemas", sch, schn, why, sizeof why);
  if (rc == NQOK)
    rc = nqdsyn(r, tmp, "data/s.csv", 7, 5, why, sizeof why);
  nqdrfree(r);
  return rc;
}

static void tsyn(void) {
  qdrm(at("data/s.csv"), 0);
}

static int fchk(void) {
  nqdrep *r = NULL;
  int rc = nqdchk("vectors/nqd/cap", &r);
  if (rc == NQOK || rc == NQEVRFY) {
    int r2 = nqdrpt("vectors/nqd/cap", NULL, r, NQDMD, out, sizeof out, &on);
    if (r2 != NQOK)
      rc = r2;
  }
  return frep(rc, r);
}

/* a record with every member nqdchk checks (made in main) */
static int fchkw(void) {
  nqdrep *r = NULL;
  int rc = nqdchk(at("w"), &r);
  if (rc == NQOK || rc == NQEVRFY) {
    int r2 = nqdrpt(at("w"), NULL, r, NQDTXT, out, sizeof out, &on);
    if (r2 != NQOK)
      rc = r2;
  }
  return frep(rc, r);
}

/* tmp/w: data/a.csv of vectors/nqd/cap, and a record of its source,
 * schema, chunks, stats and a check */
static void mkw(void) {
  char a[200], *b = NULL;
  size_t n = 0;
  nqdrec *r = NULL;
  NQTEQI(qdmkdir(at("w")), NQOK);
  NQTEQI(qdmkdir(at("w/data")), NQOK);
  NQTEQI(qdread("vectors/nqd/cap/data/a.csv", 1 << 20, &b, &n), NQOK);
  NQTEQI(qdwrite(at("w/data/a.csv"), b, n), NQOK);
  qdfree(b, n + 1);
  NQTEQI(nqdnew(&r), NQOK);
  NQTEQI(nqdsrc(r, at("w"), "data/a.csv", why, sizeof why), NQOK);
  NQTEQI(nqdinfer(at("w"), "data/a.csv", NULL, out, sizeof out, &on, why,
                  sizeof why), NQOK);
  NQTEQI(nqdput(r, "schemas", out, on, why, sizeof why), NQOK);
  NQTEQI(nqdchunk(at("w"), "data/a.csv", 1024, out, sizeof out, &on, why,
                  sizeof why), NQOK);
  NQTEQI(nqdput(r, "chunks", out, on, why, sizeof why), NQOK);
  NQTEQI(nqdstats(at("w"), "data/a.csv", NULL, out, sizeof out, &on, why,
                  sizeof why), NQOK);
  NQTEQI(nqdput(r, "stats", out, on, why, sizeof why), NQOK);
  qdwhy(a, sizeof a, "{\"name\":\"n\",\"status\":\"pass\"}");
  NQTEQI(nqdput(r, "checks", a, strlen(a), why, sizeof why), NQOK);
  NQTEQI(nqdsave(r, at("w")), NQOK);
  nqdrfree(r);
}

/* ---- nqdsettmp: the temporary file the record is written through ---- */

static int tev[8];
static char tpth[8][600];
static int tn;

static void trec(int ev, const char *p, void *user) {
  NQTCHK(user == (void *)&tn);
  if (tn < 8) {
    tev[tn] = ev;
    qdwhy(tpth[tn], sizeof tpth[tn], "%s", p);
  }
  tn++;
}

/* told before and after the file is made and once it is renamed; a name
 * that is taken is NQTNOT, the next one is made, and the file that had
 * the name is left */
static void ttmp(void) {
  nqdrec *r = NULL;
  FILE *f;
  NQTEQI(nqdload(at("w"), &r, why, sizeof why), NQOK);
  NQTEQI(nqdsettmp(trec, &tn), NQOK);
  tn = 0;
  NQTEQI(nqdsave(r, at("w")), NQOK);
  NQTEQI(tn, 3);
  NQTEQI(tev[0], NQTPRE);
  NQTEQI(tev[1], NQTNEW);
  NQTEQI(tev[2], NQTEND);
  NQTCHK(strcmp(tpth[1], tpth[0]) == 0 && strcmp(tpth[2], tpth[0]) == 0);
  NQTCHK(strstr(tpth[0], "/.noqtis.") != NULL);
#ifdef __wasi__
  /* each name is drawn at random there: no first name to take */
  f = NULL;
#else
  f = fopen(tpth[0], "wb");
  NQTCHK(f != NULL);
#endif
  if (f != NULL) {
    fputs("planted\n", f);
    fclose(f);
    tn = 0;
    NQTEQI(nqdsave(r, at("w")), NQOK);
    NQTEQI(tn, 5);
    NQTEQI(tev[0], NQTPRE);
    NQTEQI(tev[1], NQTNOT);
    NQTEQI(tev[2], NQTPRE);
    NQTEQI(tev[3], NQTNEW);
    NQTEQI(tev[4], NQTEND);
    NQTCHK(strcmp(tpth[1], tpth[0]) == 0 && strcmp(tpth[2], tpth[0]) != 0);
    NQTCHK(strcmp(tpth[3], tpth[2]) == 0 && strcmp(tpth[4], tpth[2]) == 0);
    f = fopen(tpth[0], "rb");
    NQTCHK(f != NULL);
    if (f != NULL)
      fclose(f);
    qdrm(tpth[0], 0);
  }
  NQTEQI(nqdsettmp(NULL, NULL), NQOK);
  tn = 0;
  NQTEQI(nqdsave(r, at("w")), NQOK);
  NQTEQI(tn, 0);
  nqdrfree(r);
}

static void rmw(void) {
  qdrm(at("w/data/a.csv"), 0);
  qdrm(at("w/data"), 1);
  qdrm(at("w/noqtis.data.json"), 0);
  qdrm(at("w"), 1);
}

static int fdiff(void) {
  nqdrep *r = NULL;
  int rc = nqddiff("vectors/cap/sample", "vectors/nqd/cap", &r);
  return frep(rc, r);
}

static int fchain(void) {
  static const char *const ds[] = {"vectors/cap/sample"};
  uint8_t head[32];
  nqdrep *r = NULL;
  int rc = nqdchain(ds, 1, NULL, head, &r);
  return frep(rc, r);
}

static int fpack(void) {
  int rc = nqdpack("vectors/cap/sample", 1, at("p.nqb"));
  if (rc == NQOK)
    rc = nqdunpack(at("p.nqb"), at("u"), 0, why, sizeof why);
  return rc;
}

static void tpack(void) {
  nqdunpack(at("p.nqb"), at("u"), 1, why, sizeof why);
  qdrm(at("u"), 1);
  qdrm(at("p.nqb"), 0);
}

static int fsrc(void) {
  static const char soc[] = "{\"base\":\"https://data.example.org\","
                            "\"id\":\"abcd-1234\",\"kind\":\"socrata\"}";
  char tm[21], *b = NULL;
  size_t bl = 0;
  int rc = nqdrslv(soc, strlen(soc), out, sizeof out, &on, why, sizeof why);
  if (rc == NQOK)
    rc = nqdwb("https://example.org/a.csv", out, sizeof out, &on);
  if (rc == NQOK)
    rc = qdread("vectors/nqd/src/soc.json", 1 << 20, &b, &bl);
  if (rc == NQOK)
    rc = nqdrsp(soc, strlen(soc), b, bl, out, sizeof out, &on, tm, why,
                sizeof why);
  qdfree(b, bl + 1);
  return rc;
}

/* a whole file into buf (cap bytes), NUL added */
static size_t slurp(const char *p, char *buf, size_t cap) {
  char *b = NULL;
  size_t n = 0;
  NQTEQI(qdread(p, cap - 1, &b, &n), NQOK);
  if (b != NULL)
    memcpy(buf, b, n);
  buf[n] = '\0';
  qdfree(b, n + 1);
  return n;
}

int main(void) {
  const char *t = getenv("TMPDIR");
  uint8_t r[8];
  char hx[17];
  if (t == NULL || *t == '\0' || strlen(t) > 300)
    t = "/tmp";
#ifdef _WIN32
  if (getenv("TEMP") != NULL && strlen(getenv("TEMP")) <= 300)
    t = getenv("TEMP");
#endif
  NQTEQI(nqdsetal(tmal, NULL, NULL), NQEARG);
  NQTEQI(nqdsetal(NULL, tfree, NULL), NQEARG);
  NQTEQI(nqdsetal(tmal, tfree, NULL), NQOK);
  NQTEQI(nqrand(r, sizeof r), NQOK);
  qdhex(r, sizeof r, hx);
  qdwhy(tmp, sizeof tmp, "%s/tdal%s", t, hx);
  NQTEQI(qdmkdir(tmp), NQOK);
  NQTEQI(qdmkdir(at("data")), NQOK);
  fulln = slurp("vectors/nqd/full.json", full, sizeof full);
  schn = slurp("vectors/nqd/syn/schema.json", sch, sizeof sch);
  NQTEQI(fstats(), NQOK);
  memcpy(st, out, on + 1);
  stn = on;
  mkw();
  ttmp();
  NQTEQI(live, 0);
  sweep("nqdparse, nqdjson", fparse, NULL);
  sweep("nqdnew, nqdsrc, nqdset, nqdput, nqddel, nqdsave, nqdload", fedit,
        NULL);
  sweep("nqdload, nqdat, nqdkey, nqdfld, nqdaddr, nqdvrfy, nqdcite", fread1,
        NULL);
  sweep("nqdcommit, nqdreveal", fcommit, NULL);
  sweep("nqdinfer", finfer, NULL);
  sweep("nqdschk", fschk, NULL);
  sweep("nqdschk, its rules", frules, NULL);
  sweep("nqdstats", fstats, NULL);
  sweep("nqddrift", fdrift, NULL);
  sweep("nqddcal", fdcal, NULL);
  sweep("nqdchunk, nqdpiece", fchunk, NULL);
  sweep("nqdsyn", fsyn, tsyn);
  sweep("nqdchk, nqdrpt", fchk, NULL);
  sweep("nqdchk, nqdrpt, every member", fchkw, NULL);
  sweep("nqddiff", fdiff, NULL);
  sweep("nqdchain", fchain, NULL);
  sweep("nqdpack, nqdunpack", fpack, tpack);
  sweep("nqdrslv, nqdwb, nqdrsp", fsrc, NULL);
  rmw();
  qdrm(at("noqtis.data.json"), 0);
  qdrm(at("data"), 1);
  qdrm(tmp, 1);
  NQTEQI(live, 0);
  NQTEQI(nqdsetal(NULL, NULL, NULL), NQOK);
  /* malloc again: a block from it is freed as one */
  {
    char *b = qddup("x", 1);
    NQTCHK(b != NULL);
    qdfree(b, 2);
    NQTEQI(live, 0);
  }
  return nqtdone("tdal");
}
