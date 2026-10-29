/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis seal and check (capsules), and the RFC 3161 timestamps of
 * seal --tsa and check --anchor. */
#include "cli.h"

#include <signal.h>
#include <stdlib.h>
#include <string.h>

/* ---- a seal waiting for its timestamp ---- */

/* While seal --tsa waits for a TSA, an interrupt (Ctrl-C, SIGTERM,
 * SIGHUP) removes the new noqtis.json and noqtis.sig before the process
 * ends, so the folder is not left sealed without the timestamp asked
 * for. Only SIGKILL (or a power cut) can still leave it so. */
static char pend[2][4200];
static volatile sig_atomic_t armed = 0;

static void onsig(int s) {
  if (armed) {
    remove(pend[0]);
    remove(pend[1]);
  }
  signal(s, SIG_DFL);
  raise(s);
}

static int arm(const char *dir) {
  if (snprintf(pend[0], sizeof pend[0], "%s/noqtis.sig", dir) >=
          (int)sizeof pend[0] ||
      snprintf(pend[1], sizeof pend[1], "%s/noqtis.json", dir) >=
          (int)sizeof pend[1])
    return 0;
  armed = 1;
  signal(SIGINT, onsig);
  signal(SIGTERM, onsig);
#ifdef SIGHUP
  signal(SIGHUP, onsig);
#endif
  return 1;
}

static void disarm(void) {
  armed = 0;
  signal(SIGINT, SIG_DFL);
  signal(SIGTERM, SIG_DFL);
#ifdef SIGHUP
  signal(SIGHUP, SIG_DFL);
#endif
}

/* ---- TSA anchors (--anchor, DER certificates) ---- */

typedef struct {
  uint8_t *b[NCMAXV];
  size_t n[NCMAXV];
  size_t k;
} ncanc;

static void ancfree(ncanc *a) {
  size_t i;
  for (i = 0; i < a->k; i++)
    free(a->b[i]);
  a->k = 0;
}

static int ancrd(const char *cmd, const char *const *p, int np, ncanc *a) {
  int i;
  a->k = 0;
  for (i = 0; i < np; i++) {
    uint8_t *b = NULL;
    size_t n = 0;
    if (ncrdx(p[i], 0, NCRDSMALL, &b, &n) != NQOK) {
      ncmsg(cmd, "cannot read TSA anchor %s (give the path to the TSA's "
            "root or issuing certificate, DER)", p[i]);
      ancfree(a);
      return NCUSE;
    }
    if (n >= 10 && memcmp(b, "-----BEGIN", 10) == 0) {
      ncmsg(cmd, "%s is PEM; give the DER form (openssl x509 -in %s "
            "-outform DER -out %s.der)", p[i], p[i], p[i]);
      free(b);
      ancfree(a);
      return NCUSE;
    }
    if (n < 2 || b[0] != 0x30) {
      ncmsg(cmd, "%s is not a DER certificate (give the TSA's root or "
            "issuing certificate, DER)", p[i]);
      free(b);
      ancfree(a);
      return NCUSE;
    }
    a->b[a->k] = b;
    a->n[a->k++] = n;
  }
  return NCOK;
}

/* "YYYY-MM-DDTHH:MM:SSZ" for seconds since the epoch (from 1970); out
 * is sized for any int, which the compiler cannot rule out */
static void utc(int64_t t, char out[80]) {
  int64_t d = t / 86400, s = t % 86400, y, m, doe, yoe, doy, mp, z;
  if (t < 0) {
    strcpy(out, "before 1970");
    return;
  }
  z = d + 719468;
  doe = z % 146097;
  yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  y = yoe + z / 146097 * 400;
  doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  mp = (5 * doy + 2) / 153;
  d = doy - (153 * mp + 2) / 5 + 1;
  m = mp < 10 ? mp + 3 : mp - 9;
  if (m <= 2)
    y++;
  snprintf(out, 80, "%04d-%02d-%02dT%02d:%02d:%02dZ", (int)(y % 10000),
           (int)m, (int)d, (int)(s / 3600), (int)(s / 60 % 60),
           (int)(s % 60));
}

/* Asks each TSA in turn for a token over the seal in dir until one
 * gives a token that checks (nqtsput); NCOK once one is stored. */
static int stamp(const char *cmd, const char *dir, const char *const *tsa,
                 int nt, const ncanc *an) {
  uint8_t nonce[8], req[128];
  size_t qn = 0;
  int i, rc;
  if (nqrand(nonce, sizeof nonce) != NQOK)
    return nclib(cmd, "random nonce", NQERNG);
  nonce[0] = (uint8_t)((nonce[0] & 0x7f) | 0x40);
  rc = nqtsreq(dir, nonce, sizeof nonce, req, sizeof req, &qn);
  if (rc != NQOK)
    return nclib(cmd, "timestamp request", rc);
  for (i = 0; i < nt; i++) {
    uint8_t *rsp = NULL;
    size_t rn = 0;
    char err[300];
    const char *why = NULL;
    int64_t gt = 0;
    char ts[80];
    if (nchttp(tsa[i], req, qn, &rsp, &rn, err, sizeof err) != NCOK) {
      ncmsg(cmd, "%s: %s", tsa[i], err);
      continue;
    }
    rc = nqtsput(dir, rsp, rn, nonce, sizeof nonce,
                 (const uint8_t *const *)an->b, an->n, an->k, &gt, &why);
    free(rsp);
    if (rc != NQOK) {
      ncmsg(cmd, "%s: refused its reply: %s", tsa[i],
            why != NULL ? why : nqerr(rc));
      continue;
    }
    utc(gt, ts);
    printf("timestamp from %s: genTime %s%s\n", ncesc(tsa[i]), ts,
           an->k != 0 ? ", verified under a TSA anchor" : "");
    if (an->k == 0)
      ncmsg(cmd, "note: no --anchor given, so the TSA itself was not "
            "checked; check with --anchor <der-file> to trust the time");
    return NCOK;
  }
  return NCBAD;
}

int ncseal(int argc, char **argv) {
  const char *kp = NULL, *pp = NULL, *mp = NULL;
  const char *tsa[NCMAXV], *anc[NCMAXV];
  int help = 0, np, rc, ret = NCUSE, nt = 0, na = 0;
  ncopt o[] = {
    {'k', "key", 1, &kp, NULL},
    {'p', "pub", 1, &pp, NULL},
    {'m', "meta", 1, &mp, NULL},
    {'\0', "tsa", NCMANY, tsa, &nt},
    {'\0', "anchor", NCMANY, anc, &na}
  };
  nckey sk = {{0, 0, NULL}, 0, NULL, 0}, pk = {{0, 0, NULL}, 0, NULL, 0};
  ncanc an;
  uint8_t *meta = NULL;
  size_t mn = 0;
  char *dp = NULL;

  an.k = 0;
  if (ncargs("seal", argc, argv, o, sizeof o / sizeof o[0], &np,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "seal");
    return NCOK;
  }
  if (kp == NULL || np != 1) {
    ncuse(stderr, "seal");
    return NCUSE;
  }
  if (na > 0 && nt == 0) {
    ncmsg("seal", "--anchor checks a timestamp: give --tsa <url> too");
    return NCUSE;
  }
  /* a URL the request could never be sent to is refused before sealing */
  for (rc = 0; rc < nt; rc++) {
    char err[300];
    if (ncurlok(tsa[rc], err, sizeof err) != NCOK) {
      ncmsg("seal", "--tsa %s: %s", tsa[rc], err);
      return NCUSE;
    }
  }
  if (ancrd("seal", anc, na, &an) != NCOK)
    return NCUSE;
  if (pp == NULL) {
    size_t l = strlen(kp);
    dp = (char *)malloc(l + 5);
    if (dp == NULL) {
      ancfree(&an);
      return nclib("seal", "memory", NQEMEM);
    }
    memcpy(dp, kp, l);
    memcpy(dp + l, ".pub", 5);
    pp = dp;
  }
  if (mp != NULL) {
    uint8_t *m;
    if (ncrdx(mp, 0, NCRDSMALL, &meta, &mn) != NQOK) {
      ncmsg("seal", "cannot read %s", mp);
      goto out;
    }
    m = (uint8_t *)realloc(meta, mn + 1);
    if (m == NULL) {
      nclib("seal", "memory", NQEMEM);
      goto out;
    }
    meta = m;
    meta[mn] = 0;
    if (memchr(meta, 0, mn) != NULL) {
      ncmsg("seal", "%s holds a NUL byte; give a JSON object", mp);
      goto out;
    }
  }
  if (nckrd("seal", pp, 0, &pk) != NCOK)
    goto out;
  if (nckrd("seal", kp, 1, &sk) != NCOK) {
    nckfree(&pk);
    goto out;
  }
  if (sk.a.kem || pk.a.kem || sk.a.alg != pk.a.alg) {
    if (sk.a.kem)
      ncmsg("seal", "%s is a %s (KEM) key; seals need a signature key", kp,
            sk.a.name);
    else
      ncmsg("seal", "%s (%s) and %s (%s) are not a pair", kp, sk.a.name, pp,
            pk.a.name);
    goto done;
  }
  /* armed before the seal is written, so no interrupt can fall between
   * writing it and waiting for the TSA */
  if (nt > 0 && !arm(argv[0])) {
    ncmsg("seal", "%s: path too long", argv[0]);
    goto done;
  }
  rc = nqseal(argv[0], (nqsalg)sk.a.alg, sk.b, sk.n, pk.b, pk.n,
              (const char *)meta, NULL);
  if (rc != NQOK) {
    disarm();
    if (rc == NQEARG)
      ncmsg("seal", "%s: a file in it starts like a noqtis secret key "
            "(noqtis-key-1 ... sec), which would ship with the capsule: "
            "move secret keys out of the folder, then seal it", argv[0]);
    else
      nclib("seal", argv[0], rc);
    goto done;
  }
  ret = NCOK;
  if (nt == 0 || (rc = stamp("seal", argv[0], tsa, nt, &an)) == NCOK) {
    disarm();
    printf("sealed %s with %s%s\n", ncesc(argv[0]), sk.a.name,
           nt > 0 ? " and a timestamp" : "");
  } else {
    /* a seal asked to carry a timestamp never stays without one */
    char *f;
    disarm();
    f = (char *)malloc(strlen(argv[0]) + 16);
    int gone = f != NULL;
    if (f != NULL) {
      sprintf(f, "%s/noqtis.sig", argv[0]);
      gone = remove(f) == 0;
      sprintf(f, "%s/noqtis.json", argv[0]);
      gone = remove(f) == 0 && gone;
      free(f);
    }
    ncmsg("seal", "no --tsa gave a timestamp; %s", gone
          ? "removed noqtis.json and noqtis.sig, so the folder is not left "
            "sealed without one: try again, or give another --tsa"
          : "could not remove noqtis.json and noqtis.sig: delete them, "
            "or seal again");
    ret = NCUSE;
  }
done:
  nckfree(&sk);
  nckfree(&pk);
out:
  ancfree(&an);
  free(meta);
  free(dp);
  return ret;
}

static void jstr(const char *s) {
  putchar('"');
  for (; s != NULL && *s != '\0'; s++) {
    unsigned char c = (unsigned char)*s;
    if (c == '"' || c == '\\')
      printf("\\%c", c);
    else if (c == '\n')
      fputs("\\n", stdout);
    else if (c == '\t')
      fputs("\\t", stdout);
    else if (c < 0x20)
      printf("\\u%04x", c);
    else
      putchar(c);
  }
  putchar('"');
}

/* ---- what to do about each failed check ----
 *
 * One entry per check name nqchk reports (src/cap/chk.c), the first whose
 * detail holds sub (NULL: any) wins. tcli reads chk.c and fails when a
 * check name has no entry. */
typedef struct {
  const char *chk;
  const char *sub;
  const char *fix;
} ncfix;

#define RESEAL "restore it from the sealed copy, or seal the folder again"

static const ncfix fixes[] = {
  {"seal.read", NULL, "noqtis.sig is missing or unreadable: give the "
   "folder that holds noqtis.json and noqtis.sig, or seal it with "
   "`noqtis seal`"},
  {"seal.parse", NULL, "noqtis.sig is not JSON: " RESEAL},
  {"seal.canonical", NULL, "noqtis.sig was edited (it is not in the "
   "canonical form noqtis writes): " RESEAL},
  {"seal.fields", NULL, "noqtis.sig was edited or made by another tool: "
   RESEAL},
  {"seal.format", NULL, "noqtis.sig is not a noqtis-seal-1 seal: " RESEAL},
  {"seal.alg", NULL, "the seal's algorithm is not one this noqtis knows "
   "(`noqtis algs`): use a newer noqtis, or " RESEAL},
  {"seal.context", NULL, "the seal's context is not \"noqtis-capsule-1\", so "
   "its signature was not made for a capsule: " RESEAL},
  {"seal.key", NULL, "the seal's public_key is damaged: " RESEAL},
  {"seal.signature", NULL, "the seal's signature is damaged: " RESEAL},
  {"manifest.read", "too large", "noqtis.json is over 512 MiB, more than "
   "noqtis reads: split the folder into smaller capsules"},
  {"manifest.read", NULL, "noqtis.json is missing or unreadable: " RESEAL},
  {"manifest.digest", NULL, "noqtis.json is not the manifest this seal "
   "signed: restore the sealed noqtis.json, or seal again if the files "
   "changed on purpose"},
  {"manifest.parse", NULL, "noqtis.json is not JSON: " RESEAL},
  {"manifest.canonical", NULL, "noqtis.json was edited: " RESEAL},
  {"manifest.fields", "too many", "the manifest lists more files than "
   "noqtis checks: split the folder into smaller capsules"},
  {"manifest.fields", NULL, "noqtis.json was edited or made by another "
   "tool: " RESEAL},
  {"manifest.format", NULL, "noqtis.json is not a noqtis-capsule-1 "
   "manifest: " RESEAL},
  {"manifest.created", NULL, "the manifest's created time is not RFC 3339 "
   "UTC: " RESEAL},
  {"manifest.order", NULL, "the manifest's files are not sorted, so it "
   "was edited: " RESEAL},
  {"key", NULL, "the seal was made with another key than -p gives: check "
   "that -p is the signer's public key; if it is, someone else sealed "
   "the folder again"},
  {"signature", NULL, "the signature over noqtis.json does not verify: "
   "noqtis.json or noqtis.sig changed after sealing; restore both from "
   "the sealed copy"},
  {"timestamp", "no timestamp in the seal", "this seal has no timestamp: "
   "check without --anchor, or seal again with --tsa <url>"},
  {"timestamp", "no TSA trust anchors", "give the TSA's root or issuing "
   "certificate with --anchor <der-file> to check the timestamp"},
  {"timestamp", "imprint", "the timestamp is over another signature: seal "
   "again with --tsa <url>"},
  {"timestamp", "not a certificate", "every --anchor must be a DER X.509 "
   "certificate: convert a PEM one with `openssl x509 -outform DER`"},
  {"timestamp", "does not verify", "the token is not from a TSA under the "
   "anchors given: give --anchor the certificate of the TSA that made it, "
   "or seal again with --tsa <url>"},
  {"timestamp", NULL, "the timestamp in noqtis.sig is damaged: restore "
   "noqtis.sig from the sealed copy, or seal again with --tsa <url>"},
  {"folder", NULL, "the folder cannot be listed: check its permissions, "
   "and that it is within the limits in noqtis-capsule(5)"},
  {"path", "differ only in case", "two files differ only in case, which "
   "breaks on Windows and macOS: rename one and seal again"},
  {"path", NULL, "the manifest lists a path noqtis refuses or lists it "
   "twice, so it was not written by `noqtis seal`: " RESEAL},
  {"file", ": missing", "a sealed file is gone: restore it from the "
   "original, or seal the folder again if it was removed on purpose"},
  {"file", ": a symbolic link", "a sealed file was replaced by a link: put "
   "the file itself back"},
  {"file", ": unreadable", "a sealed file cannot be read: check its "
   "permissions"},
  {"file", NULL, "a sealed file changed after sealing: restore it from "
   "the original, or seal the folder again if the change was intended"},
  {"extra", NULL, "a file was added after sealing: remove it, or seal the "
   "folder again to include it"},
  {"unsafe", NULL, "capsules hold only regular files and folders with "
   "portable names: remove the link or special file (or rename the "
   "file), then seal again"}
};

#define NCNFIX (sizeof fixes / sizeof fixes[0])

static const char *fixfor(const char *chk, const char *det) {
  size_t i;
  for (i = 0; i < NCNFIX; i++) {
    if (strcmp(fixes[i].chk, chk) == 0 &&
        (fixes[i].sub == NULL ||
         (det != NULL && strstr(det, fixes[i].sub) != NULL)))
      return fixes[i].fix;
  }
  return "no advice for this check: please report it as a bug";
}

int ncchk(int argc, char **argv) {
  const char *pp = NULL, *anc[NCMAXV];
  int json = 0, help = 0, np, rc, ret, all = 1, na = 0;
  ncopt o[] = {
    {'p', "pub", 1, &pp, NULL},
    {'j', "json", 0, NULL, &json},
    {'\0', "anchor", NCMANY, anc, &na}
  };
  nckey pk = {{0, 0, NULL}, 0, NULL, 0};
  nqrep *r = NULL;
  ncanc an;
  size_t n = 0, i, j, w = 5, nf = 0;
  const char *kn = NULL, *kalg = NULL;

  an.k = 0;
  if (ncargs("check", argc, argv, o, sizeof o / sizeof o[0], &np,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "check");
    return NCOK;
  }
  if (np != 1) {
    ncuse(stderr, "check");
    return NCUSE;
  }
  if (!ncisdir(argv[0])) {
    ncmsg("check", "%s: not a folder (give the folder that holds "
          "noqtis.json and noqtis.sig)", argv[0]);
    return NCUSE;
  }
  pk.b = NULL;
  pk.n = 0;
  pk.sec = 0;
  if (pp != NULL) {
    if (nckrd("check", pp, 0, &pk) != NCOK)
      return NCUSE;
    if (pk.a.kem) {
      ncmsg("check", "%s is a %s (KEM) key, not a signature key; give the "
            "signer's .pub from `noqtis keygen -a ML-DSA-...` or SLH-DSA",
            pp, pk.a.name);
      nckfree(&pk);
      return NCUSE;
    }
  }
  if (ancrd("check", anc, na, &an) != NCOK) {
    nckfree(&pk);
    return NCUSE;
  }
  rc = nqchkt(argv[0], pk.b, pk.n, (const uint8_t *const *)an.b, an.n,
              an.k, &r);
  kn = pp != NULL ? pk.a.name : NULL;
  nckfree(&pk);
  ancfree(&an);
  if (r != NULL)
    n = nqrepn(r);
  for (i = 0; i < n; i++) {
    const char *c = NULL, *d = NULL;
    int ok = 0;
    if (nqrepi(r, i, &c, &ok, &d) != NQOK || c == NULL) {
      all = 0;
      continue;
    }
    if (!ok) {
      all = 0;
      nf++;
    }
    /* -p pins the key file's algorithm too, not only its bytes */
    if (kn != NULL && ok && strcmp(c, "seal.alg") == 0 && d != NULL &&
        strcmp(d, kn) != 0) {
      kalg = d;
      all = 0;
      nf++;
    }
    if (strlen(c) > w)
      w = strlen(c);
  }
  if (rc == NQOK && all && n > 0)
    ret = NCOK;
  else if (rc == NQOK || rc == NQEVRFY || rc == NQEDEC)
    ret = NCBAD;
  else
    ret = NCUSE;
  if (json) {
    fputs("{\"capsule\":", stdout);
    jstr(argv[0]);
    printf(",\"ok\":%s,\"result\":", ret == NCOK ? "true" : "false");
    jstr(nqerr(rc));
    fputs(",\"checks\":[", stdout);
  } else if (n > 0) {
    printf("%-4s  %-*s  %s\n", "", (int)w, "check", "detail");
  }
  for (i = 0; i < n; i++) {
    const char *c = NULL, *d = NULL;
    int ok = 0;
    if (nqrepi(r, i, &c, &ok, &d) != NQOK || c == NULL)
      continue;
    if (json) {
      fputs(i > 0 ? ",{\"check\":" : "{\"check\":", stdout);
      jstr(c);
      printf(",\"ok\":%s,\"detail\":", ok ? "true" : "false");
      jstr(d != NULL ? d : "");
      if (!ok) {
        fputs(",\"fix\":", stdout);
        jstr(fixfor(c, d));
      }
      putchar('}');
    } else {
      printf("%-4s  %-*s  %s\n", ok ? "ok" : "FAIL", (int)w, ncesc(c),
             ncesc(d));
    }
  }
  if (kalg != NULL) {
    if (json) {
      fputs(n > 0 ? ",{\"check\":\"key.alg\",\"ok\":false,\"detail\":"
                  : "{\"check\":\"key.alg\",\"ok\":false,\"detail\":",
            stdout);
      jstr(kn);
      putchar('}');
    } else {
      printf("%-4s  %-*s  the trusted key file is %s, the seal says %s\n",
             "FAIL", (int)w, "key.alg", kn, ncesc(kalg));
    }
  }
  if (json) {
    fputs("]}\n", stdout);
  } else if (ret == NCOK) {
    printf("%s: OK (%lu checks passed)\n", ncesc(argv[0]),
           (unsigned long)n);
  } else if (n > 0 && nf > 0) {
    printf("%s: FAILED (%lu of %lu checks failed)\n", ncesc(argv[0]),
           (unsigned long)nf, (unsigned long)n);
  } else {
    printf("%s: FAILED (%s)\n", ncesc(argv[0]), nqerr(rc));
  }
  /* what to do: once per failed check and advice, after the table */
  for (i = 0; i < n && !json; i++) {
    const char *c = NULL, *d = NULL, *f;
    int ok = 1, dup = 0;
    if (nqrepi(r, i, &c, &ok, &d) != NQOK || c == NULL || ok)
      continue;
    f = fixfor(c, d);
    for (j = 0; j < i && !dup; j++) {
      const char *c2 = NULL, *d2 = NULL;
      int ok2 = 1;
      if (nqrepi(r, j, &c2, &ok2, &d2) == NQOK && c2 != NULL && !ok2 &&
          strcmp(c, c2) == 0 && fixfor(c2, d2) == f)
        dup = 1;
    }
    if (!dup)
      ncmsg("check", "%s: %s", c, f);
  }
  if (pp == NULL && ret == NCOK && !json)
    ncmsg("check", "note: no -p given, so the key inside the seal was "
          "trusted; pass -p <key.pub> to check who sealed it");
  if (ret == NCUSE && !json)
    ncmsg("check", "%s: %s", argv[0], nqerr(rc));
  if (r != NULL)
    nqrepfree(r);
  fflush(stdout);
  return ret;
}

/* the value of an info.* row of an nqinsp report, or NULL */
static const char *info(const nqrep *r, const char *name) {
  size_t i, n = nqrepn(r);
  for (i = 0; i < n; i++) {
    const char *c = NULL, *d = NULL;
    if (nqrepi(r, i, &c, NULL, &d) == NQOK && c != NULL &&
        strcmp(c, name) == 0)
      return d;
  }
  return NULL;
}

int ncinsp(int argc, char **argv) {
  static const char *const rows[][2] = {
    {"format", "info.format"}, {"alg", "info.alg"},
    {"key", "info.key"}, {"created", "info.created"},
    {"files", "info.files"}, {"bytes", "info.bytes"},
    {"timestamp", "info.timestamp"}, {"meta", "info.meta"}
  };
  int json = 0, help = 0, np, rc, ret;
  ncopt o[] = {{'j', "json", 0, NULL, &json}};
  nqrep *r = NULL;
  size_t i, n;

  if (ncargs("inspect", argc, argv, o, sizeof o / sizeof o[0], &np,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "inspect");
    return NCOK;
  }
  if (np != 1) {
    ncuse(stderr, "inspect");
    return NCUSE;
  }
  if (!ncisdir(argv[0])) {
    ncmsg("inspect", "%s: not a folder (give the folder that holds "
          "noqtis.json and noqtis.sig)", argv[0]);
    return NCUSE;
  }
  rc = nqinsp(argv[0], &r);
  if (rc != NQOK && rc != NQEDEC) {
    ncmsg("inspect", "%s: %s", argv[0], nqerr(rc));
    return NCUSE;
  }
  ret = rc == NQOK ? NCOK : NCBAD;
  n = nqrepn(r);
  if (json) {
    fputs("{\"capsule\":", stdout);
    jstr(argv[0]);
    fputs(",\"checked\":false", stdout);
    if (ret == NCOK) {
      const char *v;
      fputs(",\"format\":", stdout);
      jstr(info(r, "info.format"));
      fputs(",\"alg\":", stdout);
      jstr(info(r, "info.alg"));
      fputs(",\"key_sha256\":", stdout);
      jstr(info(r, "info.key"));
      fputs(",\"created\":", stdout);
      jstr(info(r, "info.created"));
      printf(",\"files\":%s", info(r, "info.files"));
      v = info(r, "info.bytes");
      if (v != NULL && v[0] >= '0' && v[0] <= '9') {
        printf(",\"bytes\":%s", v);
      } else {
        fputs(",\"bytes\":", stdout);
        jstr(v);
      }
      v = info(r, "info.timestamp");
      printf(",\"timestamp\":%s",
             v != NULL && strcmp(v, "present") == 0 ? "true" : "false");
      /* meta is canonical JSON already */
      v = info(r, "info.meta");
      printf(",\"meta\":%s}\n", v != NULL ? v : "null");
    } else {
      int first = 1;
      fputs(",\"errors\":[", stdout);
      for (i = 0; i < n; i++) {
        const char *c = NULL, *d = NULL;
        int ok = 1;
        if (nqrepi(r, i, &c, &ok, &d) != NQOK || ok)
          continue;
        fputs(first ? "{\"check\":" : ",{\"check\":", stdout);
        first = 0;
        jstr(c);
        fputs(",\"detail\":", stdout);
        jstr(d != NULL ? d : "");
        putchar('}');
      }
      fputs("]}\n", stdout);
    }
  } else if (ret == NCOK) {
    for (i = 0; i < sizeof rows / sizeof rows[0]; i++) {
      const char *v = info(r, rows[i][1]);
      if (v != NULL)
        printf("%-9s  %s\n", rows[i][0], ncesc(v));
    }
    printf("%s: read, not checked (run `noqtis check` to check it)\n",
           argv[0]);
  } else {
    for (i = 0; i < n; i++) {
      const char *c = NULL, *d = NULL;
      int ok = 1;
      if (nqrepi(r, i, &c, &ok, &d) == NQOK && !ok)
        printf("FAIL  %s  %s\n", ncesc(c), ncesc(d));
    }
    printf("%s: cannot be read as a capsule\n", argv[0]);
  }
  nqrepfree(r);
  fflush(stdout);
  return ret;
}

/* noqtis timestamp: a timestamp for a capsule sealed before, from the
 * first TSA whose reply checks; the seal's signature and the manifest are
 * not touched, and nothing is written when no reply checks. */
int ncts(int argc, char **argv) {
  const char *tsa[NCMAXV], *anc[NCMAXV];
  int help = 0, force = 0, np, nt = 0, na = 0, rc, has = 0;
  ncopt o[] = {
    {'\0', "tsa", NCMANY, tsa, &nt},
    {'\0', "anchor", NCMANY, anc, &na},
    {'\0', "force", 0, NULL, &force}
  };
  nqrep *r = NULL;
  ncanc an;
  size_t i, n;

  an.k = 0;
  if (ncargs("timestamp", argc, argv, o, sizeof o / sizeof o[0], &np,
             &help) != NCOK)
    return NCUSE;
  if (help) {
    ncuse(stdout, "timestamp");
    return NCOK;
  }
  if (np != 1 || nt == 0) {
    ncuse(stderr, "timestamp");
    return NCUSE;
  }
  for (rc = 0; rc < nt; rc++) {
    char err[300];
    if (ncurlok(tsa[rc], err, sizeof err) != NCOK) {
      ncmsg("timestamp", "--tsa %s: %s", tsa[rc], err);
      return NCUSE;
    }
  }
  if (!ncisdir(argv[0])) {
    ncmsg("timestamp", "%s: not a folder (give a folder `noqtis seal` "
          "sealed)", argv[0]);
    return NCUSE;
  }
  /* the seal and the manifest must read before a TSA is asked */
  rc = nqinsp(argv[0], &r);
  if (rc != NQOK) {
    ncmsg("timestamp", "%s is not a sealed capsule that reads (%s): seal "
          "it with `noqtis seal`, or see `noqtis inspect %s`", argv[0],
          nqerr(rc), argv[0]);
    nqrepfree(r);
    return NCUSE;
  }
  n = nqrepn(r);
  for (i = 0; i < n; i++) {
    const char *ck = NULL, *d = NULL;
    if (nqrepi(r, i, &ck, NULL, &d) == NQOK && ck != NULL &&
        strcmp(ck, "info.timestamp") == 0 && d != NULL &&
        strcmp(d, "present") == 0)
      has = 1;
  }
  nqrepfree(r);
  if (has && !force) {
    ncmsg("timestamp", "%s already has a timestamp; --force replaces it "
          "(the earlier time is then no longer shown by the seal)", argv[0]);
    return NCUSE;
  }
  if (ancrd("timestamp", anc, na, &an) != NCOK)
    return NCUSE;
  rc = stamp("timestamp", argv[0], tsa, nt, &an);
  ancfree(&an);
  if (rc != NCOK) {
    ncmsg("timestamp", "no --tsa gave a timestamp; %s is unchanged: try "
          "again, or give another --tsa", argv[0]);
    return NCUSE;
  }
  printf("timestamped %s%s\n", argv[0], has ? " (the old timestamp was "
         "replaced)" : "");
  fflush(stdout);
  return NCOK;
}
