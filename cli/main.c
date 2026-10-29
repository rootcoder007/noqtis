/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis: entry point, help, option parsing, version and algs. */
#include "cli.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#endif

typedef struct {
  const char *name;
  int (*run)(int argc, char **argv);
  const char *brief;
  const char *use;
} nccmd;

static int ncver(int argc, char **argv);
static int ncalgs(int argc, char **argv);
static int nchelp(int argc, char **argv);

static const nccmd cmds[] = {
  {"keygen", nckeygen, "make a key pair",
   "usage: noqtis keygen -a <alg> -o <key> [--seed <hex|file>] [--force]\n"
   "  Writes the secret key to <key> (owner-only) and the public key to\n"
   "  <key>.pub. <alg> is a signature or KEM name from `noqtis algs`.\n"
   "  --seed  deterministic key generation from the standard's seed\n"
   "          (hex digits, or a file holding the raw seed bytes)\n"
   "  --force replace existing files\n"},
  {"sign", ncsign, "sign a file",
   "usage: noqtis sign -k <key> [-o <sig>] [-c <ctx>] [-d] [--ph <hash>]\n"
   "                   [--force] <file>\n"
   "  Writes the raw signature to <sig> (default <file>.sig); <file> may\n"
   "  be - for stdin (then -o is required).\n"
   "  -c      context string (at most 255 bytes)\n"
   "  -d      deterministic signature (no per-signature randomness)\n"
   "  --ph    pre-hash variant (HashML-DSA, HashSLH-DSA) with <hash>\n"},
  {"verify", ncvrfy, "check a signature",
   "usage: noqtis verify -p <key.pub> -s <sig> [-c <ctx>] [--ph <hash>]\n"
   "                     [-q] <file>\n"
   "  Exit 0 when the signature is valid, 1 when it is not, 2 on a usage\n"
   "  or file error.\n"},
  {"enc", ncenc, "encapsulate a shared secret (KEM)",
   "usage: noqtis enc -p <key.pub> -o <ct> [--force] (<ss> | --stdout)\n"
   "  Writes the ciphertext to <ct> and the shared secret to <ss>\n"
   "  (owner-only). --stdout prints the secret in hex instead.\n"},
  {"dec", ncdec, "decapsulate a shared secret (KEM)",
   "usage: noqtis dec -k <key> (-o <ss> | --stdout) [--force] <ct>\n"
   "  Writes the shared secret to <ss> (owner-only), or prints it in hex\n"
   "  with --stdout. A tampered ciphertext gives an unrelated secret\n"
   "  (implicit rejection), not an error.\n"},
  {"hash", nchash, "print or check file digests",
   "usage: noqtis hash [-a <hash>] [-c|--check] [<file>...]\n"
   "  Prints `<hex>  <file>` lines like sha256sum (- or no file: stdin).\n"
   "  --check reads such lines from the files and checks each digest;\n"
   "  exit 1 if any differs or cannot be read.\n"
   "  <hash>: sha224 sha256 (default) sha384 sha512 sha512-224\n"
   "          sha512-256 sha3-224 sha3-256 sha3-384 sha3-512\n"
   "          shake128 shake256\n"},
  {"seal", ncseal, "seal a capsule folder",
   "usage: noqtis seal -k <key> [-p <key.pub>] [--meta <json-file>]\n"
   "                   [--tsa <url>]... [--anchor <der-file>]... <dir>\n"
   "  Writes noqtis.json and noqtis.sig into <dir>, covering every file.\n"
   "  The public key defaults to <key>.pub.\n"
   "  --tsa     an RFC 3161 time-stamping authority (http:// only; the\n"
   "            token is signed). The seal holds one timestamp: give\n"
   "            --tsa again for fallbacks, tried in order until one\n"
   "            answers with a token that checks. If none does, the\n"
   "            seal is removed and the exit status is 2.\n"
   "  --anchor  the TSA's root or issuing certificate (DER), to check\n"
   "            the token at seal time too (up to 32)\n"},
  {"check", ncchk, "check a sealed capsule folder",
   "usage: noqtis check [-p <key.pub>] [--json] [--anchor <der-file>]...\n"
   "                    <dir>\n"
   "  Prints every check and its result; exit 0 only if all pass. Without\n"
   "  -p the key inside the seal is trusted, and the report says so.\n"
   "  For each failed check, stderr says what to do.\n"
   "  --anchor  a TSA root or issuing certificate (DER), up to 32: the\n"
   "            seal must then carry a timestamp that verifies under one\n"
   "            of them. Without --anchor, a timestamped seal fails its\n"
   "            timestamp check (it cannot be checked).\n"},
  {"timestamp", ncts, "add a timestamp to a sealed capsule",
   "usage: noqtis timestamp --tsa <url>... [--anchor <der-file>]...\n"
   "                        [--force] <dir>\n"
   "  Asks each RFC 3161 time-stamping authority in turn (http:// only)\n"
   "  for a token over the seal's signature and stores the first that\n"
   "  checks in noqtis.sig; the manifest and the signature are unchanged.\n"
   "  --anchor  the TSA's root or issuing certificate (DER), to check the\n"
   "            token now too (up to 32)\n"
   "  --force   replace a timestamp the seal already has\n"
   "  If no TSA gives a token that checks, nothing is written (exit 2).\n"},
  {"inspect", ncinsp, "show what a capsule says (nothing checked)",
   "usage: noqtis inspect [--json] <dir>\n"
   "  Prints the seal's format, algorithm and key fingerprint (SHA-256 of\n"
   "  the public key), the manifest's created time, meta, number of files\n"
   "  and total size, and whether a timestamp is there. Nothing is\n"
   "  checked: run `noqtis check` for that. Exit 0 when the seal and the\n"
   "  manifest parse, 1 when one does not, 2 on a usage or folder error.\n"},
  {"algs", ncalgs, "list algorithms and sizes",
   "usage: noqtis algs\n"},
  {"version", ncver, "print the version",
   "usage: noqtis version\n"},
  {"help", nchelp, "show help for a command",
   "usage: noqtis help [<command>]\n"}
};

#define NCNCMD (sizeof cmds / sizeof cmds[0])

/* s for a terminal: every C0 control character, DEL and C1 control
 * (U+0080..U+009F, CSI among them) as \xNN, so a file name or a
 * server's text cannot move the cursor, clear lines or recolour the
 * screen. The result lives until the fourth call after. */
const char *ncesc(const char *s) {
  static char *b[4];
  static size_t cap[4];
  static int k = 0;
  const unsigned char *p = (const unsigned char *)s;
  size_t i, n = 0, o = 0;
  if (s == NULL)
    return "";
  for (i = 0; p[i] != 0; i++) {
    int c1 = p[i] == 0xc2 && p[i + 1] >= 0x80 && p[i + 1] <= 0x9f;
    if (c1) {
      n += 8;
      i++;
    } else {
      n += p[i] < 0x20 || p[i] == 0x7f ? 4 : 1;
    }
  }
  if (n == i)
    return s;
  k = (k + 1) % 4;
  if (cap[k] < n + 1) {
    char *nb = (char *)realloc(b[k], n + 1);
    if (nb == NULL)
      return "?";
    b[k] = nb;
    cap[k] = n + 1;
  }
  for (i = 0; p[i] != 0; i++) {
    if (p[i] == 0xc2 && p[i + 1] >= 0x80 && p[i + 1] <= 0x9f) {
      snprintf(b[k] + o, 9, "\\x%02x\\x%02x", p[i], p[i + 1]);
      o += 8;
      i++;
    } else if (p[i] < 0x20 || p[i] == 0x7f) {
      snprintf(b[k] + o, 5, "\\x%02x", p[i]);
      o += 4;
    } else {
      b[k][o++] = (char)p[i];
    }
  }
  b[k][o] = '\0';
  return b[k];
}

void ncmsg(const char *cmd, const char *fmt, ...) {
  va_list ap;
  char sb[1024], *b = sb;
  int n;
  fflush(stdout);
  if (cmd != NULL)
    fprintf(stderr, "noqtis %s: ", cmd);
  else
    fputs("noqtis: ", stderr);
  va_start(ap, fmt);
  n = vsnprintf(sb, sizeof sb, fmt, ap);
  va_end(ap);
  if (n >= (int)sizeof sb && (b = (char *)malloc((size_t)n + 1)) != NULL) {
    va_start(ap, fmt);
    vsnprintf(b, (size_t)n + 1, fmt, ap);
    va_end(ap);
  } else if (b == NULL) {
    b = sb;
  }
  /* one line, whatever the arguments held */
  fputs(ncesc(n < 0 ? "" : b), stderr);
  if (b != sb)
    free(b);
  fputc('\n', stderr);
}

int nclib(const char *cmd, const char *what, int rc) {
  ncmsg(cmd, "%s: %s", what, nqerr(rc));
  return NCUSE;
}

int ncuse(FILE *f, const char *cmd) {
  size_t i;
  for (i = 0; i < NCNCMD; i++) {
    if (strcmp(cmds[i].name, cmd) == 0) {
      fputs(cmds[i].use, f);
      return 1;
    }
  }
  return 0;
}

static void ncall(FILE *f) {
  size_t i;
  fputs("usage: noqtis <command> [options] [args]\n\ncommands:\n", f);
  for (i = 0; i < NCNCMD; i++)
    fprintf(f, "  %-8s %s\n", cmds[i].name, cmds[i].brief);
  fputs("\n`noqtis help <command>` shows a command's options.\n"
        "Exit status: 0 success, 1 verification failed, 2 usage or file "
        "error.\n", f);
}

static int cmdopt(const char *cmd, const ncopt *o, size_t n, const char *a,
                  size_t *at) {
  size_t i;
  (void)cmd;
  for (i = 0; i < n; i++) {
    if (a[1] == '-') {
      size_t l = strlen(o[i].l);
      if (o[i].l[0] != '\0' && strncmp(a + 2, o[i].l, l) == 0 &&
          (a[2 + l] == '\0' || a[2 + l] == '=')) {
        *at = i;
        return a[2 + l] == '=' ? 2 : 1;
      }
    } else if (o[i].s != '\0' && a[1] == o[i].s) {
      *at = i;
      return a[2] != '\0' ? 3 : 1;
    }
  }
  return 0;
}

int ncargs(const char *cmd, int argc, char **argv, const ncopt *o,
           size_t n, int *npos, int *help) {
  /* which one-value options were given: a second -p would otherwise
   * silently replace the first (`check -p trusted.pub "$@"`) */
  unsigned char seen[64];
  int i, np = 0, dash = 0;
  *help = 0;
  memset(seen, 0, sizeof seen);
  if (n > sizeof seen)
    return NCUSE;
  for (i = 1; i < argc; i++) {
    char *a = argv[i];
    const char *v;
    size_t at = 0;
    int how;
    if (dash || a[0] != '-' || a[1] == '\0') {
      argv[np++] = a;
      continue;
    }
    if (strcmp(a, "--") == 0) {
      dash = 1;
      continue;
    }
    if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
      *help = 1;
      continue;
    }
    how = cmdopt(cmd, o, n, a, &at);
    if (how == 0) {
      ncmsg(cmd, "unknown option %s (see `noqtis help %s`)", a, cmd);
      return NCUSE;
    }
    if (!o[at].arg) {
      if (how != 1) {
        ncmsg(cmd, "option %s takes no value", a);
        return NCUSE;
      }
      *o[at].flag = 1;
      continue;
    }
    if (how == 2) {
      v = strchr(a, '=') + 1;
    } else if (how == 3) {
      v = a + 2;
    } else {
      if (i + 1 >= argc) {
        ncmsg(cmd, "option %s needs a value", a);
        return NCUSE;
      }
      v = argv[++i];
    }
    if (o[at].arg == NCMANY) {
      if (*o[at].flag >= NCMAXV) {
        ncmsg(cmd, "option %s may be given at most %d times", a, NCMAXV);
        return NCUSE;
      }
      o[at].val[(*o[at].flag)++] = v;
    } else {
      if (seen[at]) {
        ncmsg(cmd, "option %s is given more than once", a);
        return NCUSE;
      }
      seen[at] = 1;
      *o[at].val = v;
    }
  }
  *npos = np;
  return NCOK;
}

static int noargs(const char *cmd, int argc, char **argv) {
  int np, help, rc = ncargs(cmd, argc, argv, NULL, 0, &np, &help);
  if (rc != NCOK)
    return rc;
  if (help) {
    ncuse(stdout, cmd);
    return -1;
  }
  if (np != 0) {
    ncmsg(cmd, "unexpected argument %s", argv[0]);
    return NCUSE;
  }
  return NCOK;
}

static int ncver(int argc, char **argv) {
  int rc = noargs("version", argc, argv);
  if (rc != NCOK)
    return rc < 0 ? NCOK : rc;
  printf("noqtis %s\n", nqver());
  return NCOK;
}

static int ncalgs(int argc, char **argv) {
  int i, rc = noargs("algs", argc, argv);
  if (rc != NCOK)
    return rc < 0 ? NCOK : rc;
  printf("%-22s %-4s %7s %7s %7s %4s\n", "algorithm", "type", "pk", "sk",
         "sig/ct", "ss");
  for (i = 1; i <= 64; i++) {
    nqssz s;
    const char *nm = nqsname((nqsalg)i);
    if (nm == NULL || nqssize((nqsalg)i, &s) != NQOK)
      break;
    printf("%-22s %-4s %7lu %7lu %7lu %4s\n", nm, "sig",
           (unsigned long)s.pk, (unsigned long)s.sk, (unsigned long)s.sig,
           "-");
  }
  for (i = 1; i <= 64; i++) {
    nqksz k;
    const char *nm = nqkname((nqkalg)i);
    if (nm == NULL || nqksize((nqkalg)i, &k) != NQOK)
      break;
    printf("%-22s %-4s %7lu %7lu %7lu %4lu\n", nm, "kem",
           (unsigned long)k.pk, (unsigned long)k.sk, (unsigned long)k.ct,
           (unsigned long)k.ss);
  }
  return NCOK;
}

static int nchelp(int argc, char **argv) {
  int i;
  for (i = 1; i < argc; i++) {
    if (argv[i][0] == '-')
      continue;
    if (!ncuse(stdout, argv[i])) {
      ncmsg("help", "unknown command %s", argv[i]);
      return NCUSE;
    }
    return NCOK;
  }
  ncall(stdout);
  return NCOK;
}

static int run(int argc, char **argv) {
  size_t i;
  ncbin();
  if (argc < 2) {
    ncall(stderr);
    return NCUSE;
  }
  if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
    ncall(stdout);
    return NCOK;
  }
  if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0) {
    printf("noqtis %s\n", nqver());
    return NCOK;
  }
  for (i = 0; i < NCNCMD; i++) {
    if (strcmp(cmds[i].name, argv[1]) == 0)
      return cmds[i].run(argc - 1, argv + 1);
  }
  ncmsg(NULL, "unknown command %s (see `noqtis help`)", argv[1]);
  return NCUSE;
}

#ifdef _WIN32
/* The arguments as UTF-8, from the wide command line, so that paths and
 * context strings outside the ANSI code page survive. */
int main(void) {
  int argc = 0, i, rc;
  wchar_t **w = CommandLineToArgvW(GetCommandLineW(), &argc);
  char **argv, **own;
  if (w == NULL)
    return NCUSE;
  /* ncargs() reorders argv in place, so free from a copy of the pointers */
  argv = (char **)calloc((size_t)argc + 1, sizeof *argv);
  own = (char **)calloc((size_t)argc + 1, sizeof *own);
  if (argv == NULL || own == NULL)
    return NCUSE;
  for (i = 0; i < argc; i++) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w[i], -1, NULL, 0, NULL, NULL);
    if (n <= 0 || (argv[i] = (char *)malloc((size_t)n)) == NULL ||
        WideCharToMultiByte(CP_UTF8, 0, w[i], -1, argv[i], n, NULL,
                            NULL) != n) {
      fputs("noqtis: cannot convert the arguments to UTF-8\n", stderr);
      return NCUSE;
    }
    own[i] = argv[i];
  }
  LocalFree(w);
  rc = run(argc, argv);
  for (i = 0; i < argc; i++)
    free(own[i]);
  free(own);
  free(argv);
  return rc;
}
#else
int main(int argc, char **argv) {
  return run(argc, argv);
}
#endif
