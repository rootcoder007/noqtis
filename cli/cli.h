/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/*
 * The noqtis command-line tool: shared declarations. The tool uses only
 * the public API in noqtis.h.
 */
#ifndef NQCLI_H
#define NQCLI_H

#include <noqtis.h>
#include <nqd.h>

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

/* exit codes */
/* s with control characters escaped, for printing to a terminal */
const char *ncesc(const char *s);

#define NCOK 0   /* success; a signature or capsule verified */
#define NCBAD 1  /* verification failed, a digest differs */
#define NCUSE 2  /* usage, file or library error */

/* ---- options ---- */

/* One option: -s, --long; arg 1 when it takes a value (stored in *val),
 * NCMANY when it may be given up to NCMAXV times (val is then an array
 * of NCMAXV and *flag counts the values), else *flag is set to 1. */
#define NCMANY 2
#define NCMAXV 32
typedef struct {
  char s;
  const char *l;
  int arg;
  const char **val;
  int *flag;
} ncopt;

/* Parses argv[1..argc-1] (argv[0] is the command name); moves the
 * positional arguments to the front of argv and stores their count in
 * *npos. Prints an error and returns NCUSE on a bad option, NCOK
 * otherwise. -h/--help sets *help. */
int ncargs(const char *cmd, int argc, char **argv, const ncopt *o,
           size_t n, int *npos, int *help);

/* ---- messages ---- */

void ncmsg(const char *cmd, const char *fmt, ...);

/* ---- a newer release (upd.c) ---- */
/* `noqtis version --check`: asks now and prints the answer. NCOK, or
 * NCBAD when the latest release cannot be asked for. */
int ncupdnow(void);
/* Prints the usage of cmd to f; 0 if cmd is unknown. */
int ncuse(FILE *f, const char *cmd);
/* Prints "noqtis <cmd>: <what>: <nqerr(rc)>" and returns NCUSE. */
int nclib(const char *cmd, const char *what, int rc);

/* ---- files (io.c) ---- */

/* Opens a UTF-8 path on every OS. */
FILE *ncfopen(const char *path, const char *mode);
/* Reads a whole file ("-" is stdin) into a new buffer. sec: unbuffered,
 * and every intermediate copy is wiped. The caller frees with ncfree. */
int ncrd(const char *path, int sec, uint8_t **buf, size_t *len);
/* whether path is a folder (following links) */
int ncisdir(const char *path);
/* Reads descriptor fd up to a newline (not kept) into b, cap bytes. */
int ncrdfd(int fd, uint8_t *b, size_t cap, size_t *n);
/* ncrd that refuses (NQELIM) an input over max bytes, so /dev/zero or a
 * huge file cannot fill memory or run forever */
int ncrdx(const char *path, int sec, size_t max, uint8_t **buf,
          size_t *len);
#define NCRDMAX ((size_t)1 << 30) /* a message or list: 1 GiB */
/* A file of a capsule as it was before a command of several steps began,
 * to put back when a later step refuses or the command is interrupted:
 * the command then leaves the folder as it found it. ncsnapget reads
 * dir/name (NCOK also when there is no such file; NCUSE when it is a
 * link, a pipe, a folder or any file that is not a plain one; NCBAD when
 * the folder or the file cannot be opened or read, errno saying why, and
 * s->p naming which). On POSIX it keeps the folder open, and everything
 * put back goes there by descriptor, never by the path, with the file's
 * mode and, where the owner may give it, its group.
 * ncsnappend notes n snapshots (at most 4, of one folder) as one group
 * that an interrupt puts back together, before the command changes
 * anything: every file that is no longer what it was is written whole
 * under a name of the tool's temporary shape (.noqtis.<16 hex>.tmp, made
 * new) and only then are they renamed over their names, and a file there
 * was none of is removed; when that cannot be done, nothing is renamed
 * and "noqtis: <who>: stopped, ..." goes to standard error. NCOK, or
 * NCUSE (out of memory; nothing noted). The bytes must stay allocated
 * until the group is let go: ncsnapfree of any of them lets it go.
 * ncsnapput puts the n back the same way now, with the signals held, then
 * lets them go and frees them: NCOK when they are back (a file that was
 * not touched is left alone). ncsnapfree lets go and frees. */
typedef struct {
  char p[4200];
  uint8_t *b;
  size_t n;
  int had;
  int mode; /* its permission bits, put back with it */
  long gid; /* its group (POSIX) */
  int dfd;  /* its folder, open (POSIX), or -1 */
  int sl;   /* what ncsnappend noted it as, or -1 */
} ncsnap;
int ncsnapget(ncsnap *s, const char *dir, const char *name);
int ncsnappend(ncsnap *s, int n, const char *who);
int ncsnapput(ncsnap *s, int n);
void ncsnapfree(ncsnap *s);
/* A run over several capsules (seal -r) leaves the tree as it found it
 * when it is interrupted: after nctreeon, nctree takes over a group
 * noted by ncsnappend from each capsule done (with its open folder), and
 * the handler stays in place and puts every one back until nctreeend, at
 * the end of the run, lets them go. Without nctreeon, nctree lets the
 * group go at once (the capsule keeps its new files) and frees it. */
size_t nctreeon(unsigned long *lim);
void nctree(ncsnap *s, int n);
void nctreeend(int back);
/* nctreeon gives how many capsules one run can keep this way (the
 * open-file limit, raised to the hard one and put in *lim, less what the
 * rest of the run needs): seal -r refuses a larger tree before it
 * writes anything. A capsule that fails because no descriptor is left
 * sets ncnofd; the run then stops, and nctreeend(1) puts back every
 * capsule it resealed before letting them go. */
extern int ncnofd;
/* the descriptors a run of seal -r needs besides the folders it keeps:
 * the standard three, the starting folder, and what one capsule's seal
 * opens at a time (its folder twice, a file, the folders of the walk
 * down to the depth most trees have, a key, a TSA's socket). A tree
 * deeper than that can still run out; the run then puts every capsule
 * back (ncnofd). */
#define NCFDRES 16
/* 1 when e is how open(O_NOFOLLOW | O_DIRECTORY) says the name is a link
 * (ELOOP; EMLINK on FreeBSD; EFTYPE on NetBSD) or no folder (ENOTDIR). */
int nclnk(int e);
/* Says why ncsnapget refused (rc): not a plain file (NCUSE), or the
 * error errno holds, by name, never a guess. NCUSE. */
int ncsnapsay(const char *cmd, const ncsnap *s, int rc);
/* whether a and b name one file: by its identity where both exist, else by
 * the name */
int ncsame(const char *a, const char *b);
#define NCRDSMALL ((size_t)1 << 20) /* a key, signature, anchor: 1 MiB */
/* Creates path for writing: refuses an existing file unless force; sec
 * gives owner-only permissions (0600 on POSIX). The bytes go to a new
 * temporary name beside path (".noqtis.<16 hex>.tmp"), which ncclose
 * renames to path once the file is whole and removes otherwise; a
 * signal (see psig, cli/io.c) removes it too. */
FILE *ncopen(const char *path, int force, int sec);
/* path is removed on a signal (see psig, cli/io.c) until ncunpend(slot):
 * the slot, or -1 when all 8 are taken or path is too long */
int ncpend(const char *path);
void ncunpend(int slot);
/* The hook the library and nqd tell of each temporary file they make
 * (nqsettmp, nqdsettmp, set once in main.c before any command runs):
 * the file is then removed on a signal until it is renamed into place,
 * the one made, never a file that had its name. */
void nctmpev(int ev, const char *path, void *user);
/* Closes f (from ncopen) and keeps it, when whole, under its temporary
 * name for ncput: its slot; -1 when it is bad or the close fails (it is
 * removed then). */
int nckeep(FILE *f, int bad);
/* Gives the n kept outputs of sl (nckeep, nctmpf, nctmpd) their names,
 * in that order, with the signals held back; from the first that fails,
 * that one and the rest are removed. Returns how many were named. */
int ncput(const int *sl, int n);
/* Removes a kept or reserved output and frees its slot. */
void ncdrop(int slot);
/* A temporary name for path in t (cap bytes), noted for removal, for a
 * file the library makes (with O_EXCL) and ncput names: the slot, or -1
 * when path exists and !force, or no slot is free. */
int nctmpf(const char *path, int force, char *t, size_t cap);
/* The same for a folder that is filled under t and then named path by
 * ncput (path must not exist; a folder is never replaced). Until then a
 * signal is held back: ncstop() turns 1, and once the folder is removed
 * or named, the process ends as the signal would have ended it. */
int nctmpd(const char *path, char *t, size_t cap);
int ncstop(void);
/* Writes len bytes to a new file (see ncopen); removes it on failure. */
int ncwr(const char *path, const uint8_t *b, size_t len, int force,
         int sec);
/* ncopen and ncwr of the path rel (a capsule path) under the folder dir:
 * each folder on the way is opened from dir by descriptor without
 * following a link (made when missing), the file itself must be new or a
 * plain file, and its temporary file is made and named in that folder by
 * descriptor; NULL (NQEIO) when a link or anything else is in the way.
 * Close with ncclose, giving dir/rel as the path. */
FILE *ncopenat(const char *dir, const char *rel, int force, int sec);
int ncwrat(const char *dir, const char *rel, const uint8_t *b, size_t len,
           int force, int sec);
/* path, a temporary folder of the command's own about to be made, noted
 * for removal (with everything in it) as nctmpd's: the slot for ncdrop,
 * or -1. A signal is held back until ncdrop, or until ncbail */
int nctmpin(const char *path);
/* When a signal was held back, removes every pending output and folder
 * and ends the process as the signal would have; called where a long
 * step can stop (the library's progress calls). */
void ncbail(void);
/* on: what is made from now on is owner-only (umask 077), for a
 * plaintext copy made in a shared temporary folder; off: the umask as it
 * was. A no-op on Windows, where %TEMP% is the user's own. */
void ncpriv(int on);
/* Makes the folder path (owner-only on POSIX). NCOK or NCUSE. */
int ncmkdir(const char *path);
/* Removes the file path, or the empty folder path; 0 on success. */
int ncrmfile(const char *path);
int ncrmdir(const char *path);
/* ": <the reason>" for the last failure of the file helpers here
 * (ncfopen, ncrdx, ncopen, ncclose, ncmkdir), from its errno, or ""
 * when none is known: what a "cannot read" or "cannot write" message
 * ends with, never a guess. */
const char *ncwhy(void);
/* Prints why path could not be created; returns NCUSE. */
int ncwfail(const char *cmd, const char *path, int force);
/* 1 when path names an existing file. */
int ncexist(const char *path);
/* 1 when path names a regular file (after links). */
int ncisreg(const char *path);
/* The UTC calendar time of t into *tm (gmtime_r, gmtime_s on Windows;
 * gmtime itself is not thread-safe). NCOK, or NCUSE, also for a t this
 * system's time_t does not hold (with 32 bits, past January 2038). */
int ncgmtime(int64_t t, struct tm *tm);
/* SOURCE_DATE_EPOCH when set, else the clock, in seconds; -1 when
 * SOURCE_DATE_EPOCH is not a plain decimal number of seconds up to the
 * end of the year 9999 (the caller says so, with NCSDEBAD) */
int64_t ncnow(void);
#define NCSDEBAD "SOURCE_DATE_EPOCH is not a number of seconds up to the year 9999"
/* the clock always fits time_t; SOURCE_DATE_EPOCH may not */
#define NCSDETT "SOURCE_DATE_EPOCH is past what this system's time_t holds (with 32 bits, January 2038)"
/* Closes f; for a file from ncopen, gives it its name when whole, and
 * removes it when bad or when the close or the rename fails (any other
 * f: removes path then). 0 on success. */
int ncclose(FILE *f, const char *path, int bad);
/* dir and every folder under it, 64 levels deep at most, without
 * following links, deepest first (free each and the list); NCUSE over
 * NCWALKMAX folders or when memory runs out. A link to a folder (on
 * Windows, a reparse point) is said on standard error for cmd and
 * counted in *nl, never followed. */
#define NCWALKMAX ((size_t)100000)
int ncwalk(const char *cmd, const char *dir, char ***out, size_t *n,
           size_t *nl);
/* POSIX: makes the folder path (one ncwalk listed under top) the
 * working folder, reached from top by descriptor with O_NOFOLLOW at
 * every step, and returns "." to give the command; NULL when a step is
 * now a link or not a folder. Windows: returns path (ncwalk skipped
 * reparse points). nchome saves the working folder (a descriptor),
 * ncback returns to it, NCOK or NCUSE. */
const char *ncenter(const char *top, const char *path);
int nchome(void);
int ncback(int fd);
void ncunhome(int fd);
/* p made absolute against the working folder (POSIX; a URL or an
 * absolute path as it is), in a new buffer (free it); NULL out of
 * memory */
char *ncabs(const char *p);
#ifdef NQTEST
void nctswap(const char *path);
void nctkill(const char *at);
int nctfail(const char *at);
#endif
/* runs cmd (ncseal or ncchk) on every capsule folder under the folder
 * that is its last argument: those holding the file mark (seal: a
 * manifest or a data record), with -r taken out of argv */
int ncrec(const char *cmd, int (*fn)(int, char **), int argc, char **argv);
/* while ncrec runs a command in a folder: the folder's path under the
 * one given, for the command to name the capsule by (it is given "."
 * on POSIX); NULL otherwise */
extern const char *nclab;
/* Wipes (when sec) and frees. */
void ncfree(void *p, size_t len, int sec);
/* stdin/stdout in binary mode (Windows). */
void ncbin(void);

/* ---- encodings (b64.c), constant time ---- */

size_t ncb64n(size_t len);  /* encoded length with a newline every 64 */
void ncb64e(const uint8_t *in, size_t len, char *out);
/* Decodes, ignoring line breaks; NQEDEC on anything else. */
int ncb64d(const char *in, size_t inlen, uint8_t *out, size_t outmax,
           size_t *outlen);
void nchexe(const uint8_t *in, size_t len, char *out);  /* 2*len chars */
/* NQEDEC unless in is exactly 2*n hex digits. */
int nchexd(const char *in, size_t inlen, uint8_t *out, size_t outmax,
           size_t *outlen);

/* ---- ASCII armor (arm.c): RFC 7468, a line at a time ---- */

#define NCLSIG "NOQTIS SIGNATURE"
#define NCLBOX "NOQTIS SEALED STREAM"
#define NCLDATA "NOQTIS DATA"
/* A writer: with a label, what ncawput is given goes out armored (the
 * BEGIN line at once, the END line from ncawend); with label NULL, as
 * it is. */
typedef struct {
  FILE *f;
  int on;
  uint8_t b[48];
  size_t n;
  char lab[NQARMLAB];
} ncaw;
int ncawbeg(ncaw *w, FILE *f, const char *label);
int ncawput(ncaw *w, const uint8_t *p, size_t n);
int ncawend(ncaw *w);
/* A reader: ncarbeg looks at the first byte of f; a dash starts an
 * armor (on is 1, its label in lab; NQEDEC when the line is not a BEGIN
 * line, or label is given and is another), anything else is read as it
 * is. ncarget reads up to n bytes (fewer only at the end) and ncarpeek
 * takes one, as fread and fgetc would. NQEIO from ncarget with dec set
 * means the armor is not whole (changed, cut, or text after its end);
 * ncarok says, when all was read, that it ended as an armor must (1
 * also for what is not armored). */
typedef struct {
  FILE *f;
  int on, end, pad, bol, bad, dec;
  uint8_t b[48];
  size_t at, n;
  char lab[NQARMLAB];
} ncar;
int ncarbeg(ncar *r, FILE *f, const char *label);
int ncarget(ncar *r, uint8_t *p, size_t n, size_t *got);
int ncarpeek(ncar *r, uint8_t *c);
int ncarok(const ncar *r);
/* What was read whole (a signature): when b starts with a BEGIN line it
 * is replaced by the bytes it armors, whose label must be label
 * (NQEDEC); anything else is left as it is. */
int ncunarm(const char *label, uint8_t *b, size_t *n);

/* ---- the network (net.c) ---- */

/* POSTs body (an RFC 3161 request) to an http:// URL (or https://, with
 * NQTLS) and returns the reply's body in a new buffer (free it). NCUSE
 * with a sentence in err on any failure: the URL, the connection, TLS,
 * the HTTP status or type. The trust anchors for https:// are the PEM
 * bundle SSL_CERT_FILE names, else the system's. */
int nchttp(const char *url, const uint8_t *body, size_t n, uint8_t **out,
           size_t *outn, char *err, size_t cap);
/* GETs url and returns the body (at most max bytes) in a new buffer
 * (free it), following at most 5 redirects, never one from https:// to
 * anything else. Within 120 s in all. */
int ncget(const char *url, size_t max, uint8_t **out, size_t *outn,
          char *err, size_t cap);
/* what ncfetch fetched: the bytes, the server's ETag and Last-Modified
 * (as sent, "" when none), the URL they came from after redirects, and
 * how many times the transfer was resumed */
typedef struct {
  uint8_t *b;
  size_t n;
  char etag[256];
  char mod[64];
  char url[2048];
  int resumed;
} ncres;
/* GETs url as ncget does (the same redirect rules) for a file of at
 * most max bytes, within secs seconds in all (0: 120), resuming a
 * transfer cut short with a Range request when the server takes one
 * and names the file (ETag or Last-Modified), at most 3 times. NCOK
 * with *r set (free with ncresfree), or NCUSE and why in err. */
int ncfetch(const char *url, size_t max, int secs, ncres *r, char *err,
            size_t cap);
void ncresfree(ncres *r);
/* NCOK when url is one nchttp can send to (http://host[:port][/path],
 * or https:// with NQTLS); else NCUSE and why in err. No network. */
int ncurlok(const char *url, char *err, size_t cap);

/* ---- remote capsules (rem.c) ---- */

typedef struct ncrem ncrem;
/* 1 when s is an http:// or https:// URL */
int ncisurl(const char *s);
/* Fetches the capsule served at url (its folder) into a new temporary
 * folder: the seal and the manifest, then, when those check under co's
 * key and anchors, the listed files (co's only, when set), each at most
 * its listed size. Problems fetching are printed, and the check of the
 * folder reports what is missing. NCOK with *out set, or NCUSE. */
int ncremget(const char *url, const nqcopt *co, ncrem **out);
const char *ncremdir(const ncrem *m);
/* Removes everything ncremget wrote, then frees m. */
void ncremfree(ncrem *m);
/* a new temporary folder's path (not made) into out: NCOK or NCUSE */
int nctmp(char *out, size_t cap);

/* ---- bundles (rem.c, through nqd.h) ---- */

/* 1 when path is a regular file that starts as a bundle does */
int ncisbnd(const char *path);
/* writes the bundle of the capsule dir (checked by the caller) to out,
 * replacing a file there when force: NCOK or NCUSE, with why printed */
int ncbwr(const char *cmd, const char *dir, int files, const char *out,
          int force);
/* unpacks the bundle file into a new temporary folder, its path in dir,
 * owner-only (a plaintext copy of the files) and removed by a signal
 * (nctmpin), its slot in *sl: NCOK, NCBAD for a file that is not a
 * bundle, NCUSE */
int ncbget(const char *cmd, const char *file, char *dir, size_t cap,
           int *sl);
/* removes the folder of ncbget's slot sl and everything in it */
void ncbdone(int sl);

/* ---- algorithms and keys (key.c) ---- */

typedef struct {
  int kem;     /* 0 signature, 1 KEM */
  int alg;     /* nqsalg or nqkalg */
  const char *name;
} ncalg;

/* Finds an algorithm by name (case-insensitive). NQENOSUP if unknown. */
int ncfind(const char *name, ncalg *a);
/* Public and secret key sizes. */
int ncksz(const ncalg *a, size_t *pk, size_t *sk);

typedef struct {
  ncalg a;
  int sec;
  uint8_t *b;
  size_t n;
} nckey;

/* Reads a public key file; a secret one is read with ncskrd. */
int nckrd(const char *cmd, const char *path, nckey *k);
void nckfree(nckey *k);
/* The key store's folder into out: opt (--store) when given, else the
 * variable NOQTIS_KEYS, else noqtis/keys under XDG_CONFIG_HOME or
 * ~/.config (APPDATA on Windows). NCUSE when none of them is set or the
 * path does not fit. Where nckrd reads a public key, a path that starts
 * with @ names a key of that store instead of a file: @<name, address
 * or start of the fingerprint>; exactly one key must answer, and it must
 * be valid there. */
int ncstore(const char *opt, char *out, size_t cap);
/* Writes a key file to an already opened f. */
int nckwr(FILE *f, const ncalg *a, int sec, const uint8_t *b, size_t n);

/* A passphrase from --pass-fd <n> (read from that descriptor up to a
 * newline) or --pass-env <name> (the variable's value), never from the
 * command line; at most NQPWLEN bytes, at least one. */
typedef struct {
  const char *fd;
  const char *env;
} ncpw;
/* *b NULL when neither option was given; else a new buffer of
 * NQPWLEN bytes (free with ncfree(*b, NQPWLEN, 1)) holding *n bytes.
 * NCOK, or NCUSE with a message. */
int ncpwget(const char *cmd, const ncpw *o, uint8_t **b, size_t *n);
/* the same for options of another name: opt is "pass" for --pass-fd and
 * --pass-env, "new-pass" for --new-pass-fd and --new-pass-env */
int ncpwgetn(const char *cmd, const ncpw *o, const char *opt, uint8_t **b,
             size_t *n);
/* Reads a secret key file, one under a passphrase (noqtis-pwkey-1)
 * opened with the passphrase of the options o (opt "pass" for --pass-fd
 * and --pass-env, "new-pass" for --new-pass-*): the one way the commands
 * read a secret key, so each takes those options. A descriptor is read
 * once; later calls for it reuse the bytes. NCOK, or NCUSE with a
 * message. */
int ncskrd(const char *cmd, const char *path, const ncpw *o,
           const char *opt, nckey *k);
/* ncskrd that also gives *kdf: the KDF byte of a file under a passphrase
 * (NQPWA2, NQPWPB), 0 for one under none. */
int ncskrdk(const char *cmd, const char *path, const ncpw *o,
            const char *opt, nckey *k, int *kdf);
/* Writes a secret key file under the passphrase pw, derived by kdf
 * (NQPWA2 Argon2id, NQPWPB PBKDF2; nqpwenc2). */
int nckwrp(FILE *f, const ncalg *a, int kdf, const uint8_t *pw, size_t pwn,
           const uint8_t *b, size_t n);
/* --kdf: NULL or "argon2id" NQPWA2, "pbkdf2" NQPWPB; NCOK, or NCUSE with
 * a message. */
int nckdf(const char *cmd, const char *s, int *kdf);

/* A hash by its command-line name (sha256, sha3-256, ...). */
int nchalg(const char *name, nqhalg *h);
const char *nchname(nqhalg h);

/* ---- commands ---- */

int nckeygen(int argc, char **argv);
int ncpasswd(int argc, char **argv);
int ncarmor(int argc, char **argv);
int nckeys(int argc, char **argv);
int nccert(int argc, char **argv);
int ncsmime(int argc, char **argv);
int ncpgp(int argc, char **argv);
int nctoken(int argc, char **argv);
/* A key on a PKCS #11 token for another command: the module loaded
 * (mod, else $NOQTIS_PKCS11), the token of slot (NULL: the only one)
 * opened with its PIN, the key of that label or hexadecimal ID found.
 * NCOK with *p open (close it with nqp11close), else the message is
 * printed and *p is NULL. */
int nctkopen(const char *mod, const char *slot, const ncpw *pwo,
             const char *label, const char *id, nqp11 **p, nqp11k *k);
/* the algorithm's name, and the token's refusal said */
const char *nctkname(const nqp11k *k);
int nctkfail(nqp11 *p, const char *what, int rc);
int ncdearmor(int argc, char **argv);
int ncsign(int argc, char **argv);
int ncvrfy(int argc, char **argv);
int ncenc(int argc, char **argv);
int ncdec(int argc, char **argv);
int ncbox(int argc, char **argv);
int ncunbox(int argc, char **argv);
int nchash(int argc, char **argv);
int ncseal(int argc, char **argv);
int ncchk(int argc, char **argv);
int ncprove(int argc, char **argv);
int ncrot(int argc, char **argv);
int ncexp(int argc, char **argv);
/* verify --dsse (exp.c): the envelope env under key file kp; the payload
 * to out when not NULL */
int ncvdsse(const char *kp, const char *env, const char *out, int quiet);
int ncrev(int argc, char **argv);
int ncexpire(int argc, char **argv);
int ncidc(int argc, char **argv);
/* the identity card at path (idc.c), checked: NCOK with *f, else NCBAD
 * (not a card, or one that does not verify) or NCUSE (unreadable), and a
 * sentence in why */
int ncidrd(const char *path, nqcardf *f, char *why, size_t cap);
/* "name (ORCID ..., email, url, affil)" for a report */
void ncidwho(const nqcardf *f, char *out, size_t cap);
int ncinsp(int argc, char **argv);
int ncts(int argc, char **argv);
/* the progress bar of long calls on a terminal (prog.c) */
void ncprog(void);
/* the bytes of a message read so far, of total (0 when unknown, as for
 * stdin), on the same bar; ncpdone clears it */
void ncpread(uint64_t done, uint64_t total);
void ncpdone(void);
int ncers(int argc, char **argv);

/* ---- the data layer (data.c, through nqd.h) ---- */

int ncdata(int argc, char **argv);
int ncpack(int argc, char **argv);
int ncchunk(int argc, char **argv);
int ncchain(int argc, char **argv);
/* the record of dir (a new one when it has none and mk), with the
 * reason printed on failure; NCOK or NCUSE */
int ncdload(const char *cmd, const char *dir, int mk, nqdrec **r);
/* saves r in dir, and says so when dir is sealed */
int ncdsave(const char *cmd, const char *dir, nqdrec *r);
/* prints a report of nqd rows as a table (or --json) with what to do for
 * each failed kind; the exit status for rc */
int ncdrep(const char *cmd, const char *lab, const nqdrep *rep, int rc,
           int json);
/* the same over nr reports, with the exit status ret already known */
int ncdreps(const char *cmd, const char *lab, const nqdrep *const *rs,
            size_t nr, int ret, int json);
int ncschema(int argc, char **argv);
int ncdiff(int argc, char **argv);
int ncrpt(int argc, char **argv);
int ncdrift(int argc, char **argv);
int ncenv(int argc, char **argv);
int nccommit(int argc, char **argv);
int ncreveal(int argc, char **argv);
int nccite(int argc, char **argv);
int ncsrc(int argc, char **argv);
/* s as a JSON string, to stdout or into a new buffer (free it) */
void ncjstr(const char *s);
char *ncjq(const char *s);

#endif /* NQCLI_H */
