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
 * to put back when a later step refuses: the command then leaves the
 * folder as it found it. ncsnapget reads dir/name (NCOK also when there
 * is no such file; NCUSE when it is there and cannot be read, or the path
 * is too long, or it is a link, a pipe or any file that is not a plain one).
 * ncsnapput writes it back with its mode when the file is no longer what it
 * was (a file that was not touched is left alone), or removes the file the
 * command made where there was none, and frees; ncsnapfree only frees.
 * ncsnappend makes an interrupt put the file back as well (a slot for
 * ncunpend, or -1): the bytes must stay allocated until then. */
typedef struct {
  char p[4200];
  uint8_t *b;
  size_t n;
  int had;
  int mode; /* its permission bits, put back with it */
} ncsnap;
int ncsnapget(ncsnap *s, const char *dir, const char *name);
int ncsnapput(ncsnap *s);
void ncsnapfree(ncsnap *s);
int ncsnappend(const ncsnap *s);
/* A run over several capsules (seal -r) leaves the tree as it found it
 * when it is interrupted: after nctreeon, nctree takes a file's earlier
 * state from each capsule done, and an interrupt puts every one back (or
 * removes the file where there was none); nctreeend, at the end of the
 * run, lets them go. Without nctreeon, nctree does nothing. */
void nctreeon(void);
void nctree(ncsnap *s);
void nctreeend(void);
/* whether a and b name one file: by its identity where both exist, else by
 * the name */
int ncsame(const char *a, const char *b);
#define NCRDSMALL ((size_t)1 << 20) /* a key, signature, anchor: 1 MiB */
/* Creates path for writing: refuses an existing file unless force; sec
 * gives owner-only permissions (0600 on POSIX). The bytes go to a new
 * temporary name beside path (".noqtis.<16 hex>.tmp"), which ncclose
 * renames to path once the file is whole and removes otherwise; a
 * signal (SIGINT, SIGTERM, SIGHUP, SIGXFSZ) removes it too. */
FILE *ncopen(const char *path, int force, int sec);
/* path is removed on SIGINT, SIGTERM or SIGHUP until ncunpend(slot):
 * the slot, or -1 when all 8 are taken or path is too long */
int ncpend(const char *path);
void ncunpend(int slot);
/* ncpend for the temporary files the library writes a seal of dir
 * through (.noqtis.json.<pid>.0.tmp, .noqtis.sig.<pid>.0.tmp): two
 * slots into sl, -1 where none was free */
void ncpendseal(const char *dir, int sl[2]);
/* the same for one of them, name (noqtis.sig, noqtis.ers): the slot */
int ncpendown(const char *dir, const char *name);
/* ncpend for the temporary file nqd writes a file of folder dir through
 * (.noqtis.<pid, 8 hex>00000000.tmp, as a data record): the slot, or -1 */
int ncpendrec(const char *dir);
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
/* Prints why path could not be created; returns NCUSE. */
int ncwfail(const char *cmd, const char *path, int force);
/* 1 when path names an existing file. */
int ncexist(const char *path);
/* 1 when path names a regular file (after links). */
int ncisreg(const char *path);
/* The UTC calendar time of t into *tm (gmtime_r, gmtime_s on Windows;
 * gmtime itself is not thread-safe). NCOK or NCUSE. */
int ncgmtime(time_t t, struct tm *tm);
/* SOURCE_DATE_EPOCH when set, else the clock, in seconds; -1 when
 * SOURCE_DATE_EPOCH is not a plain decimal number of seconds up to the
 * end of the year 9999 (the caller says so, with NCSDEBAD) */
int64_t ncnow(void);
#define NCSDEBAD "SOURCE_DATE_EPOCH is not a number of seconds up to the year 9999"
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

/* Reads a key file; sec is the kind the caller needs (1 secret). */
int nckrd(const char *cmd, const char *path, int sec, nckey *k);
void nckfree(nckey *k);
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
/* nckrd, and a secret key file under a passphrase (noqtis-pwkey-1)
 * opened with pw (pwn bytes; NULL when none was given). */
int nckrdp(const char *cmd, const char *path, int sec, const uint8_t *pw,
           size_t pwn, nckey *k);
/* Writes a secret key file under the passphrase pw. */
int nckwrp(FILE *f, const ncalg *a, const uint8_t *pw, size_t pwn,
           const uint8_t *b, size_t n);

/* A hash by its command-line name (sha256, sha3-256, ...). */
int nchalg(const char *name, nqhalg *h);
const char *nchname(nqhalg h);

/* ---- commands ---- */

int nckeygen(int argc, char **argv);
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
