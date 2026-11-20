/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The notice of a newer release, and `noqtis version --check`.
 *
 * The page of the latest release answers with the address of its tag, and
 * nothing is sent but the request for it. Nothing is linked for that
 * request, and the library takes no part in it: Windows asks through
 * WinHTTP, which is part of it; elsewhere the libcurl of the system is
 * loaded when there is one, and the curl program is the last resort (the
 * tool's own HTTP client has TLS only in a build with NQTLS). The notice
 * is one line on standard error after a command that ended with status 0,
 * only when standard error is a terminal, never with CI or
 * NOQTIS_NO_UPDATE_CHECK set (NOQTIS_UPDATE_CHECK=1 says it away from a
 * terminal and under CI too); the question is asked at most once a day
 * (two seconds at most) and the answer kept in the user's cache
 * directory. A build with NQNOUPD defined has neither. */
#define _POSIX_C_SOURCE 200809L
#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if !defined(NQNOUPD) && (defined(_WIN32) || defined(__unix__) || \
                          defined(__APPLE__)) && !defined(__ANDROID__)
#define NCUPD 1
#endif

#ifdef NCUPD
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <direct.h>
#include <io.h>
#include <windows.h>
#include <winhttp.h>
#define NCTTY() (_isatty(_fileno(stderr)) != 0)
#else
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>
#define NCTTY() (isatty(STDERR_FILENO) != 0)
#endif

#define NCREL "https://github.com/rootcoder007/noqtis/releases/"
#define NCVMAX 24 /* bytes of a version */

/* is version a later than version b (numbers between dots) */
static int later(const char *a, const char *b) {
  while (*a != '\0' || *b != '\0') {
    unsigned long x = 0, y = 0;
    while (*a >= '0' && *a <= '9') x = x * 10 + (unsigned long)(*a++ - '0');
    while (*b >= '0' && *b <= '9') y = y * 10 + (unsigned long)(*b++ - '0');
    if (x != y)
      return x > y;
    if (*a != '\0') a++;
    if (*b != '\0') b++;
  }
  return 0;
}

/* The address the page of the latest release redirects to, in buf (cap
 * bytes, ended with 0); the length, or 0 when it cannot be had within secs
 * seconds. Nothing is linked for this: Windows asks through WinHTTP, which
 * is part of it; elsewhere the libcurl of the system is loaded when there
 * is one, and the curl program is the last resort. */
#ifdef _WIN32
static size_t asknet(int secs, char *buf, size_t cap) {
  HINTERNET s, c = NULL, r = NULL;
  wchar_t w[200];
  DWORD n = sizeof w, nored = WINHTTP_DISABLE_REDIRECTS;
  size_t k = 0, i;
  const int ms = secs * 1000;
  s = WinHttpOpen(L"noqtis", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (s == NULL)
    return 0;
  WinHttpSetTimeouts(s, ms, ms, ms, ms);
  c = WinHttpConnect(s, L"github.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
  if (c != NULL)
    r = WinHttpOpenRequest(c, L"HEAD", L"/rootcoder007/noqtis/releases/latest",
                           NULL, WINHTTP_NO_REFERER,
                           WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
  if (r != NULL &&
      WinHttpSetOption(r, WINHTTP_OPTION_DISABLE_FEATURE, &nored,
                       sizeof nored) &&
      WinHttpSendRequest(r, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                         WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
      WinHttpReceiveResponse(r, NULL) &&
      WinHttpQueryHeaders(r, WINHTTP_QUERY_LOCATION,
                          WINHTTP_HEADER_NAME_BY_INDEX, w, &n,
                          WINHTTP_NO_HEADER_INDEX)) {
    k = (size_t)n / sizeof w[0];
    if (k >= cap)
      k = 0;
    for (i = 0; i < k; i++) {
      /* an address is ASCII; anything else is not the answer looked for */
      if (w[i] < 0x21 || w[i] > 0x7e) {
        k = 0;
        break;
      }
      buf[i] = (char)w[i];
    }
  }
  if (r != NULL)
    WinHttpCloseHandle(r);
  if (c != NULL)
    WinHttpCloseHandle(c);
  WinHttpCloseHandle(s);
  buf[k] = '\0';
  return k;
}
#else
/* libcurl, by the numbers of its stable interface (curl/curl.h):
 * CURLOPT_URL 10002, NOBODY 44, TIMEOUT 13, NOSIGNAL 99, USERAGENT 10018,
 * CURLINFO_REDIRECT_URL 0x100000 + 31. */
typedef void *(*askinit)(void);
typedef int (*askset)(void *, int, ...);
typedef int (*askrun)(void *);
typedef int (*askinfo)(void *, int, ...);
typedef void (*askend)(void *);

static size_t asklib(int secs, char *buf, size_t cap) {
  static const char *const names[] = {"libcurl.so.4", "libcurl-gnutls.so.4",
                                      "libcurl.4.dylib", "libcurl.so"};
  void *h = NULL, *p[5], *c;
  askinit finit;
  askset fset;
  askrun frun;
  askinfo finfo;
  askend fend;
  const char *url = NULL;
  size_t i, k = 0;
  for (i = 0; h == NULL && i < sizeof names / sizeof names[0]; i++)
    h = dlopen(names[i], RTLD_NOW | RTLD_LOCAL);
  if (h == NULL)
    return 0;
  p[0] = dlsym(h, "curl_easy_init");
  p[1] = dlsym(h, "curl_easy_setopt");
  p[2] = dlsym(h, "curl_easy_perform");
  p[3] = dlsym(h, "curl_easy_getinfo");
  p[4] = dlsym(h, "curl_easy_cleanup");
  for (i = 0; i < 5; i++) {
    if (p[i] == NULL)
      return 0;
  }
  /* an object pointer to a function pointer, as POSIX has dlsym give it */
  memcpy(&finit, &p[0], sizeof finit);
  memcpy(&fset, &p[1], sizeof fset);
  memcpy(&frun, &p[2], sizeof frun);
  memcpy(&finfo, &p[3], sizeof finfo);
  memcpy(&fend, &p[4], sizeof fend);
  c = finit();
  if (c == NULL)
    return 0;
  fset(c, 10002, NCREL "latest");
  fset(c, 44, 1L);
  fset(c, 13, (long)secs);
  fset(c, 99, 1L);
  fset(c, 10018, "noqtis");
  if (frun(c) == 0 && finfo(c, 0x100000 + 31, &url) == 0 && url != NULL) {
    k = strlen(url);
    if (k >= cap)
      k = 0;
    memcpy(buf, url, k);
  }
  fend(c);
  /* the library stays loaded: the program is about to end, and unloading
   * a TLS library is not safe everywhere */
  buf[k] = '\0';
  return k;
}

static size_t asknet(int secs, char *buf, size_t cap) {
  char cmd[256];
  size_t n = asklib(secs, buf, cap);
  FILE *f;
  if (n > 0)
    return n;
  /* the curl program; the command is a constant but for the seconds */
  snprintf(cmd, sizeof cmd,
           "curl -fsS -m %d -o /dev/null -w \"%%{redirect_url}\" " NCREL
           "latest 2>/dev/null",
           secs);
  f = popen(cmd, "r");
  if (f == NULL)
    return 0;
  n = fread(buf, 1, cap - 1, f);
  pclose(f);
  buf[n] = '\0';
  return n;
}
#endif

/* The version of the latest release in v (NCVMAX + 1 bytes), or "" when
 * it cannot be had: no network within secs seconds, nothing to ask with,
 * an answer of another form. */
static void latest(int secs, char *v) {
  static const char pre[] = NCREL "tag/v";
  char buf[160];
  size_t n = asknet(secs, buf, sizeof buf), k = sizeof pre - 1, i;
  v[0] = '\0';
  if (n <= k || n - k > NCVMAX || memcmp(buf, pre, k) != 0)
    return;
  for (i = k; i < n; i++) {
    if ((buf[i] < '0' || buf[i] > '9') && buf[i] != '.')
      return;
  }
  memcpy(v, buf + k, n - k);
  v[n - k] = '\0';
}

/* the file that keeps the last answer and its time; 0 without a place */
static int updfile(char *f, size_t cap) {
#ifdef _WIN32
  const char *d = getenv("LOCALAPPDATA");
  if (d == NULL || *d == '\0' ||
      snprintf(f, cap, "%s\\noqtis", d) >= (int)cap)
    return 0;
  _mkdir(f);
  return snprintf(f, cap, "%s\\noqtis\\update", d) < (int)cap;
#else
  const char *x = getenv("XDG_CACHE_HOME"), *h = getenv("HOME");
  char dir[1024];
  if (x != NULL && *x != '\0') {
    if (snprintf(dir, sizeof dir, "%s", x) >= (int)sizeof dir)
      return 0;
  } else if (h == NULL || *h == '\0' ||
             snprintf(dir, sizeof dir, "%s/.cache", h) >= (int)sizeof dir) {
    return 0;
  }
  mkdir(dir, 0700);
  if (snprintf(f, cap, "%s/noqtis", dir) >= (int)cap)
    return 0;
  mkdir(f, 0700);
  return snprintf(f, cap, "%s/noqtis/update", dir) < (int)cap;
#endif
}

void ncupd(void) {
  const char *off = getenv("NOQTIS_NO_UPDATE_CHECK");
  const char *on = getenv("NOQTIS_UPDATE_CHECK");
  int force = on != NULL && strcmp(on, "1") == 0;
  char f[1100], v[NCVMAX + 1] = "";
  long long t = 0, now = (long long)time(NULL);
  FILE *c;
  if ((off != NULL && *off != '\0') || (on != NULL && strcmp(on, "0") == 0))
    return;
  if (!force && (getenv("CI") != NULL || !NCTTY()))
    return;
  if (!updfile(f, sizeof f))
    return;
  c = fopen(f, "r");
  if (c != NULL) {
    if (fscanf(c, "%lld %24[0-9.]", &t, v) < 1)
      t = 0;
    fclose(c);
  }
  if (now < t || now - t >= 86400) {
    latest(2, v);
    c = fopen(f, "w");
    if (c != NULL) {
      fprintf(c, "%lld %s\n", now, v);
      fclose(c);
    }
  }
  if (v[0] != '\0' && later(v, nqver())) {
    fprintf(stderr,
            "noqtis: version %s is available (this is %s): " NCREL "latest\n"
            "noqtis: NOQTIS_NO_UPDATE_CHECK=1 stops this notice.\n",
            v, nqver());
  }
}

int ncupdnow(void) {
  char v[NCVMAX + 1];
  latest(10, v);
  if (v[0] == '\0') {
    ncmsg("version", "the latest release could not be asked for (no "
                     "network, or nothing to ask with)");
    return NCBAD;
  }
  if (later(v, nqver()))
    printf("noqtis %s is available (this is %s): " NCREL "latest\n", v,
           nqver());
  else
    printf("noqtis %s is up to date\n", nqver());
  return NCOK;
}
#else
void ncupd(void) {
}

int ncupdnow(void) {
  ncmsg("version", "this build cannot ask for the latest release");
  return NCBAD;
}
#endif
