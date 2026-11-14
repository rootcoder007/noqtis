/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* noqtis: a progress bar on stderr for the library's long calls (seal and
 * check hashing a folder, SLH-DSA signing), through nqsetprog. Only when
 * stderr is a terminal and NOQTIS_PROGRESS is not 0; nothing is drawn for
 * work that ends within a third of a second, the line is redrawn at most
 * ten times a second, and it is cleared when the work ends, so output
 * that goes to a file or a pipe never holds it. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "cli.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <time.h>
#include <unistd.h>
#endif

static uint64_t ms(void) {
#ifdef _WIN32
  return (uint64_t)GetTickCount64();
#else
  struct timespec t;
  if (clock_gettime(CLOCK_MONOTONIC, &t) != 0)
    return 0;
  return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
#endif
}

static uint64_t t0, last;
static int drawn, spin, prevst, on;
static size_t width; /* of the line drawn, to clear it */

/* n bytes as "512 B", "3.4 MiB", ... */
static void human(uint64_t n, char *o, size_t cap) {
  static const char *const u[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB"};
  double v = (double)n;
  int i = 0;
  while (v >= 1024.0 && i < 5) {
    v /= 1024.0;
    i++;
  }
  if (i == 0)
    snprintf(o, cap, "%lu B", (unsigned long)n);
  else
    snprintf(o, cap, "%.1f %s", v, u[i]);
}

static void clear(void) {
  if (drawn) {
    fprintf(stderr, "\r%*s\r", (int)width, "");
    fflush(stderr);
  }
  drawn = 0;
}

static void draw(int stage, uint64_t done, uint64_t total, void *user) {
  static const char wheel[] = "|/-\\";
  char line[160], a[24], b[24], bar[24];
  uint64_t now = ms();
  int pct, k, n;
  (void)user;
  if (stage != prevst || done == 0) { /* a stage begins */
    clear();
    prevst = stage;
    t0 = now;
    last = 0;
  }
  if (done >= total && total != 0) { /* it ends */
    clear();
    prevst = 0;
    return;
  }
  if (now - t0 < 300 || (last != 0 && now - last < 100))
    return;
  last = now;
  pct = total != 0 ? (int)(done * 100 / total) : 0;
  for (k = 0; k < 20; k++)
    bar[k] = k < pct / 5 ? '#' : '.';
  bar[20] = 0;
  spin = (spin + 1) & 3;
  if (stage == NQPHASH && total == 0) {
    /* a stream of unknown length: what was read */
    human(done, a, sizeof a);
    n = snprintf(line, sizeof line, "noqtis: %c hashing  %s", wheel[spin], a);
  } else if (stage == NQPHASH) {
    human(done, a, sizeof a);
    human(total, b, sizeof b);
    n = snprintf(line, sizeof line, "noqtis: %c hashing  [%s] %3d%%  %s of %s",
                 wheel[spin], bar, pct, a, b);
  } else {
    n = snprintf(line, sizeof line,
                 "noqtis: %c signing (SLH-DSA)  [%s] %3d%%  %lu of %lu trees",
                 wheel[spin], bar, pct, (unsigned long)done,
                 (unsigned long)total);
  }
  if (n < 0)
    return;
  if ((size_t)n < width) /* a shorter line covers the longer one */
    fprintf(stderr, "\r%s%*s", line, (int)(width - (size_t)n), "");
  else
    fprintf(stderr, "\r%s", line);
  if ((size_t)n > width)
    width = (size_t)n;
  fflush(stderr);
  drawn = 1;
}

void ncprog(void) {
  const char *e = getenv("NOQTIS_PROGRESS");
#ifdef _WIN32
  int tty = _isatty(_fileno(stderr));
#else
  int tty = isatty(STDERR_FILENO);
#endif
  if (e != NULL && strcmp(e, "0") == 0)
    return;
  /* NOQTIS_PROGRESS=1 draws to a stderr that is not a terminal too (the
   * tests' pseudo-terminal does not need it) */
  if (!tty && !(e != NULL && strcmp(e, "1") == 0))
    return;
  on = 1;
  nqsetprog(draw, NULL);
}

void ncpread(uint64_t done, uint64_t total) {
  if (on)
    draw(NQPHASH, done, total, NULL);
}

void ncpdone(void) {
  if (on) {
    clear();
    prevst = 0;
  }
}
