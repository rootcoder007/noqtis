/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* iOS simulator only: xcrun simctl spawn cannot set a program's working
 * directory, and the tests read vectors/ relative to tests/. CMake builds
 * each test with its main renamed nqmain and this main in front, which
 * moves to $NQCWD (set by tests/sim.sh) first. NQMAINV: the test's main
 * takes no arguments. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifdef NQMAINV
int nqmain(void);
#else
int nqmain(int argc, char **argv);
#endif

int main(int argc, char **argv) {
  const char *d = getenv("NQCWD");
  if (d != NULL && d[0] != 0 && chdir(d) != 0) {
    fprintf(stderr, "cwd: cannot move to %s\n", d);
    return 1;
  }
#ifdef NQMAINV
  (void)argc;
  (void)argv;
  return nqmain();
#else
  return nqmain(argc, argv);
#endif
}
