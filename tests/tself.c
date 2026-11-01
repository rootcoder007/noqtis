/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* nqselftest: every known answer matches, twice (it keeps no state), and
 * its error has a message. */
#include <string.h>

#include "noqtis.h"
#include "nqt.h"

static int nofill(uint8_t *buf, size_t len, void *user) {
  (void)buf;
  (void)len;
  (void)user;
  return 1;
}

int main(void) {
  uint8_t b[16];
  NQTEQI(nqselftest(), NQOK);
  NQTEQI(nqselftest(), NQOK);
  NQTCHK(strstr(nqerr(NQEKAT), "self-test") != NULL);
  /* a caller's random source, failing: every draw fails; then the
   * operating system's again */
  NQTEQI(nqsetrng(nofill, NULL), NQOK);
  NQTEQI(nqrand(b, sizeof b), NQERNG);
  NQTEQI(nqsetrng(NULL, NULL), NQOK);
  NQTEQI(nqrand(b, sizeof b), NQOK);
  return nqtdone("tself");
}
