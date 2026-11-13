/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* Schemas: until the CSV reader is in, a schema cannot be checked, and
 * its row fails (closed) rather than pass unchecked. */
#include "int.h"

int qdschk(nqdrep *rep, const char *dir, const djs *sch, const char *sy) {
  (void)dir;
  return qdrepadd(rep, "schema", 0, "%s%s: not checked (no CSV reader)",
                  qdjget(sch, "path")->s, sy);
}
