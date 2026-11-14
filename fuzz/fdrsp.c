/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */
/* The portal reply readers (nqdrsp): the first byte picks a resolver of
 * each kind (CKAN by dataset and by resource, Socrata, ArcGIS by item
 * and by layer, the Wayback Machine), or, from 0xf0 on, the rest starts
 * with a resolver of its own (two bytes of length, then it); the rest
 * is the reply. An address read must be one nqdwb takes, of the form
 * nqdaddr(3) promises, and the call must say the same twice. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "nqd.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static const char *const rs[] = {
    "{\"base\":\"https://data.example.org\",\"id\":\"x\",\"kind\":\"ckan\"}",
    "{\"base\":\"https://data.example.org\",\"kind\":\"ckan\",\"resource\":"
    "\"r1\"}",
    "{\"base\":\"https://data.example.org\",\"id\":\"x\",\"kind\":\"ckan\","
    "\"resource\":\"r1\"}",
    "{\"base\":\"http://data.example.org\",\"format\":\"json\",\"id\":\"x\","
    "\"kind\":\"ckan\"}",
    "{\"base\":\"https://data.example.org\",\"id\":\"abcd-1234\",\"kind\":"
    "\"socrata\"}",
    "{\"base\":\"https://www.arcgis.com\",\"id\":\"0123456789abcdef0123456789"
    "abcdef\",\"kind\":\"arcgis\",\"layer\":3}",
    "{\"base\":\"https://s.example.com/x/FeatureServer\",\"kind\":\"arcgis\"}",
    "{\"base\":\"https://example.org/a.csv\",\"kind\":\"wayback\"}",
};

/* 1 when s starts with p, ignoring ASCII case */
static int pre(const char *s, const char *p) {
  for (; *p != '\0'; s++, p++) {
    char c = *s >= 'A' && *s <= 'Z' ? (char)(*s + 32) : *s;
    if (c != *p)
      return 0;
  }
  return 1;
}

static int addrok(const char *u, size_t n) {
  size_t i;
  if (n == 0 || n > 4200 || strlen(u) != n ||
      (!pre(u, "http://") && !pre(u, "https://")))
    return 0;
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)u[i];
    if (c <= 0x20 || c == 0x7f || c == '#' || c == '\\')
      return 0;
  }
  return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const char *r;
  size_t rl, n = 0, n2 = 0;
  char *own = NULL, out[8192], out2[8192], tm[21], tm2[21], why[256], w[8192];
  int rc, rc2;
  if (size == 0)
    return 0;
  if (data[0] < 0xf0) {
    r = rs[data[0] % (sizeof rs / sizeof rs[0])];
    rl = strlen(r);
    data++;
    size--;
  } else {
    if (size < 3)
      return 0;
    rl = (size_t)data[1] << 8 | data[2];
    if (rl > size - 3)
      rl = size - 3;
    own = (char *)malloc(rl + 1);
    if (own == NULL)
      abort();
    memcpy(own, data + 3, rl);
    r = own;
    data += 3 + rl;
    size -= 3 + rl;
    if (nqdrslv(r, rl, out, sizeof out, &n, why, sizeof why) == NQOK &&
        !addrok(out, n))
      abort();
  }
  {
    /* a copy of exactly the reply, so ASan sees a read past its end */
    char *rp = (char *)malloc(size ? size : 1);
    if (rp == NULL)
      abort();
    if (size)
      memcpy(rp, data, size);
    rc = nqdrsp(r, rl, rp, size, out, sizeof out, &n, tm, why, sizeof why);
    rc2 = nqdrsp(r, rl, rp, size, out2, sizeof out2, &n2, tm2, why,
                 sizeof why);
    free(rp);
  }
  if (rc != rc2)
    abort();
  if (rc == NQOK) {
    if (n != n2 || strcmp(out, out2) != 0 || strcmp(tm, tm2) != 0 ||
        !addrok(out, n))
      abort();
    if (tm[0] != '\0' && strlen(tm) != 20)
      abort();
    if (nqdwb(out, w, sizeof w, &n2) != NQOK)
      abort();
  } else if (tm[0] != '\0') {
    abort();
  }
  free(own);
  return 0;
}
